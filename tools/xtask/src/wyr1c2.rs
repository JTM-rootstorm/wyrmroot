//! Selector-free WYR1-C2 product binding.
//!
//! C2 deliberately has no guest selector, run, or evidence command.  It
//! freezes C1's exact native product and adds a reviewed host policy source,
//! its canonical WRDM v1 compilation, and a bounded observation policy.  An
//! ESP cannot be manufactured honestly until the separate selector/guest tuple
//! is admitted. Its `image` action constructs only the selector-free,
//! hash-bound production ESP; it never reuses selector 25 or 27.

use std::{
    collections::{BTreeMap, BTreeSet},
    env,
    ffi::OsStr,
    fs::{self, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

use crate::{error::Failure, sha256, wyr1c};
use wyrmroot_bootfs::archive::Archive;
use wyrmroot_device_proto::manifest::{
    ContentIdentity, HEADER_BYTES, RECORD_BYTES, encode_com2_manifest,
};
use wyrmroot_rrc_manifest::{Manifest as RrcManifest, RoleId, StartupProfile};

const REQUEST_KIND: &str = "wyrmroot-wyr1-c2-unselected-request";
const RECEIPT_KIND: &str = "wyrmroot-wyr1-c2-unselected-receipt";
const SOURCE_NAME: &str = "q35-com2-role.toml";
const WRDM_NAME: &str = "wrdm-c2-v1.bin";
const CONFIG_NAME: &str = "inspection-policy.toml";
const REQUEST_NAME: &str = "wyr1-c2-request.toml";
const RECEIPT_NAME: &str = "c2-receipt.toml";
const IMAGE_RECEIPT_NAME: &str = "c2-image-receipt.toml";
const NATIVE_TARGET: &str = "x86_64-unknown-wyrmroot";
const KERNEL_TARGET: &str = "x86_64-unknown-none";
const O_NOFOLLOW: i32 = 0o400000;
const MAX_BYTES: usize = 64 * 1024 * 1024;
const GENERATED_ABI_REVISION: &str = "cfc69bd8a49819ce1cda1a132cf56e55c93f92e4";
const ACCEPTED_ABI_TREE: &str = "1c6a74f130e386eee95b3780c75950beefd0037d";
const SOURCE: &[u8] = include_bytes!("../../../products/wyr1c/q35-com2-role.toml");
const OBSERVATION: &str = concat!(
    "schema = 1\n",
    "selector = \"none\"\n",
    "evidence = \"not-produced\"\n",
    "allowed = \"CoordinatorOperational,WaitingForRegistry,WaitingForDeviceBundle,Rebind\"\n",
    "forbidden = \"DeviceBound,DriverLaunched,HardwareAccepted\"\n",
);

pub(crate) fn freeze(output: &Path) -> Result<String, Failure> {
    reject_ambient()?;
    reject_nonempty(output)?;
    validate_freeze_output(output)?;
    // C1 already enforces the accepted a92dc7f toolchain, clean Wyrmroot
    // revision, isolated offline native builds, and fresh output.  C2 wraps
    // that exact product rather than duplicating those assumptions.
    wyr1c::product(output)?;
    let repository = crate::tasks::repository_root()?;
    let project = repository
        .parent()
        .ok_or_else(|| Failure::task("WYR1-C2 source has no project root"))?;
    let deep = project.join("deepwyrm");
    let wyrm_revision = clean_revision(&repository, "Wyrmroot")?;
    let deep_revision = clean_revision(&deep, "Deepwyrm")?;
    validate_abi_tree(&deep, &deep_revision)?;
    let manifest = crate::metadata::BuildManifest::load(&repository)?;
    let profile = manifest.validate_loader_build_readiness(&repository)?;
    let layout = crate::deep_layout::prepare(
        &repository,
        manifest.deepwyrm_repository()?,
        manifest.deepwyrm_revision()?,
    )?;
    let toolchain = crate::tasks::prepare_loader_toolchain(&repository, &profile, &manifest)?;
    let cargo_home = crate::tasks::project_cargo_home(&repository, &manifest)?;
    let build = output.join("build-c2");
    fs::create_dir(&build)
        .map_err(|e| Failure::task(format!("could not create C2 build root: {e}")))?;
    let uefi = crate::tasks::build_deterministic_uefi_pair(
        &repository,
        &toolchain,
        &profile,
        &layout,
        &crate::tasks::IsolatedUefiBuild {
            cargo_home: &cargo_home,
            production_target: &build.join("uefi-release"),
            retained_debug_target: &build.join("uefi-debug"),
            cargo_profile: crate::tasks::UefiCargoProfile::Release,
        },
    )?;
    let loader = read_regular_bounded(&uefi.loader, "loader")?;
    let bootstrap = build_bootstrap(&repository, &cargo_home, toolchain.accepted(), &build)?;
    let kernel = build_kernel(&deep, &output.join("deepwyrm-target"))?;
    let artifacts = output.join("artifacts");
    write_new(&artifacts.join("loader.efi"), &loader)?;
    write_new(&artifacts.join("bootstrap.elf"), &bootstrap)?;
    write_new(&artifacts.join("deepwyrm.elf"), &kernel)?;
    write_new(
        &output.join("inspections/loader-c2.json"),
        uefi.inspection_report.as_bytes(),
    )?;
    fs::remove_dir_all(&build)
        .map_err(|e| Failure::task(format!("could not retire C2 build root: {e}")))?;
    fs::remove_dir_all(output.join("deepwyrm-target"))
        .map_err(|e| Failure::task(format!("could not retire C2 kernel target: {e}")))?;
    write_new(&artifacts.join("provenance.toml"), format!("kind = \"wyrmroot-wyr1-c2-production-provenance\"\nwyrmroot_revision = \"{wyrm_revision}\"\ndeepwyrm_revision = \"{deep_revision}\"\nloader_command = \"deterministic-release-uefi\"\nkernel_command = \"tools/pinned-cargo target build --locked --offline --release --target x86_64-unknown-none --package deepwyrm-kernel --bin deepwyrm-kernel\"\nbootstrap_command = \"accepted-cargo native bootstrap\"\n").as_bytes())?;
    let product = output.join("product");
    let source = product.join(SOURCE_NAME);
    let config = product.join(CONFIG_NAME);
    write_new(&source, SOURCE)?;
    write_new(&config, OBSERVATION.as_bytes())?;
    let uart_hex_value = digest_file(&output.join("artifacts/uart16550d.elf"))?;
    let uart = hex_to_digest(&uart_hex_value)?;
    let compiled = compile_source(SOURCE, uart)?;
    let wrdm = product.join(WRDM_NAME);
    write_new(&wrdm, &compiled)?;
    let c1_wrdm = read_regular(&product.join("wrdm-c1-v1.bin"))?;
    if c1_wrdm != compiled {
        return Err(Failure::task(
            "C2 compiler output disagrees with the frozen C1 WRDM",
        ));
    }
    let values = [
        ("source", digest_file(&source)?),
        ("wrdm", digest_file(&wrdm)?),
        ("observation", digest_file(&config)?),
        ("devmgr", digest_file(&output.join("artifacts/devmgr.elf"))?),
        ("uart16550d_retained_actor", uart_hex_value),
        ("rrc_manifest", digest_file(&product.join("rrc-c1-v1.bin"))?),
        ("bootfs", digest_file(&product.join("bootfs.img"))?),
        (
            "c1_receipt",
            digest_file(&product.join("build-receipt.toml"))?,
        ),
        ("loader", digest_file(&artifacts.join("loader.efi"))?),
        ("kernel", digest_file(&artifacts.join("deepwyrm.elf"))?),
        ("bootstrap", digest_file(&artifacts.join("bootstrap.elf"))?),
        (
            "provenance",
            digest_file(&artifacts.join("provenance.toml"))?,
        ),
        ("wyrmroot_revision", wyrm_revision),
        ("deepwyrm_revision", deep_revision),
        ("generated_abi_revision", GENERATED_ABI_REVISION.to_owned()),
        ("generated_abi_tree", ACCEPTED_ABI_TREE.to_owned()),
        ("output", ".".to_owned()),
    ];
    let request = render(REQUEST_KIND, &values);
    let request_path = output.join(REQUEST_NAME);
    write_new(&request_path, request.as_bytes())?;
    let mut receipt_values = vec![("request", digest_file(&request_path)?)];
    receipt_values.extend(values.iter().map(|(key, value)| (*key, value.clone())));
    let receipt = render(RECEIPT_KIND, &receipt_values);
    write_new(&output.join(RECEIPT_NAME), receipt.as_bytes())?;
    clean_revision(&repository, "Wyrmroot")?;
    clean_revision(&deep, "Deepwyrm")?;
    toolchain.accepted().verify_unchanged()?;
    inspect(&request_path)?;
    Ok(format!(
        "WYR1_C2_FREEZE_PASS selector=none evidence=not-produced request={}\n",
        request_path.display()
    ))
}

pub(crate) fn image(request: &Path) -> Result<String, Failure> {
    inspect(request)?;
    let root = checked_root(request)?;
    let product = root.join("product");
    let image = product.join("esp.img");
    if fs::symlink_metadata(&image).is_ok() {
        return Err(Failure::task("C2 ESP output must be fresh"));
    }
    let args = crate::cli::G3ImageArguments {
        image: image.display().to_string(),
        loader: root.join("artifacts/loader.efi").display().to_string(),
        kernel: root.join("artifacts/deepwyrm.elf").display().to_string(),
        bootstrap: root.join("artifacts/bootstrap.elf").display().to_string(),
        bootfs: product.join("bootfs.img").display().to_string(),
    };
    crate::g3_image::build_in_root(&args, Some(&root))?;
    crate::g3_image::inspect(&args)?;
    let request_bytes = read_regular(request)?;
    let request_values = parse_request(&request_bytes)?;
    let mut image_values = vec![
        ("request", sha256::bytes_digest(&request_bytes)),
        ("esp", digest_file(&image)?),
    ];
    image_values.extend(
        request_values
            .iter()
            .filter(|(key, _)| !matches!(key.as_str(), "kind" | "schema" | "selector" | "evidence"))
            .map(|(key, value)| (key.as_str(), value.clone())),
    );
    let receipt = render(RECEIPT_KIND, &image_values);
    write_new(&root.join(IMAGE_RECEIPT_NAME), receipt.as_bytes())?;
    Ok(format!(
        "WYR1_C2_IMAGE_PASS selector=none evidence=not-produced esp={}\n",
        image.display()
    ))
}

pub(crate) fn inspect(request: &Path) -> Result<String, Failure> {
    let request_bytes = read_regular(request)?;
    let root = checked_root(request)?;
    let map = parse_request(&request_bytes)?;
    if map.get("kind") != Some(&REQUEST_KIND.to_owned())
        || map.get("selector") != Some(&"none".to_owned())
        || map.contains_key("test_id")
    {
        return Err(Failure::task(
            "C2 request is not an explicitly unselected product",
        ));
    }
    let product = root.join("product");
    let expected = [
        ("source", product.join(SOURCE_NAME)),
        ("wrdm", product.join(WRDM_NAME)),
        ("observation", product.join(CONFIG_NAME)),
        ("devmgr", root.join("artifacts/devmgr.elf")),
        (
            "uart16550d_retained_actor",
            root.join("artifacts/uart16550d.elf"),
        ),
        ("rrc_manifest", product.join("rrc-c1-v1.bin")),
        ("bootfs", product.join("bootfs.img")),
        ("c1_receipt", product.join("build-receipt.toml")),
        ("loader", root.join("artifacts/loader.efi")),
        ("kernel", root.join("artifacts/deepwyrm.elf")),
        ("bootstrap", root.join("artifacts/bootstrap.elf")),
        ("provenance", root.join("artifacts/provenance.toml")),
    ];
    for (key, path) in expected {
        let actual = digest_file(&path)?;
        if map.get(key) != Some(&actual) {
            return Err(Failure::task(format!("C2 request hash mismatch for {key}")));
        }
    }
    let source = read_regular(&product.join(SOURCE_NAME))?;
    let uart = hex_to_digest(
        map.get("uart16550d_retained_actor")
            .ok_or_else(|| Failure::task("missing C2 UART digest"))?,
    )?;
    if compile_source(&source, uart)? != read_regular(&product.join(WRDM_NAME))? {
        return Err(Failure::task("C2 WRDM does not match reviewed source"));
    }
    validate_c1_tuple(&root, &map, uart)?;
    if read_regular(&product.join(CONFIG_NAME))? != OBSERVATION.as_bytes() {
        return Err(Failure::task("C2 observation policy drifted"));
    }
    let keys = map.keys().cloned().collect::<BTreeSet<_>>();
    let expected_keys = [
        "kind",
        "schema",
        "selector",
        "evidence",
        "source",
        "wrdm",
        "observation",
        "devmgr",
        "uart16550d_retained_actor",
        "rrc_manifest",
        "bootfs",
        "c1_receipt",
        "loader",
        "kernel",
        "bootstrap",
        "provenance",
        "wyrmroot_revision",
        "deepwyrm_revision",
        "generated_abi_revision",
        "generated_abi_tree",
        "output",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();
    if keys != expected_keys
        || map.get("schema") != Some(&"1".to_owned())
        || map.get("output") != Some(&".".to_owned())
    {
        return Err(Failure::task(
            "C2 request key set or fixed path policy drifted",
        ));
    }
    let receipt = parse_request(&read_regular(&root.join(RECEIPT_NAME))?)?;
    if receipt.get("kind") != Some(&RECEIPT_KIND.to_owned())
        || receipt.get("selector") != Some(&"none".to_owned())
        || receipt.get("evidence") != Some(&"not-produced".to_owned())
        || receipt.get("request") != Some(&sha256::bytes_digest(&request_bytes))
        || !receipt_matches_request(&receipt, &map)
    {
        return Err(Failure::task(
            "C2 receipt is not bound to unselected request",
        ));
    }
    let image_receipt = root.join(IMAGE_RECEIPT_NAME);
    if image_receipt.exists() {
        let values = parse_request(&read_regular(&image_receipt)?)?;
        let esp = product.join("esp.img");
        if values.get("request") != Some(&sha256::bytes_digest(&request_bytes))
            || values.get("esp") != Some(&digest_file(&esp)?)
            || !receipt_matches_request(&values, &map)
        {
            return Err(Failure::task(
                "C2 image receipt is not bound to current ESP",
            ));
        }
        let args = crate::cli::G3ImageArguments {
            image: esp.display().to_string(),
            loader: root.join("artifacts/loader.efi").display().to_string(),
            kernel: root.join("artifacts/deepwyrm.elf").display().to_string(),
            bootstrap: root.join("artifacts/bootstrap.elf").display().to_string(),
            bootfs: product.join("bootfs.img").display().to_string(),
        };
        crate::g3_image::inspect(&args)?;
    }
    Ok(format!(
        "WYR1_C2_INSPECTION_PASS selector=none evidence=not-produced request_sha256={}\n",
        sha256::bytes_digest(&request_bytes)
    ))
}

fn compile_source(source: &[u8], uart: [u8; 32]) -> Result<Vec<u8>, Failure> {
    let policy = parse_policy(source)?;
    if policy.profile != "q35"
        || policy.profile_version != 1
        || policy.role != 1
        || policy.hardware != "com2"
        || policy.resource != "pio-interrupt"
        || policy.pio_base != 760
        || policy.pio_length != 8
        || policy.irq != 3
        || policy.driver != "system/uart16550d"
        || policy.metadata_policy != "serial-console-v1"
    {
        return Err(Failure::task(
            "C2 device policy is not the reviewed q35 COM2 policy",
        ));
    }
    let mut output = [0; HEADER_BYTES + RECORD_BYTES];
    let length = encode_com2_manifest(ContentIdentity(uart), &mut output)
        .map_err(|_| Failure::task("C2 WRDM encoding failed"))?;
    Ok(output[..length].to_vec())
}

struct DevicePolicy<'a> {
    profile: &'a str,
    profile_version: u64,
    role: u64,
    hardware: &'a str,
    resource: &'a str,
    pio_base: u64,
    pio_length: u64,
    irq: u64,
    driver: &'a str,
    metadata_policy: &'a str,
}
fn parse_policy(source: &[u8]) -> Result<DevicePolicy<'_>, Failure> {
    let text = std::str::from_utf8(source).map_err(|_| Failure::task("C2 policy is not UTF-8"))?;
    if !text.starts_with("# Reviewed host policy for the immutable WYR1-C q35 COM2 role.\n")
        || !text.ends_with('\n')
        || text.contains('\r')
    {
        return Err(Failure::task("C2 policy preamble or line endings drifted"));
    }
    let mut values = BTreeMap::new();
    for line in text.lines().skip(1) {
        let (key, raw) = line
            .split_once(" = ")
            .ok_or_else(|| Failure::task("C2 policy line is malformed"))?;
        if !key.bytes().all(|b| b.is_ascii_lowercase() || b == b'_')
            || values.insert(key, raw).is_some()
        {
            return Err(Failure::task("C2 policy has duplicate or invalid key"));
        }
    }
    let keys = [
        "schema",
        "profile",
        "profile_version",
        "role",
        "hardware",
        "resource",
        "pio_base",
        "pio_length",
        "irq",
        "driver",
        "metadata_policy",
    ]
    .into_iter()
    .collect::<BTreeSet<_>>();
    if values.keys().copied().collect::<BTreeSet<_>>() != keys || values.get("schema") != Some(&"1")
    {
        return Err(Failure::task("C2 policy key set or schema drifted"));
    }
    let string = |key| -> Result<&str, Failure> {
        let raw = values
            .get(key)
            .ok_or_else(|| Failure::task("C2 policy missing string"))?;
        if raw.starts_with('"')
            && raw.ends_with('"')
            && raw.len() > 2
            && !raw[1..raw.len() - 1].contains(['"', '\\'])
        {
            Ok(&raw[1..raw.len() - 1])
        } else {
            Err(Failure::task("C2 policy string is malformed"))
        }
    };
    let integer = |key| -> Result<u64, Failure> {
        values
            .get(key)
            .ok_or_else(|| Failure::task("C2 policy missing integer"))?
            .parse()
            .map_err(|_| Failure::task("C2 policy integer is malformed"))
    };
    Ok(DevicePolicy {
        profile: string("profile")?,
        profile_version: integer("profile_version")?,
        role: integer("role")?,
        hardware: string("hardware")?,
        resource: string("resource")?,
        pio_base: integer("pio_base")?,
        pio_length: integer("pio_length")?,
        irq: integer("irq")?,
        driver: string("driver")?,
        metadata_policy: string("metadata_policy")?,
    })
}

fn parse_request(bytes: &[u8]) -> Result<BTreeMap<String, String>, Failure> {
    let text = std::str::from_utf8(bytes).map_err(|_| Failure::task("C2 TOML is not UTF-8"))?;
    if !text.ends_with('\n') || text.contains('\r') {
        return Err(Failure::task(
            "C2 TOML does not have canonical line endings",
        ));
    }
    let mut map = BTreeMap::new();
    for line in text.lines() {
        let (key, value) = line
            .split_once(" = ")
            .ok_or_else(|| Failure::task("C2 TOML has malformed line"))?;
        if key == "schema" && value == "1" {
            if map.insert(key.to_owned(), value.to_owned()).is_some() {
                return Err(Failure::task("C2 TOML has duplicate schema"));
            }
            continue;
        }
        if !value.starts_with('"') || !value.ends_with('"') || value.len() < 2 {
            return Err(Failure::task("C2 TOML value is not a quoted scalar"));
        }
        let value = &value[1..value.len() - 1];
        if value.contains('"') || value.contains('\\') || value.is_empty() {
            return Err(Failure::task("C2 TOML scalar is malformed"));
        }
        if key.is_empty()
            || !key
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte == b'_')
            || map.insert(key.to_owned(), value.to_owned()).is_some()
        {
            return Err(Failure::task("C2 TOML has duplicate or invalid key"));
        }
    }
    Ok(map)
}

fn render(kind: &str, values: &[(&str, String)]) -> String {
    let mut text = format!(
        "kind = \"{kind}\"\nschema = 1\nselector = \"none\"\nevidence = \"not-produced\"\n"
    );
    for (key, value) in values {
        text.push_str(&format!("{key} = \"{value}\"\n"));
    }
    text
}
fn reject_nonempty(path: &Path) -> Result<(), Failure> {
    if path.exists() {
        Err(Failure::task("C2 output must be a fresh nonexistent path"))
    } else {
        Ok(())
    }
}
fn write_new(path: &Path, bytes: &[u8]) -> Result<(), Failure> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .custom_flags(O_NOFOLLOW)
        .open(path)
        .map_err(|error| Failure::task(format!("could not create C2 product: {error}")))?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|error| Failure::task(format!("could not write C2 product: {error}")))
}
fn read_regular(path: &Path) -> Result<Vec<u8>, Failure> {
    read_regular_bounded(path, "input")
}
fn read_regular_bounded(path: &Path, label: &str) -> Result<Vec<u8>, Failure> {
    let m = fs::symlink_metadata(path)
        .map_err(|e| Failure::task(format!("could not inspect C2 {label}: {e}")))?;
    if !m.file_type().is_file()
        || m.file_type().is_symlink()
        || m.len() == 0
        || m.len() > MAX_BYTES as u64
        || m.nlink() != 1
    {
        return Err(Failure::task(
            "C2 input is not a bounded single-link regular file",
        ));
    }
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(O_NOFOLLOW)
        .open(path)
        .map_err(|e| Failure::task(format!("could not open C2 {label}: {e}")))?;
    let opened = file
        .metadata()
        .map_err(|e| Failure::task(format!("could not stat C2 {label}: {e}")))?;
    if (m.dev(), m.ino()) != (opened.dev(), opened.ino()) {
        return Err(Failure::task("C2 input changed before open"));
    }
    let mut bytes = Vec::with_capacity(opened.len() as usize);
    file.take(MAX_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| Failure::task(format!("could not read C2 {label}: {e}")))?;
    if bytes.len() != opened.len() as usize {
        return Err(Failure::task("C2 input changed while reading"));
    }
    Ok(bytes)
}
fn digest_file(path: &Path) -> Result<String, Failure> {
    Ok(sha256::bytes_digest(&read_regular(path)?))
}
fn hex_to_digest(value: &str) -> Result<[u8; 32], Failure> {
    crate::wyr1::decode_digest(value)
}

fn checked_root(request: &Path) -> Result<PathBuf, Failure> {
    let repository = crate::tasks::repository_root()?;
    let project = fs::canonicalize(
        repository
            .parent()
            .ok_or_else(|| Failure::task("C2 source has no project root"))?,
    )
    .map_err(|e| Failure::task(format!("could not resolve C2 project root: {e}")))?;
    let source = fs::canonicalize(&repository)
        .map_err(|e| Failure::task(format!("could not resolve C2 source root: {e}")))?;
    let parent = request
        .parent()
        .ok_or_else(|| Failure::task("C2 request has no parent"))?;
    let root = fs::canonicalize(parent)
        .map_err(|e| Failure::task(format!("could not resolve C2 request root: {e}")))?;
    let output_base = project.join("artifacts/wyr1-c");
    if !root.starts_with(&output_base)
        || root.starts_with(&source)
        || request.file_name() != Some(OsStr::new(REQUEST_NAME))
    {
        return Err(Failure::task(
            "C2 request root escapes the trusted project output boundary",
        ));
    }
    Ok(root)
}

fn validate_freeze_output(output: &Path) -> Result<(), Failure> {
    if output.file_name().is_none()
        || output.components().any(|c| {
            matches!(
                c,
                std::path::Component::ParentDir | std::path::Component::CurDir
            )
        })
    {
        return Err(Failure::task("C2 output path is not canonical"));
    }
    let repository = crate::tasks::repository_root()?;
    let project = fs::canonicalize(
        repository
            .parent()
            .ok_or_else(|| Failure::task("C2 source has no project root"))?,
    )
    .map_err(|e| Failure::task(format!("could not resolve C2 project root: {e}")))?;
    let parent = output
        .parent()
        .ok_or_else(|| Failure::task("C2 output has no parent"))?;
    let parent = fs::canonicalize(parent)
        .map_err(|e| Failure::task(format!("could not resolve C2 output parent: {e}")))?;
    if !parent.starts_with(project.join("artifacts/wyr1-c")) {
        return Err(Failure::task(
            "C2 output must be below canonical artifacts/wyr1-c",
        ));
    }
    Ok(())
}

fn receipt_matches_request(
    receipt: &BTreeMap<String, String>,
    request: &BTreeMap<String, String>,
) -> bool {
    let mut expected = request
        .keys()
        .filter(|key| !matches!(key.as_str(), "kind" | "schema" | "selector" | "evidence"))
        .cloned()
        .chain(std::iter::once("request".to_owned()))
        .collect::<BTreeSet<_>>();
    if receipt.contains_key("esp") {
        expected.insert("esp".to_owned());
    }
    let actual = receipt
        .keys()
        .filter(|key| !matches!(key.as_str(), "kind" | "schema" | "selector" | "evidence"))
        .cloned()
        .collect::<BTreeSet<_>>();
    actual == expected
        && request
            .iter()
            .filter(|(key, _)| !matches!(key.as_str(), "kind" | "schema" | "selector" | "evidence"))
            .all(|(key, value)| receipt.get(key) == Some(value))
}

fn validate_c1_tuple(
    root: &Path,
    request: &BTreeMap<String, String>,
    uart: [u8; 32],
) -> Result<(), Failure> {
    let product = root.join("product");
    let c1 = parse_scalars(&read_regular(&product.join("build-receipt.toml"))?)?;
    let mut required = [
        "kind",
        "schema_version",
        "product_kind",
        "selector",
        "evidence",
        "wyrmroot_revision",
        "cargo_lock_sha256",
        "rust_revision",
        "rust_toolchain_name",
        "rustc_sha256",
        "cargo_sha256",
        "rust_lld_sha256",
        "toolchain_manifest_sha256",
        "toolchain_tree_sha256",
        "boot_generation",
        "rrc_manifest_path",
        "rrc_manifest_sha256",
        "device_manifest_path",
        "device_manifest_sha256",
        "bootfs_path",
        "bootfs_sha256",
        "bootfs_bytes",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect::<BTreeSet<_>>();
    for label in [
        "system-init",
        "registryd",
        "devmgr",
        "uart16550d",
        "consoled",
        "wyrmsh",
    ] {
        for suffix in ["path", "sha256", "command", "inspection_sha256"] {
            required.insert(format!("{label}_{suffix}"));
        }
    }
    if c1.keys().cloned().collect::<BTreeSet<_>>() != required {
        return Err(Failure::task("C2 C1 receipt key set drifted"));
    }
    for (key, value) in [
        ("kind", "wyrmroot-wyr1-c1-host-product-receipt"),
        ("schema_version", "1"),
        ("product_kind", "wyrmroot-wyr1-c1-host-product"),
        ("selector", "none"),
        ("evidence", "not-produced"),
    ] {
        if c1.get(key) != Some(&value.to_owned()) {
            return Err(Failure::task("C2 C1 receipt identity drifted"));
        }
    }
    if c1.get("wyrmroot_revision") != request.get("wyrmroot_revision") {
        return Err(Failure::task("C2 C1 receipt Wyrmroot revision drifted"));
    }
    let rrc = read_regular(&product.join("rrc-c1-v1.bin"))?;
    let external = read_regular(&product.join("wrdm-c1-v1.bin"))?;
    let bootfs = read_regular(&product.join("bootfs.img"))?;
    for (key, bytes) in [
        ("rrc_manifest_sha256", &rrc),
        ("device_manifest_sha256", &external),
        ("bootfs_sha256", &bootfs),
    ] {
        if c1.get(key) != Some(&sha256::bytes_digest(bytes)) {
            return Err(Failure::task("C2 C1 product digest drifted"));
        }
    }
    let archive = Archive::new(&bootfs)
        .map_err(|e| Failure::task(format!("C2 bootfs is malformed: {e:?}")))?;
    if archive.entries().count() != 10 {
        return Err(Failure::task("C2 bootfs entry count drifted"));
    }
    let embedded_rrc = archive
        .lookup(b"system/bootstrap/rrc-a-v1")
        .map_err(|_| Failure::task("C2 bootfs lacks WRRM"))?;
    let embedded_wrdm = archive
        .lookup(b"system/bootstrap/wyr1-c-device-manifest-v1")
        .map_err(|_| Failure::task("C2 bootfs lacks WRDM"))?;
    let devmgr = archive
        .lookup(b"system/devmgr")
        .map_err(|_| Failure::task("C2 bootfs lacks devmgr"))?;
    let retained = archive
        .lookup(b"system/uart16550d")
        .map_err(|_| Failure::task("C2 bootfs lacks retained actor"))?;
    for (label, path) in [
        ("system-init", b"system/init".as_slice()),
        ("registryd", b"system/registryd".as_slice()),
        ("devmgr", b"system/devmgr".as_slice()),
        ("uart16550d", b"system/uart16550d".as_slice()),
        ("consoled", b"system/consoled".as_slice()),
        ("wyrmsh", b"system/wyrmsh".as_slice()),
    ] {
        let expected = c1
            .get(&format!("{label}_sha256"))
            .ok_or_else(|| Failure::task("C2 C1 lacks component hash"))?;
        let artifact = read_regular(&root.join("artifacts").join(format!("{label}.elf")))?;
        let inspection = read_regular(&root.join("inspections").join(format!("{label}.json")))?;
        let embedded = archive
            .lookup(path)
            .map_err(|_| Failure::task("C2 bootfs lacks C1 component"))?
            .data();
        if sha256::bytes_digest(&artifact) != *expected
            || artifact.as_slice() != embedded
            || c1.get(&format!("{label}_path")) != Some(&format!("artifacts/{label}.elf"))
            || c1.get(&format!("{label}_inspection_sha256"))
                != Some(&sha256::bytes_digest(&inspection))
            || !String::from_utf8_lossy(&inspection).contains(&format!("\"sha256\":\"{expected}\""))
        {
            return Err(Failure::task("C2 C1 component tuple drifted"));
        }
    }
    if embedded_rrc.data() != rrc
        || embedded_wrdm.data() != external
        || external != read_regular(&product.join(WRDM_NAME))?
    {
        return Err(Failure::task("C2 embedded/external WRDM or WRRM drifted"));
    }
    if wyrmroot_device_proto::Manifest::parse(&external)
        .and_then(|m| m.match_com2(ContentIdentity(uart)))
        .is_err()
    {
        return Err(Failure::task("C2 WRDM semantics drifted"));
    }
    let generation = crate::wyr1::decode_digest(
        c1.get("boot_generation")
            .ok_or_else(|| Failure::task("C2 C1 receipt lacks generation"))?,
    )?;
    let manifest = RrcManifest::parse_structural(&rrc, &generation)
        .map_err(|e| Failure::task(format!("C2 WRRM is malformed: {e:?}")))?;
    for (role, profile, label, data) in [
        (
            RoleId::Registryd,
            StartupProfile::BootstrapRegistry,
            "registryd",
            None,
        ),
        (
            RoleId::Devmgr,
            StartupProfile::DeviceCoordinator,
            "devmgr",
            Some(devmgr.data()),
        ),
        (
            RoleId::Uart16550d,
            StartupProfile::Retained,
            "uart16550d",
            Some(retained.data()),
        ),
    ] {
        let entry = manifest
            .role(role)
            .ok_or_else(|| Failure::task("C2 WRRM lacks role"))?;
        if entry.startup_profile() != profile {
            return Err(Failure::task("C2 WRRM startup profile drifted"));
        }
        let expected = c1
            .get(&format!("{label}_sha256"))
            .ok_or_else(|| Failure::task("C2 C1 receipt lacks component digest"))?;
        if entry.executable_identity() != &crate::wyr1::decode_digest(expected)?
            || data.is_some_and(|bytes| sha256::bytes_digest(bytes) != *expected)
        {
            return Err(Failure::task("C2 WRRM component identity drifted"));
        }
    }
    Ok(())
}

fn parse_scalars(bytes: &[u8]) -> Result<BTreeMap<String, String>, Failure> {
    let text = std::str::from_utf8(bytes).map_err(|_| Failure::task("C2 receipt is not UTF-8"))?;
    if !text.ends_with('\n') || text.contains('\r') {
        return Err(Failure::task("C2 receipt line endings drifted"));
    }
    let mut values = BTreeMap::new();
    for line in text.lines() {
        let (key, raw) = line
            .split_once(" = ")
            .ok_or_else(|| Failure::task("C2 receipt has malformed line"))?;
        if key.is_empty()
            || !key.bytes().all(|b| b.is_ascii_lowercase() || b == b'_')
            || values.contains_key(key)
        {
            return Err(Failure::task("C2 receipt has invalid or duplicate key"));
        }
        let value = if raw.starts_with('"') && raw.ends_with('"') && raw.len() >= 2 {
            let value = &raw[1..raw.len() - 1];
            if value.contains('"') || value.contains('\\') || value.is_empty() {
                return Err(Failure::task("C2 receipt has malformed string"));
            }
            value
        } else if raw.bytes().all(|b| b.is_ascii_digit()) && !raw.is_empty() {
            raw
        } else {
            return Err(Failure::task("C2 receipt scalar type drifted"));
        };
        values.insert(key.to_owned(), value.to_owned());
    }
    Ok(values)
}

fn clean_revision(repository: &Path, label: &str) -> Result<String, Failure> {
    let head = Command::new("git")
        .arg("-C")
        .arg(repository)
        .args(["rev-parse", "HEAD"])
        .output()
        .map_err(|e| Failure::task(format!("could not inspect {label}: {e}")))?;
    let status = Command::new("git")
        .arg("-C")
        .arg(repository)
        .args(["status", "--porcelain=v1", "--untracked-files=all"])
        .output()
        .map_err(|e| Failure::task(format!("could not inspect {label} status: {e}")))?;
    if !head.status.success() || !status.status.success() || !status.stdout.is_empty() {
        return Err(Failure::task(format!(
            "C2 requires one exact clean {label} revision"
        )));
    }
    std::str::from_utf8(&head.stdout)
        .map(str::trim)
        .map(str::to_owned)
        .map_err(|_| Failure::task("git revision was not UTF-8"))
}

fn validate_abi_tree(deep: &Path, kernel_revision: &str) -> Result<(), Failure> {
    let tree = |revision: &str| -> Result<String, Failure> {
        let output = Command::new("git")
            .arg("-C")
            .arg(deep)
            .args(["rev-parse", &format!("{revision}:abi")])
            .output()
            .map_err(|e| Failure::task(format!("could not inspect C2 ABI tree: {e}")))?;
        if !output.status.success() {
            return Err(Failure::task("C2 kernel revision has no ABI tree"));
        }
        std::str::from_utf8(&output.stdout)
            .map(str::trim)
            .map(str::to_owned)
            .map_err(|_| Failure::task("C2 ABI tree was not UTF-8"))
    };
    if tree(kernel_revision)? != ACCEPTED_ABI_TREE
        || tree(GENERATED_ABI_REVISION)? != ACCEPTED_ABI_TREE
    {
        return Err(Failure::task(
            "C2 kernel and generated ABI trees are incompatible",
        ));
    }
    Ok(())
}

fn build_bootstrap(
    repository: &Path,
    cargo_home: &Path,
    toolchain: &crate::toolchain_artifact::AcceptedToolchain,
    build: &Path,
) -> Result<Vec<u8>, Failure> {
    let target = build.join("bootstrap");
    fs::create_dir(&target)
        .map_err(|e| Failure::task(format!("could not create C2 bootstrap target: {e}")))?;
    let status = Command::new(&toolchain.cargo)
        .args([
            "build",
            "--offline",
            "--locked",
            "--release",
            "--target",
            NATIVE_TARGET,
            "--package",
            "wyrmroot-bootstrap",
            "--bin",
            "wyrmroot-bootstrap",
            "--features",
            "native-bootstrap",
            "--target-dir",
        ])
        .arg(&target)
        .env("RUSTC", &toolchain.rustc)
        .env("CARGO_HOME", cargo_home)
        .env("CARGO_INCREMENTAL", "0")
        .env("CARGO_NET_OFFLINE", "true")
        .env("SOURCE_DATE_EPOCH", "0")
        .env_remove("LD_AUDIT")
        .env_remove("LD_LIBRARY_PATH")
        .env_remove("LD_PRELOAD")
        .current_dir(repository)
        .stdin(Stdio::null())
        .status()
        .map_err(|e| Failure::task(format!("could not build C2 bootstrap: {e}")))?;
    if !status.success() {
        return Err(Failure::task("C2 bootstrap build failed"));
    }
    read_regular_bounded(
        &target
            .join(NATIVE_TARGET)
            .join("release/wyrmroot-bootstrap"),
        "bootstrap",
    )
}

fn build_kernel(deep: &Path, target: &Path) -> Result<Vec<u8>, Failure> {
    fs::create_dir_all(target)
        .map_err(|e| Failure::task(format!("could not create C2 kernel target: {e}")))?;
    let status = Command::new(deep.join("tools/pinned-cargo"))
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
        .env("DEEPWYRM_PINNED_TARGET_DIR", target)
        .env_remove("CARGO_HOME")
        .env_remove("DEEPWYRM_GUEST_TEST_SELECTOR")
        .env_remove("DEEPWYRM_GUEST_TEST_ID")
        .env_remove("LD_AUDIT")
        .env_remove("LD_LIBRARY_PATH")
        .env_remove("LD_PRELOAD")
        .current_dir(deep)
        .stdin(Stdio::null())
        .status()
        .map_err(|e| Failure::task(format!("could not build C2 production kernel: {e}")))?;
    if !status.success() {
        return Err(Failure::task("C2 production kernel build failed"));
    }
    read_regular_bounded(
        &target.join(KERNEL_TARGET).join("release/deepwyrm-kernel"),
        "kernel",
    )
}

fn reject_ambient() -> Result<(), Failure> {
    for name in [
        "DEEPWYRM_GUEST_TEST_SELECTOR",
        "DEEPWYRM_GUEST_TEST_ID",
        "DEEPWYRM_WYR1B_EVIDENCE_NONCE",
        "DEEPWYRM_WYR1_EVIDENCE_NONCE",
        "DEEPWYRM_WYR1_EVIDENCE_SCENARIO",
        "CARGO_TARGET_DIR",
        "RUSTC",
        "RUSTFLAGS",
    ] {
        if env::var_os(name).is_some() {
            return Err(Failure::task(format!("C2 freeze refuses ambient {name}")));
        }
    }
    if env::vars_os().any(|(key, _)| {
        key.as_os_str()
            .as_encoded_bytes()
            .starts_with(b"CARGO_TARGET_")
    }) {
        return Err(Failure::task("C2 freeze refuses ambient CARGO_TARGET_*"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn reviewed_source_compiles_deterministically() {
        let a = compile_source(SOURCE, [7; 32]).unwrap();
        assert_eq!(a, compile_source(SOURCE, [7; 32]).unwrap());
        assert!(compile_source(b"hardware = \"com1\"\n", [7; 32]).is_err());
    }
    #[test]
    fn request_parser_rejects_duplicates_and_test_ids() {
        assert!(parse_request(b"a = \"x\"\na = \"y\"\n").is_err());
        assert!(parse_request(b"a = x\n").is_err());
        assert!(parse_request(b"a = \"x\"\r\n").is_err());
        let map = parse_request(b"kind = \"x\"\n").unwrap();
        assert!(!map.contains_key("test_id"));
    }
}
