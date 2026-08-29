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
    fs::{self, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::Path,
    process::{Command, Stdio},
};

use crate::{error::Failure, sha256, wyr1c};
use wyrmroot_device_proto::manifest::{
    ContentIdentity, HEADER_BYTES, RECORD_BYTES, encode_com2_manifest,
};

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
        ("output", ".".to_owned()),
    ];
    let request = render(REQUEST_KIND, &values);
    let request_path = output.join(REQUEST_NAME);
    write_new(&request_path, request.as_bytes())?;
    let receipt = render(
        RECEIPT_KIND,
        &[
            ("request", digest_file(&request_path)?),
            ("source", values[0].1.clone()),
            ("wrdm", values[1].1.clone()),
            ("observation", values[2].1.clone()),
            ("bootfs", values[6].1.clone()),
        ],
    );
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
    let root = request
        .parent()
        .ok_or_else(|| Failure::task("C2 request has no parent"))?;
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
    crate::g3_image::build(&args)?;
    crate::g3_image::inspect(&args)?;
    let request_bytes = read_regular(request)?;
    let receipt = render(
        RECEIPT_KIND,
        &[
            ("request", sha256::bytes_digest(&request_bytes)),
            ("esp", digest_file(&image)?),
            ("loader", digest_file(Path::new(&args.loader))?),
            ("kernel", digest_file(Path::new(&args.kernel))?),
            ("bootstrap", digest_file(Path::new(&args.bootstrap))?),
            ("bootfs", digest_file(Path::new(&args.bootfs))?),
        ],
    );
    write_new(&root.join(IMAGE_RECEIPT_NAME), receipt.as_bytes())?;
    Ok(format!(
        "WYR1_C2_IMAGE_PASS selector=none evidence=not-produced esp={}\n",
        image.display()
    ))
}

pub(crate) fn inspect(request: &Path) -> Result<String, Failure> {
    let request_bytes = read_regular(request)?;
    let map = parse_request(&request_bytes)?;
    if map.get("kind") != Some(&REQUEST_KIND.to_owned())
        || map.get("selector") != Some(&"none".to_owned())
        || map.contains_key("test_id")
    {
        return Err(Failure::task(
            "C2 request is not an explicitly unselected product",
        ));
    }
    let root = request
        .parent()
        .ok_or_else(|| Failure::task("C2 request has no parent"))?;
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
    if source != SOURCE {
        return Err(Failure::task(
            "C2 device policy is not the reviewed exact q35 COM2 TOML",
        ));
    }
    let mut output = [0; HEADER_BYTES + RECORD_BYTES];
    let length = encode_com2_manifest(ContentIdentity(uart), &mut output)
        .map_err(|_| Failure::task("C2 WRDM encoding failed"))?;
    Ok(output[..length].to_vec())
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
