//! DW1-B selector-26 request, four-entry product, receipt, and evidence parser.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};

use wyrmroot_bootfs::archive::Archive;
use wyrmroot_bootfs::builder::{Builder, FileMode};

use crate::error::Failure;
use crate::sha256;

pub const SCHEMA_VERSION: u32 = 5;
pub const SELECTOR: &str = "normal-preemption-up";
pub const TEST_ID: u32 = 26;
pub const DIGEST: u64 = 0x5E4E_054B_5C24_4ACE;
pub const DEEPWYRM_CANDIDATE: &str = "ae30e879ed61698c7f11d8486639a03a7c7c323e";
pub const DEEPWYRM_ABI_TREE: &str = "1c6a74f130e386eee95b3780c75950beefd0037d";
const RECEIPT_KIND: &str = "wyrmroot-dw1-b-build-lineage";
const RUN_RECEIPT_KIND: &str = "wyrmroot-dw1-b-run-receipt";
const PROVENANCE_KIND: &str = "wyrmroot-dw1-b-kernel-build";
const SHA256_ZERO: &str = "0000000000000000000000000000000000000000000000000000000000000000";
const REQUEST_KEYS: &[&str] = &[
    "schema_version",
    "deepwyrm_revision",
    "deepwyrm_abi_tree",
    "wyrmroot_revision",
    "rust_revision",
    "selector",
    "test_id",
    "timeout_seconds",
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
    "hello",
    "hello_sha256",
    "cpu_hog",
    "cpu_hog_sha256",
    "progress",
    "progress_sha256",
    "provenance",
    "provenance_sha256",
    "bootfs",
    "esp",
    "run_directory",
    "serial_log",
    "run_receipt",
    "evidence_nonce",
    "challenge_digest",
    "bootfs_pages",
    "receipt",
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
    "run_directory",
    "serial_log",
    "timeout_seconds",
    "qemu_exit_status",
    "timed_out",
];
const PROVENANCE_KEYS: &[&str] = &[
    "kind",
    "schema_version",
    "selector",
    "test_id",
    "deepwyrm_revision",
    "deepwyrm_abi_tree",
    "rust_revision",
    "kernel_sha256",
    "symbols_sha256",
    "DEEPWYRM_DW1B_EVIDENCE_NONCE",
    "DEEPWYRM_DW1B_CHALLENGE_DIGEST",
    "DEEPWYRM_DW1B_BOOTFS_MAX_PAGES",
];

#[derive(Clone, Debug)]
pub struct Request {
    root: PathBuf,
    request_sha256: String,
    deepwyrm_revision: String,
    wyrmroot_revision: String,
    rust_revision: String,
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
    hello: PathBuf,
    hello_sha256: String,
    cpu_hog: PathBuf,
    cpu_hog_sha256: String,
    progress: PathBuf,
    progress_sha256: String,
    provenance: PathBuf,
    provenance_sha256: String,
    bootfs: PathBuf,
    esp: PathBuf,
    run_directory: PathBuf,
    serial_log: PathBuf,
    run_receipt: PathBuf,
    evidence_nonce: u64,
    timeout_seconds: u64,
    bootfs_pages: usize,
    receipt: PathBuf,
}

struct ProductInputs<'a> {
    kernel: &'a [u8],
    symbols: &'a [u8],
    init: &'a [u8],
    hello: &'a [u8],
    hog: &'a [u8],
    progress: &'a [u8],
    provenance: &'a [u8],
}

pub fn load(path: &Path) -> Result<Request, Failure> {
    let bytes =
        fs::read(path).map_err(|e| Failure::task(format!("could not read DW1-B request: {e}")))?;
    if bytes.is_empty() || bytes.len() > 64 * 1024 {
        return Err(Failure::task("DW1-B request size is invalid"));
    }
    let text =
        core::str::from_utf8(&bytes).map_err(|_| Failure::task("DW1-B request is not UTF-8"))?;
    let values = parse_scalars(text)?;
    exact_keys(&values, REQUEST_KEYS, "DW1-B request")?;
    if number::<u32>(&values, "schema_version")? != SCHEMA_VERSION
        || required(&values, "selector")? != SELECTOR
        || number::<u32>(&values, "test_id")? != TEST_ID
    {
        return Err(Failure::task(
            "DW1-B request must name schema 5 selector 26",
        ));
    }
    if required(&values, "deepwyrm_revision")? != DEEPWYRM_CANDIDATE
        || required(&values, "deepwyrm_abi_tree")? != DEEPWYRM_ABI_TREE
    {
        return Err(Failure::task(
            "DW1-B requires the exact selector-26 kernel candidate and accepted ABI tree",
        ));
    }
    let parent = path
        .parent()
        .ok_or_else(|| Failure::task("DW1-B request has no parent"))?;
    let parent = fs::canonicalize(parent)
        .map_err(|e| Failure::task(format!("could not canonicalize DW1-B request root: {e}")))?;
    let nonce = parse_hex_u64(required(&values, "evidence_nonce")?)?;
    if nonce == 0 || required(&values, "evidence_nonce")?.len() != 16 {
        return Err(Failure::task(
            "DW1-B evidence nonce must be nonzero uppercase 16-hex",
        ));
    }
    let challenge_digest = parse_hex_u64(required(&values, "challenge_digest")?)?;
    if challenge_digest != DIGEST
        || required(&values, "challenge_digest")? != format!("{DIGEST:016X}")
    {
        return Err(Failure::task(
            "DW1-B challenge digest does not match the frozen transcript",
        ));
    }
    let request = Request {
        root: parent.clone(),
        request_sha256: sha256::bytes_digest(&bytes),
        deepwyrm_revision: revision(&values, "deepwyrm_revision")?,
        wyrmroot_revision: revision(&values, "wyrmroot_revision")?,
        rust_revision: revision(&values, "rust_revision")?,
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
        hello: input(&parent, required(&values, "hello")?)?,
        hello_sha256: digest(&values, "hello_sha256")?,
        cpu_hog: input(&parent, required(&values, "cpu_hog")?)?,
        cpu_hog_sha256: digest(&values, "cpu_hog_sha256")?,
        progress: input(&parent, required(&values, "progress")?)?,
        progress_sha256: digest(&values, "progress_sha256")?,
        provenance: input(&parent, required(&values, "provenance")?)?,
        provenance_sha256: digest(&values, "provenance_sha256")?,
        bootfs: output(&parent, required(&values, "bootfs")?)?,
        esp: output(&parent, required(&values, "esp")?)?,
        run_directory: output(&parent, required(&values, "run_directory")?)?,
        serial_log: output(&parent, required(&values, "serial_log")?)?,
        run_receipt: output(&parent, required(&values, "run_receipt")?)?,
        evidence_nonce: nonce,
        timeout_seconds: bounded_number(&values, "timeout_seconds", 1, 120)?,
        bootfs_pages: bounded_number(&values, "bootfs_pages", 1, 8192)?,
        receipt: output(&parent, required(&values, "receipt")?)?,
    };
    reject_path_aliases(&request)?;
    Ok(request)
}

pub fn build(path: &Path) -> Result<String, Failure> {
    let request = load(path)?;
    let loader = read_expected(&request.loader, "loader", &request.loader_sha256)?;
    let kernel = read_expected(&request.kernel, "kernel", &request.kernel_sha256)?;
    let symbols = read_expected(&request.symbols, "symbols", &request.symbols_sha256)?;
    let bootstrap = read_expected(&request.bootstrap, "bootstrap", &request.bootstrap_sha256)?;
    let provenance = read_expected(
        &request.provenance,
        "provenance",
        &request.provenance_sha256,
    )?;
    let init = read_expected(&request.init, "init", &request.init_sha256)?;
    let hello = read_expected(&request.hello, "hello", &request.hello_sha256)?;
    let hog = read_expected(&request.cpu_hog, "cpu hog", &request.cpu_hog_sha256)?;
    let progress = read_expected(&request.progress, "progress", &request.progress_sha256)?;
    verify_product_inputs(
        &request,
        ProductInputs {
            kernel: &kernel,
            symbols: &symbols,
            init: &init,
            hello: &hello,
            hog: &hog,
            progress: &progress,
            provenance: &provenance,
        },
    )?;
    let bootfs = build_archive(&init, &hello, &hog, &progress)?;
    let pages = bootfs.len().div_ceil(4096);
    if pages != request.bootfs_pages {
        return Err(Failure::task(format!(
            "DW1-B measured bootfs pages {pages} do not match request {}",
            request.bootfs_pages
        )));
    }
    fs::create_dir_all(&request.run_directory).map_err(io_failure)?;
    if let Some(parent) = request.bootfs.parent() {
        fs::create_dir_all(parent).map_err(io_failure)?;
    }
    fs::write(&request.bootfs, &bootfs).map_err(io_failure)?;
    let image_args = crate::cli::G3ImageArguments {
        image: request.esp.display().to_string(),
        loader: request.loader.display().to_string(),
        kernel: request.kernel.display().to_string(),
        bootstrap: request.bootstrap.display().to_string(),
        bootfs: request.bootfs.display().to_string(),
    };
    let _ = crate::g3_image::build(&image_args)?;
    let esp = read(&request.esp, "ESP")?;
    let receipt = receipt(
        &request,
        &bootfs,
        [&init, &hello, &hog, &progress],
        [&loader, &kernel, &symbols, &bootstrap, &provenance, &esp],
    );
    if let Some(parent) = request.receipt.parent() {
        fs::create_dir_all(parent).map_err(io_failure)?;
    }
    fs::write(&request.receipt, receipt).map_err(io_failure)?;
    Ok(format!(
        "DW1_B_IMAGE_PASS entries=4 bootfs_bytes={} bootfs_pages={} bootfs_sha256={}\n",
        bootfs.len(),
        bootfs.len().div_ceil(4096),
        sha256::bytes_digest(&bootfs)
    ))
}

pub fn measure(init: &Path, hello: &Path, hog: &Path, progress: &Path) -> Result<String, Failure> {
    let bootfs = build_archive(
        &read(init, "init")?,
        &read(hello, "hello")?,
        &read(hog, "cpu hog")?,
        &read(progress, "progress")?,
    )?;
    Ok(format!(
        "DW1_B_MEASUREMENT_PASS entries=4 bootfs_bytes={} bootfs_pages={} bootfs_sha256={}\n",
        bootfs.len(),
        bootfs.len().div_ceil(4096),
        sha256::bytes_digest(&bootfs)
    ))
}

pub fn inspect(path: &Path) -> Result<String, Failure> {
    let request = load(path)?;
    let loader = read_expected(&request.loader, "loader", &request.loader_sha256)?;
    let kernel = read_expected(&request.kernel, "kernel", &request.kernel_sha256)?;
    let symbols = read_expected(&request.symbols, "symbols", &request.symbols_sha256)?;
    let bootstrap = read_expected(&request.bootstrap, "bootstrap", &request.bootstrap_sha256)?;
    let provenance = read_expected(
        &request.provenance,
        "provenance",
        &request.provenance_sha256,
    )?;
    let esp = read(&request.esp, "ESP")?;
    let bootfs = read(&request.bootfs, "bootfs")?;
    let artifacts = [
        read_expected(&request.init, "init", &request.init_sha256)?,
        read_expected(&request.hello, "hello", &request.hello_sha256)?,
        read_expected(&request.cpu_hog, "cpu hog", &request.cpu_hog_sha256)?,
        read_expected(&request.progress, "progress", &request.progress_sha256)?,
    ];
    verify_product_inputs(
        &request,
        ProductInputs {
            kernel: &kernel,
            symbols: &symbols,
            init: &artifacts[0],
            hello: &artifacts[1],
            hog: &artifacts[2],
            progress: &artifacts[3],
            provenance: &provenance,
        },
    )?;
    verify_archive(
        &bootfs,
        [&artifacts[0], &artifacts[1], &artifacts[2], &artifacts[3]],
    )?;
    if bootfs.len().div_ceil(4096) != request.bootfs_pages {
        return Err(Failure::task(
            "DW1-B inspected bootfs page count does not match request",
        ));
    }
    verify_receipt(
        &request,
        &bootfs,
        [&artifacts[0], &artifacts[1], &artifacts[2], &artifacts[3]],
        [&loader, &kernel, &symbols, &bootstrap, &provenance, &esp],
    )?;
    Ok(format!(
        "DW1_B_INSPECTION_PASS entries=4 bootfs_bytes={} bootfs_pages={} bootfs_sha256={}\n",
        bootfs.len(),
        bootfs.len().div_ceil(4096),
        sha256::bytes_digest(&bootfs)
    ))
}

pub fn evidence(request_path: &Path) -> Result<String, Failure> {
    let _ = inspect(request_path)?;
    let request = load(request_path)?;
    let bytes = verify_run_receipt(&request)?;
    let mut summary = None;
    let mut terminal = None;
    for (index, line) in bytes.split_inclusive(|byte| *byte == b'\n').enumerate() {
        if line.starts_with(b"DWPRE1") {
            if summary.is_some() {
                return Err(Failure::task("duplicate DWPRE1 summary"));
            }
            summary = Some((index, parse_summary(line, request.evidence_nonce)?));
        } else if line.starts_with(b"DWTEST1") {
            if terminal.is_some() {
                return Err(Failure::task("duplicate DWTEST1 terminal"));
            }
            terminal = Some((index, parse_terminal(line)?));
        }
    }
    let (summary_line, summary) = summary.ok_or_else(|| Failure::task("missing DWPRE1 summary"))?;
    let (terminal_line, ()) = terminal.ok_or_else(|| Failure::task("missing DWTEST1 terminal"))?;
    if summary_line >= terminal_line {
        return Err(Failure::task("DWPRE1 must immediately precede DWTEST1"));
    }
    let between = bytes
        .split_inclusive(|byte| *byte == b'\n')
        .skip(summary_line + 1)
        .take(terminal_line - summary_line - 1);
    if between.count() != 0 {
        return Err(Failure::task("DWPRE1 must immediately precede DWTEST1"));
    }
    Ok(format!(
        "DW1_B_EVIDENCE_PASS quantum={} involuntary={} switches={} wakeups={}\n",
        summary.0, summary.1, summary.2, summary.3
    ))
}

fn verify_run_receipt(request: &Request) -> Result<Vec<u8>, Failure> {
    let receipt_bytes = read_bounded(&request.run_receipt, "run receipt", 64 * 1024)?;
    let receipt_text = core::str::from_utf8(&receipt_bytes)
        .map_err(|_| Failure::task("DW1-B run receipt is not UTF-8"))?;
    let values = parse_scalars(receipt_text)?;
    exact_keys(&values, RUN_RECEIPT_KEYS, "DW1-B run receipt")?;
    let build_receipt = read_bounded(&request.receipt, "build receipt", 64 * 1024)?;
    let esp = read(&request.esp, "ESP")?;
    let bootfs = read(&request.bootfs, "bootfs")?;
    let serial = read_bounded(&request.serial_log, "serial log", 16 * 1024 * 1024)?;
    for (key, expected) in [
        ("kind", RUN_RECEIPT_KIND.to_owned()),
        ("schema_version", "1".to_owned()),
        ("selector", SELECTOR.to_owned()),
        ("test_id", TEST_ID.to_string()),
        ("request_sha256", request.request_sha256.clone()),
        ("build_receipt_sha256", sha256::bytes_digest(&build_receipt)),
        ("esp_sha256", sha256::bytes_digest(&esp)),
        ("bootfs_sha256", sha256::bytes_digest(&bootfs)),
        ("serial_log_sha256", sha256::bytes_digest(&serial)),
        (
            "run_directory",
            relative_path_text(request, &request.run_directory)?,
        ),
        (
            "serial_log",
            relative_path_text(request, &request.serial_log)?,
        ),
        ("timeout_seconds", request.timeout_seconds.to_string()),
        ("qemu_exit_status", "33".to_owned()),
        ("timed_out", "false".to_owned()),
    ] {
        if required(&values, key)? != expected {
            return Err(Failure::task(format!(
                "DW1-B run receipt field {key} does not match the observed run product"
            )));
        }
    }
    Ok(serial)
}

fn build_archive(
    init: &[u8],
    hello: &[u8],
    hog: &[u8],
    progress: &[u8],
) -> Result<Vec<u8>, Failure> {
    let mut builder = Builder::new();
    for (path, bytes) in [
        (b"system/init".as_slice(), init),
        (b"bin/hello", hello),
        (b"test/dw1-b/cpu-hog", hog),
        (b"test/dw1-b/progress", progress),
    ] {
        if bytes.is_empty() {
            return Err(Failure::task("DW1-B artifacts must be nonempty"));
        }
        builder
            .add(path, bytes, FileMode::Executable)
            .map_err(|e| Failure::task(format!("DW1-B bootfs add failed: {e:?}")))?;
    }
    builder
        .build()
        .map_err(|e| Failure::task(format!("DW1-B bootfs build failed: {e:?}")))
}

fn verify_archive(bootfs: &[u8], artifacts: [&[u8]; 4]) -> Result<(), Failure> {
    let archive =
        Archive::new(bootfs).map_err(|e| Failure::task(format!("DW1-B bootfs invalid: {e:?}")))?;
    for ((path, expected), actual) in [
        (b"system/init".as_slice(), artifacts[0]),
        (b"bin/hello", artifacts[1]),
        (b"test/dw1-b/cpu-hog", artifacts[2]),
        (b"test/dw1-b/progress", artifacts[3]),
    ]
    .into_iter()
    .zip(0..)
    {
        let entry = archive
            .lookup(path)
            .map_err(|e| Failure::task(format!("DW1-B entry {actual} missing: {e:?}")))?;
        if entry.data() != expected || !entry.is_executable() {
            return Err(Failure::task("DW1-B bootfs substitution or mode mismatch"));
        }
    }
    if archive.entries().count() != 4 {
        return Err(Failure::task("DW1-B bootfs contains an undeclared entry"));
    }
    Ok(())
}

fn verify_product_inputs(request: &Request, inputs: ProductInputs<'_>) -> Result<(), Failure> {
    verify_static_elf("kernel", inputs.kernel)?;
    verify_static_elf("symbols", inputs.symbols)?;
    let init = verify_static_elf("init", inputs.init)?;
    verify_static_elf("hello", inputs.hello)?;
    let hog = verify_static_elf("cpu hog", inputs.hog)?;
    let progress = verify_static_elf("progress", inputs.progress)?;
    if !contains_loaded_marker(inputs.init, &init, b"WYRMINIT0-PROFILE-V1:dw1b-preemption")
        || !contains_loaded_marker(inputs.hog, &hog, b"WYRMDW1B-HOG-V1:steady-spin-only")
        || !contains_loaded_marker(
            inputs.progress,
            &progress,
            b"WYRMDW1B-PROGRESS-V1:eight-rounds",
        )
    {
        return Err(Failure::task(
            "DW1-B payload profile marker is absent from a PT_LOAD segment",
        ));
    }
    let provenance = core::str::from_utf8(inputs.provenance)
        .map_err(|_| Failure::task("DW1-B provenance is not UTF-8"))?;
    let values = parse_scalars(provenance)?;
    exact_keys(&values, PROVENANCE_KEYS, "DW1-B provenance")?;
    for (key, expected) in [
        ("kind", PROVENANCE_KIND.to_owned()),
        ("schema_version", "1".to_owned()),
        ("selector", SELECTOR.to_owned()),
        ("test_id", TEST_ID.to_string()),
        ("deepwyrm_revision", DEEPWYRM_CANDIDATE.to_owned()),
        ("deepwyrm_abi_tree", DEEPWYRM_ABI_TREE.to_owned()),
        ("rust_revision", request.rust_revision.clone()),
        ("kernel_sha256", sha256::bytes_digest(inputs.kernel)),
        ("symbols_sha256", sha256::bytes_digest(inputs.symbols)),
        (
            "DEEPWYRM_DW1B_EVIDENCE_NONCE",
            format!("{:016X}", request.evidence_nonce),
        ),
        ("DEEPWYRM_DW1B_CHALLENGE_DIGEST", format!("{DIGEST:016X}")),
        (
            "DEEPWYRM_DW1B_BOOTFS_MAX_PAGES",
            request.bootfs_pages.to_string(),
        ),
    ] {
        if required(&values, key)? != expected {
            return Err(Failure::task(format!(
                "DW1-B provenance field {key} disagrees with the exact kernel build input"
            )));
        }
    }
    Ok(())
}

struct ElfLayout {
    load_file_ranges: Vec<(usize, usize)>,
}

fn verify_static_elf(label: &str, bytes: &[u8]) -> Result<ElfLayout, Failure> {
    if bytes.len() < 64
        || &bytes[..4] != b"\x7fELF"
        || bytes[4] != 2
        || bytes[5] != 1
        || u16::from_le_bytes([bytes[16], bytes[17]]) != 2
        || u16::from_le_bytes([bytes[18], bytes[19]]) != 62
        || u16::from_le_bytes([bytes[52], bytes[53]]) != 64
    {
        return Err(Failure::task(format!(
            "DW1-B {label} is not a static x86_64 executable ELF"
        )));
    }
    let phoff = usize::try_from(u64::from_le_bytes(bytes[32..40].try_into().unwrap()))
        .map_err(|_| Failure::task("DW1-B ELF program-header offset overflow"))?;
    let phentsize = usize::from(u16::from_le_bytes([bytes[54], bytes[55]]));
    let phnum = usize::from(u16::from_le_bytes([bytes[56], bytes[57]]));
    if phentsize != 56 || !(1..=64).contains(&phnum) {
        return Err(Failure::task("DW1-B ELF program-header size is invalid"));
    }
    let table_size = phentsize
        .checked_mul(phnum)
        .ok_or_else(|| Failure::task("DW1-B ELF program-header table overflow"))?;
    let table_end = phoff
        .checked_add(table_size)
        .ok_or_else(|| Failure::task("DW1-B ELF program-header table overflow"))?;
    if phoff < 64 || table_end > bytes.len() {
        return Err(Failure::task("DW1-B ELF program-header table is invalid"));
    }
    let entry = u64::from_le_bytes(bytes[24..32].try_into().unwrap());
    if entry == 0 {
        return Err(Failure::task("DW1-B ELF entry is zero"));
    }
    let mut load_file_ranges = Vec::new();
    let mut entry_is_executable = false;
    for index in 0..phnum {
        let offset = phoff
            .checked_add(index.checked_mul(phentsize).unwrap())
            .ok_or_else(|| Failure::task("DW1-B ELF program-header overflow"))?;
        let header = bytes
            .get(offset..offset + phentsize)
            .ok_or_else(|| Failure::task("DW1-B ELF program-header is truncated"))?;
        let kind = u32::from_le_bytes(header[..4].try_into().unwrap());
        if kind == 2 || kind == 3 {
            return Err(Failure::task(format!(
                "DW1-B {label} has a dynamic or interpreter segment"
            )));
        }
        if kind != 1 {
            continue;
        }
        let flags = u32::from_le_bytes(header[4..8].try_into().unwrap());
        let file_offset = u64::from_le_bytes(header[8..16].try_into().unwrap());
        let virtual_address = u64::from_le_bytes(header[16..24].try_into().unwrap());
        let file_size = u64::from_le_bytes(header[32..40].try_into().unwrap());
        let memory_size = u64::from_le_bytes(header[40..48].try_into().unwrap());
        let align = u64::from_le_bytes(header[48..56].try_into().unwrap());
        if flags & !7 != 0
            || flags & 2 != 0 && flags & 1 != 0
            || file_size > memory_size
            || memory_size == 0
            || align != 0
                && (!align.is_power_of_two() || file_offset % align != virtual_address % align)
        {
            return Err(Failure::task(format!(
                "DW1-B {label} has an invalid PT_LOAD contract"
            )));
        }
        let file_start = usize::try_from(file_offset)
            .map_err(|_| Failure::task("DW1-B PT_LOAD file offset overflow"))?;
        let file_end = usize::try_from(
            file_offset
                .checked_add(file_size)
                .ok_or_else(|| Failure::task("DW1-B PT_LOAD file range overflow"))?,
        )
        .map_err(|_| Failure::task("DW1-B PT_LOAD file range overflow"))?;
        if file_end > bytes.len() {
            return Err(Failure::task("DW1-B PT_LOAD exceeds the ELF file"));
        }
        let memory_end = virtual_address
            .checked_add(memory_size)
            .ok_or_else(|| Failure::task("DW1-B PT_LOAD virtual range overflow"))?;
        if flags & 1 != 0 && (virtual_address..memory_end).contains(&entry) {
            entry_is_executable = true;
        }
        load_file_ranges.push((file_start, file_end));
    }
    if load_file_ranges.is_empty() || !entry_is_executable {
        return Err(Failure::task(format!(
            "DW1-B {label} entry is not inside an executable PT_LOAD"
        )));
    }
    Ok(ElfLayout { load_file_ranges })
}

fn contains_loaded_marker(bytes: &[u8], layout: &ElfLayout, marker: &[u8]) -> bool {
    layout.load_file_ranges.iter().any(|(start, end)| {
        bytes[*start..*end]
            .windows(marker.len())
            .any(|window| window == marker)
    })
}

fn parse_summary(line: &[u8], nonce: u64) -> Result<(u64, u64, u64, u64), Failure> {
    if line.len() != 122
        || &line[..7] != b"DWPRE1|"
        || line[9] != b'|'
        || line[26] != b'|'
        || line[35] != b'|'
        || line[52] != b'|'
        || line[69] != b'|'
        || line[86] != b'|'
        || line[103] != b'|'
        || line[112] != b'|'
        || line[121] != b'\n'
    {
        return Err(Failure::task("malformed DWPRE1 summary"));
    }
    if &line[7..9] != b"01"
        || hex(&line[10..26])? != nonce
        || &line[27..35] != b"00000000"
        || &line[104..112] != b"000000FF"
        || hex(&line[113..121])? as u32 != fnv1a32(&line[..113])
    {
        return Err(Failure::task(
            "DWPRE1 identity, facts, or checksum mismatch",
        ));
    }
    let quantum = hex(&line[36..52])?;
    let involuntary = hex(&line[53..69])?;
    let switches = hex(&line[70..86])?;
    let wakeups = hex(&line[87..103])?;
    if !(1..=256).contains(&involuntary)
        || involuntary > quantum
        || quantum > 256
        || switches < involuntary
        || wakeups < 8
    {
        return Err(Failure::task("DWPRE1 scheduler relations failed"));
    }
    Ok((quantum, involuntary, switches, wakeups))
}

fn parse_terminal(line: &[u8]) -> Result<(), Failure> {
    if line.len() != 38
        || &line[..11] != b"DWTEST1|01|"
        || &line[11..19] != b"0000001A"
        || line[19] != b'|'
        || &line[20..28] != b"00000000"
        || line[28] != b'|'
        || line[37] != b'\n'
        || hex(&line[29..37])? as u32 != fnv1a32(&line[..29])
    {
        return Err(Failure::task("DWTEST1 selector-26 terminal is invalid"));
    }
    Ok(())
}

fn receipt(
    request: &Request,
    bootfs: &[u8],
    artifacts: [&[u8]; 4],
    platform: [&[u8]; 6],
) -> String {
    format!(
        "kind = \"{RECEIPT_KIND}\"\nschema_version = 5\nselector = \"{SELECTOR}\"\ntest_id = 26\nrequest_sha256 = \"{}\"\ndeepwyrm_revision = \"{}\"\ndeepwyrm_abi_tree = \"{DEEPWYRM_ABI_TREE}\"\nwyrmroot_revision = \"{}\"\nrust_revision = \"{}\"\nloader_sha256 = \"{}\"\nkernel_sha256 = \"{}\"\nsymbols_sha256 = \"{}\"\nbootstrap_sha256 = \"{}\"\nprovenance_sha256 = \"{}\"\nesp_sha256 = \"{}\"\nbootfs_sha256 = \"{}\"\ninit_sha256 = \"{}\"\nhello_sha256 = \"{}\"\ncpu_hog_sha256 = \"{}\"\nprogress_sha256 = \"{}\"\nbootfs_bytes = {}\nbootfs_pages = {}\nkernel_bootfs_env = \"DEEPWYRM_DW1B_BOOTFS_MAX_PAGES={}\"\nevidence_nonce = \"{:016X}\"\nchallenge_digest = \"{DIGEST:016X}\"\ntimeout_seconds = {}\n",
        request.request_sha256,
        request.deepwyrm_revision,
        request.wyrmroot_revision,
        request.rust_revision,
        sha256::bytes_digest(platform[0]),
        sha256::bytes_digest(platform[1]),
        sha256::bytes_digest(platform[2]),
        sha256::bytes_digest(platform[3]),
        sha256::bytes_digest(platform[4]),
        sha256::bytes_digest(platform[5]),
        sha256::bytes_digest(bootfs),
        sha256::bytes_digest(artifacts[0]),
        sha256::bytes_digest(artifacts[1]),
        sha256::bytes_digest(artifacts[2]),
        sha256::bytes_digest(artifacts[3]),
        bootfs.len(),
        bootfs.len().div_ceil(4096),
        request.bootfs_pages,
        request.evidence_nonce,
        request.timeout_seconds,
    )
}

fn verify_receipt(
    request: &Request,
    bootfs: &[u8],
    artifacts: [&[u8]; 4],
    platform: [&[u8]; 6],
) -> Result<(), Failure> {
    let observed = fs::read_to_string(&request.receipt)
        .map_err(|e| Failure::task(format!("could not read DW1-B receipt: {e}")))?;
    if observed != receipt(request, bootfs, artifacts, platform) {
        return Err(Failure::task("DW1-B receipt does not match product"));
    }
    Ok(())
}

fn parse_scalars(text: &str) -> Result<BTreeMap<String, String>, Failure> {
    let mut out = BTreeMap::new();
    for (index, raw) in text.lines().enumerate() {
        let line = raw.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        let (key, value) = line
            .split_once('=')
            .ok_or_else(|| Failure::task(format!("DW1-B request line {} is invalid", index + 1)))?;
        let key = key.trim();
        let value = value.trim();
        let value = value
            .strip_prefix('"')
            .and_then(|v| v.strip_suffix('"'))
            .unwrap_or(value);
        if out.insert(key.to_owned(), value.to_owned()).is_some() {
            return Err(Failure::task("DW1-B request repeats a key"));
        }
    }
    Ok(out)
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
        .ok_or_else(|| Failure::task(format!("DW1-B request lacks {key}")))
}
fn number<T: core::str::FromStr>(
    values: &BTreeMap<String, String>,
    key: &str,
) -> Result<T, Failure> {
    required(values, key)?
        .parse()
        .map_err(|_| Failure::task(format!("DW1-B {key} is invalid")))
}
fn bounded_number<T>(
    values: &BTreeMap<String, String>,
    key: &str,
    minimum: T,
    maximum: T,
) -> Result<T, Failure>
where
    T: core::str::FromStr + Copy + Ord,
{
    let raw = required(values, key)?;
    let value = raw
        .parse::<T>()
        .map_err(|_| Failure::task(format!("DW1-B {key} is invalid")))?;
    if raw.len() > 1 && raw.starts_with('0') || value < minimum || value > maximum {
        return Err(Failure::task(format!("DW1-B {key} is out of range")));
    }
    Ok(value)
}
fn revision(values: &BTreeMap<String, String>, key: &str) -> Result<String, Failure> {
    let v = required(values, key)?;
    if v.len() != 40
        || v.bytes().all(|byte| byte == b'0')
        || !v
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        return Err(Failure::task(format!("DW1-B {key} is not a commit")));
    }
    Ok(v.to_owned())
}
fn digest(values: &BTreeMap<String, String>, key: &str) -> Result<String, Failure> {
    let value = required(values, key)?;
    if value.len() != 64
        || value == SHA256_ZERO
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(Failure::task(format!(
            "DW1-B {key} is not a nonzero lowercase SHA-256"
        )));
    }
    Ok(value.to_owned())
}
fn clean_path(parent: &Path, value: &str, output: bool) -> Result<PathBuf, Failure> {
    let p = Path::new(value);
    if p.is_absolute() || p.components().any(|c| !matches!(c, Component::Normal(_))) {
        return Err(Failure::task("DW1-B path is not canonical relative"));
    }
    let p = parent.join(p);
    reject_symlink_ancestry(parent, &p)?;
    if output {
        if p.exists() {
            let metadata = fs::symlink_metadata(&p)
                .map_err(|e| Failure::task(format!("could not inspect DW1-B output: {e}")))?;
            if metadata.file_type().is_symlink() {
                return Err(Failure::task("DW1-B output contains a symlink"));
            }
            let resolved = fs::canonicalize(&p)
                .map_err(|e| Failure::task(format!("could not resolve DW1-B output: {e}")))?;
            if !resolved.starts_with(parent) {
                return Err(Failure::task("DW1-B output escapes through a symlink"));
            }
        } else {
            let mut ancestor = p.parent();
            while ancestor.is_some_and(|path| !path.exists()) {
                ancestor = ancestor.and_then(Path::parent);
            }
            let ancestor =
                ancestor.ok_or_else(|| Failure::task("DW1-B output has no existing parent"))?;
            let resolved = fs::canonicalize(ancestor).map_err(|e| {
                Failure::task(format!("could not resolve DW1-B output parent: {e}"))
            })?;
            if !resolved.starts_with(parent) {
                return Err(Failure::task("DW1-B output parent escapes request root"));
            }
        }
        Ok(p)
    } else if p.is_file() {
        let metadata = fs::symlink_metadata(&p)
            .map_err(|e| Failure::task(format!("could not inspect DW1-B input: {e}")))?;
        if !metadata.is_file() || metadata.nlink() != 1 {
            return Err(Failure::task(
                "DW1-B input is not a single-link regular file",
            ));
        }
        let resolved = fs::canonicalize(&p)
            .map_err(|e| Failure::task(format!("could not resolve DW1-B input: {e}")))?;
        if !resolved.starts_with(parent) {
            return Err(Failure::task("DW1-B input escapes through a symlink"));
        }
        Ok(resolved)
    } else {
        Err(Failure::task("DW1-B input is not a file"))
    }
}
fn reject_symlink_ancestry(parent: &Path, path: &Path) -> Result<(), Failure> {
    let relative = path
        .strip_prefix(parent)
        .map_err(|_| Failure::task("DW1-B path escapes request root"))?;
    let mut current = parent.to_path_buf();
    for component in relative.components() {
        let Component::Normal(name) = component else {
            return Err(Failure::task("DW1-B path is not canonical relative"));
        };
        current.push(name);
        match fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(Failure::task("DW1-B path contains symlink ancestry"));
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => break,
            Err(error) => {
                return Err(Failure::task(format!(
                    "could not inspect DW1-B path ancestry: {error}"
                )));
            }
        }
    }
    Ok(())
}
fn input(parent: &Path, value: &str) -> Result<PathBuf, Failure> {
    clean_path(parent, value, false)
}
fn reject_path_aliases(request: &Request) -> Result<(), Failure> {
    let paths = [
        &request.loader,
        &request.kernel,
        &request.symbols,
        &request.bootstrap,
        &request.init,
        &request.hello,
        &request.cpu_hog,
        &request.progress,
        &request.provenance,
        &request.bootfs,
        &request.esp,
        &request.run_directory,
        &request.serial_log,
        &request.run_receipt,
        &request.receipt,
    ];
    let mut unique = BTreeSet::new();
    let mut identities = BTreeSet::new();
    for path in paths {
        if !unique.insert(path) {
            return Err(Failure::task(
                "DW1-B input, output, or run-directory paths alias",
            ));
        }
        if let Ok(metadata) = fs::symlink_metadata(path)
            && (metadata.file_type().is_symlink()
                || metadata.is_file() && metadata.nlink() != 1
                || !identities.insert((metadata.dev(), metadata.ino())))
        {
            return Err(Failure::task(
                "DW1-B input, output, or run-directory inode aliases",
            ));
        }
    }
    Ok(())
}
fn output(parent: &Path, value: &str) -> Result<PathBuf, Failure> {
    clean_path(parent, value, true)
}
fn parse_hex_u64(value: &str) -> Result<u64, Failure> {
    if value.len() != 16
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'A'..=b'F').contains(&b))
    {
        return Err(Failure::task(
            "DW1-B hexadecimal field is not canonical uppercase",
        ));
    }
    u64::from_str_radix(value, 16).map_err(|_| Failure::task("DW1-B hexadecimal field overflow"))
}
fn hex(bytes: &[u8]) -> Result<u64, Failure> {
    let s = core::str::from_utf8(bytes).map_err(|_| Failure::task("evidence is not ASCII"))?;
    parse_hex_u64_padded(s)
}
fn parse_hex_u64_padded(value: &str) -> Result<u64, Failure> {
    if value.is_empty()
        || value.len() > 16
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'A'..=b'F').contains(&b))
    {
        return Err(Failure::task("evidence hexadecimal field is not canonical"));
    }
    u64::from_str_radix(value, 16).map_err(|_| Failure::task("evidence hexadecimal overflow"))
}
fn fnv1a32(bytes: &[u8]) -> u32 {
    bytes.iter().fold(0x811C_9DC5, |hash, byte| {
        (hash ^ u32::from(*byte)).wrapping_mul(0x0100_0193)
    })
}
fn read(path: &Path, label: &str) -> Result<Vec<u8>, Failure> {
    fs::read(path).map_err(|e| Failure::task(format!("could not read DW1-B {label}: {e}")))
}
fn read_expected(path: &Path, label: &str, expected: &str) -> Result<Vec<u8>, Failure> {
    let bytes = read(path, label)?;
    if sha256::bytes_digest(&bytes) != expected {
        return Err(Failure::task(format!(
            "DW1-B {label} does not match its request-bound SHA-256"
        )));
    }
    Ok(bytes)
}
fn read_bounded(path: &Path, label: &str, maximum: u64) -> Result<Vec<u8>, Failure> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|e| Failure::task(format!("could not inspect DW1-B {label}: {e}")))?;
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.nlink() != 1
        || metadata.len() == 0
        || metadata.len() > maximum
    {
        return Err(Failure::task(format!(
            "DW1-B {label} is not a bounded single-link regular file"
        )));
    }
    read(path, label)
}
fn relative_path_text(request: &Request, path: &Path) -> Result<String, Failure> {
    let relative = path
        .strip_prefix(&request.root)
        .map_err(|_| Failure::task("DW1-B run path is not request-relative"))?;
    if relative.as_os_str().is_empty()
        || relative
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(Failure::task("DW1-B run path is not canonical"));
    }
    relative
        .to_str()
        .map(str::to_owned)
        .ok_or_else(|| Failure::task("DW1-B run path is not UTF-8"))
}
fn io_failure(error: std::io::Error) -> Failure {
    Failure::task(format!("DW1-B output failed: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    const TEST_WYRMROOT_REVISION: &str = "1111111111111111111111111111111111111111";
    const TEST_RUST_REVISION: &str = "2222222222222222222222222222222222222222";

    #[test]
    fn exact_summary_and_terminal_are_ordered_and_relational() {
        let nonce = 0x0123_4567_89AB_CDEF;
        let mut pre=format!("DWPRE1|01|{nonce:016X}|00000000|0000000000000008|0000000000000002|0000000000000002|0000000000000008|000000FF|").into_bytes();
        let checksum = fnv1a32(&pre);
        pre.extend_from_slice(format!("{checksum:08X}\n").as_bytes());
        assert_eq!(pre.len(), 122);
        assert_eq!(parse_summary(&pre, nonce), Ok((8, 2, 2, 8)));
        let mut terminal = b"DWTEST1|01|0000001A|00000000|".to_vec();
        let checksum = fnv1a32(&terminal);
        terminal.extend_from_slice(format!("{checksum:08X}\n").as_bytes());
        assert_eq!(parse_terminal(&terminal), Ok(()));
        pre[53] = b'0';
        pre[68] = b'0';
        assert!(parse_summary(&pre, nonce).is_err());
    }
    #[test]
    fn product_is_exact_four_entry_and_deterministic() {
        let first = build_archive(b"i", b"h", b"c", b"p").unwrap();
        let second = build_archive(b"i", b"h", b"c", b"p").unwrap();
        assert_eq!(first, second);
        verify_archive(&first, [b"i", b"h", b"c", b"p"]).unwrap();
    }

    #[test]
    fn schema_rejects_revision_timeout_alias_traversal_and_symlink_ancestry() {
        let root = fixture();
        let request = root.join("request.toml");
        let valid = request_text();
        fs::write(&request, &valid).unwrap();
        load(&request).unwrap();
        for invalid in [
            valid.replace(
                DEEPWYRM_CANDIDATE,
                "1859684651e32655cc9f322fcca5b732d2cb12ca",
            ),
            valid.replace("timeout_seconds = 30", "timeout_seconds = 0"),
            valid.replace("esp = \"out/esp.img\"", "esp = \"out/bootfs.img\""),
            valid.replace("hello = \"inputs/hello\"", "hello = \"../hello\""),
            valid.replace(
                &format!("wyrmroot_revision = \"{TEST_WYRMROOT_REVISION}\""),
                "wyrmroot_revision = \"0000000000000000000000000000000000000000\"",
            ),
        ] {
            fs::write(&request, invalid).unwrap();
            assert!(load(&request).is_err());
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;
            let link = root.join("inputs/link");
            symlink(root.join("inputs/hello"), &link).unwrap();
            fs::write(
                &request,
                valid.replace("hello = \"inputs/hello\"", "hello = \"inputs/link\""),
            )
            .unwrap();
            assert!(load(&request).is_err());

            fs::create_dir(root.join("inputs/real-directory")).unwrap();
            fs::write(root.join("inputs/real-directory/hello"), b"x").unwrap();
            symlink(
                root.join("inputs/real-directory"),
                root.join("inputs/directory-link"),
            )
            .unwrap();
            fs::write(
                &request,
                valid.replace(
                    "hello = \"inputs/hello\"",
                    "hello = \"inputs/directory-link/hello\"",
                ),
            )
            .unwrap();
            assert!(load(&request).is_err());
        }
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn inode_aliases_are_rejected() {
        let root = fixture();
        let request = root.join("request.toml");
        fs::hard_link(root.join("inputs/hello"), root.join("inputs/hello-alias")).unwrap();
        fs::write(
            &request,
            request_text().replace(
                "progress = \"inputs/progress\"",
                "progress = \"inputs/hello-alias\"",
            ),
        )
        .unwrap();
        assert!(load(&request).is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn evidence_requires_an_exact_request_bound_run_receipt() {
        let root = fixture();
        fs::create_dir_all(root.join("out")).unwrap();
        fs::create_dir_all(root.join("run")).unwrap();
        let request_path = root.join("request.toml");
        fs::write(&request_path, request_text()).unwrap();
        fs::write(root.join("out/receipt.toml"), b"build receipt").unwrap();
        fs::write(root.join("out/esp.img"), b"esp").unwrap();
        fs::write(root.join("out/bootfs.img"), b"bootfs").unwrap();
        let serial = valid_evidence_log(1);
        fs::write(root.join("run/serial.log"), &serial).unwrap();
        let request = load(&request_path).unwrap();
        let run_receipt = run_receipt_text(&request, &serial);
        fs::write(root.join("run/run-receipt.toml"), &run_receipt).unwrap();
        assert_eq!(verify_run_receipt(&request).unwrap(), serial);

        fs::write(
            root.join("run/run-receipt.toml"),
            run_receipt.replace("qemu_exit_status = 33", "qemu_exit_status = 32"),
        )
        .unwrap();
        assert!(verify_run_receipt(&request).is_err());
        assert!(evidence(Path::new("missing")).is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn canonical_template_names_exact_candidate_and_digest() {
        let template = include_str!("../../../toolchain/templates/dw1-b-request.toml");
        assert!(template.contains(DEEPWYRM_CANDIDATE));
        assert!(template.contains(DEEPWYRM_ABI_TREE));
        assert!(template.contains("challenge_digest = \"5E4E054B5C244ACE\""));
        assert!(template.contains("bootfs_pages = 1424"));
        assert!(template.contains("REPLACE_WITH_INTEGRATED_WYRMROOT_COMMIT"));
        assert!(!template.contains("revision = \"0000000000000000000000000000000000000000\""));
    }

    #[test]
    fn elf_audit_requires_static_loaded_identity() {
        let marker = b"WYRMDW1B-HOG-V1:steady-spin-only";
        let valid = valid_elf(marker);
        let layout = verify_static_elf("fixture", &valid).unwrap();
        assert!(contains_loaded_marker(&valid, &layout, marker));

        let mut appended = valid_elf(b"different loaded bytes");
        let layout = verify_static_elf("fixture", &appended).unwrap();
        appended.extend_from_slice(marker);
        assert!(!contains_loaded_marker(&appended, &layout, marker));

        let mut zero_entry = valid.clone();
        zero_entry[24..32].copy_from_slice(&0_u64.to_le_bytes());
        assert!(verify_static_elf("fixture", &zero_entry).is_err());

        let mut dynamic = valid.clone();
        dynamic[64..68].copy_from_slice(&2_u32.to_le_bytes());
        assert!(verify_static_elf("fixture", &dynamic).is_err());

        let mut writable_executable = valid;
        writable_executable[68..72].copy_from_slice(&7_u32.to_le_bytes());
        assert!(verify_static_elf("fixture", &writable_executable).is_err());
    }

    fn fixture() -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("wyrmroot-dw1b-{nonce}"));
        fs::create_dir_all(root.join("inputs")).unwrap();
        for name in [
            "loader",
            "kernel",
            "symbols",
            "bootstrap",
            "init",
            "hello",
            "hog",
            "progress",
            "provenance",
        ] {
            fs::write(root.join("inputs").join(name), b"x").unwrap();
        }
        root
    }

    fn request_text() -> String {
        let input_hash = sha256::bytes_digest(b"x");
        format!(
            "schema_version = 5\ndeepwyrm_revision = \"{DEEPWYRM_CANDIDATE}\"\ndeepwyrm_abi_tree = \"{DEEPWYRM_ABI_TREE}\"\nwyrmroot_revision = \"{TEST_WYRMROOT_REVISION}\"\nrust_revision = \"{TEST_RUST_REVISION}\"\nselector = \"{SELECTOR}\"\ntest_id = 26\ntimeout_seconds = 30\nloader = \"inputs/loader\"\nloader_sha256 = \"{input_hash}\"\nkernel = \"inputs/kernel\"\nkernel_sha256 = \"{input_hash}\"\nsymbols = \"inputs/symbols\"\nsymbols_sha256 = \"{input_hash}\"\nbootstrap = \"inputs/bootstrap\"\nbootstrap_sha256 = \"{input_hash}\"\ninit = \"inputs/init\"\ninit_sha256 = \"{input_hash}\"\nhello = \"inputs/hello\"\nhello_sha256 = \"{input_hash}\"\ncpu_hog = \"inputs/hog\"\ncpu_hog_sha256 = \"{input_hash}\"\nprogress = \"inputs/progress\"\nprogress_sha256 = \"{input_hash}\"\nprovenance = \"inputs/provenance\"\nprovenance_sha256 = \"{input_hash}\"\nbootfs = \"out/bootfs.img\"\nesp = \"out/esp.img\"\nrun_directory = \"run\"\nserial_log = \"run/serial.log\"\nrun_receipt = \"run/run-receipt.toml\"\nevidence_nonce = \"0000000000000001\"\nchallenge_digest = \"{DIGEST:016X}\"\nbootfs_pages = 1\nreceipt = \"out/receipt.toml\"\n"
        )
    }

    fn valid_evidence_log(nonce: u64) -> Vec<u8> {
        let mut pre = format!("DWPRE1|01|{nonce:016X}|00000000|0000000000000008|0000000000000002|0000000000000002|0000000000000008|000000FF|").into_bytes();
        let checksum = fnv1a32(&pre);
        pre.extend_from_slice(format!("{checksum:08X}\n").as_bytes());
        let mut terminal = b"DWTEST1|01|0000001A|00000000|".to_vec();
        let checksum = fnv1a32(&terminal);
        terminal.extend_from_slice(format!("{checksum:08X}\n").as_bytes());
        pre.extend_from_slice(&terminal);
        pre
    }

    fn run_receipt_text(request: &Request, serial: &[u8]) -> String {
        format!(
            "kind = \"{RUN_RECEIPT_KIND}\"\nschema_version = 1\nselector = \"{SELECTOR}\"\ntest_id = 26\nrequest_sha256 = \"{}\"\nbuild_receipt_sha256 = \"{}\"\nesp_sha256 = \"{}\"\nbootfs_sha256 = \"{}\"\nserial_log_sha256 = \"{}\"\nrun_directory = \"run\"\nserial_log = \"run/serial.log\"\ntimeout_seconds = 30\nqemu_exit_status = 33\ntimed_out = false\n",
            request.request_sha256,
            sha256::bytes_digest(b"build receipt"),
            sha256::bytes_digest(b"esp"),
            sha256::bytes_digest(b"bootfs"),
            sha256::bytes_digest(serial),
        )
    }

    fn valid_elf(marker: &[u8]) -> Vec<u8> {
        let mut elf = vec![0_u8; 120];
        elf[..4].copy_from_slice(b"\x7fELF");
        elf[4] = 2;
        elf[5] = 1;
        elf[16..18].copy_from_slice(&2_u16.to_le_bytes());
        elf[18..20].copy_from_slice(&62_u16.to_le_bytes());
        elf[24..32].copy_from_slice(&0x0040_0000_u64.to_le_bytes());
        elf[32..40].copy_from_slice(&64_u64.to_le_bytes());
        elf[52..54].copy_from_slice(&64_u16.to_le_bytes());
        elf[54..56].copy_from_slice(&56_u16.to_le_bytes());
        elf[56..58].copy_from_slice(&1_u16.to_le_bytes());
        elf[64..68].copy_from_slice(&1_u32.to_le_bytes());
        elf[68..72].copy_from_slice(&5_u32.to_le_bytes());
        elf[80..88].copy_from_slice(&0x0040_0000_u64.to_le_bytes());
        elf.extend_from_slice(marker);
        let size = u64::try_from(elf.len()).unwrap();
        elf[96..104].copy_from_slice(&size.to_le_bytes());
        elf[104..112].copy_from_slice(&size.to_le_bytes());
        elf[112..120].copy_from_slice(&0x1000_u64.to_le_bytes());
        elf
    }
}
