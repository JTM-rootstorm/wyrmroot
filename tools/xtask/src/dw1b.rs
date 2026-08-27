//! DW1-B selector-26 request, four-entry product, receipt, and evidence parser.

use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Stdio};

use wyrmroot_bootfs::archive::Archive;
use wyrmroot_bootfs::builder::{Builder, FileMode};
use wyrmroot_loader::elf::{self, LoadSegment, MAX_LOAD_SEGMENTS, SegmentProtection};

use crate::error::Failure;
use crate::metadata::BuildManifest;
use crate::sha256;

pub const SCHEMA_VERSION: u32 = 5;
pub const SELECTOR: &str = "normal-preemption-up";
pub const TEST_ID: u32 = 26;
pub const DIGEST: u64 = 0x5E4E_054B_5C24_4ACE;
pub const DEEPWYRM_CANDIDATE: &str = "b203ba6d6a69443b9c51750369272446cb9604d9";
pub const DEEPWYRM_ABI_TREE: &str = "1c6a74f130e386eee95b3780c75950beefd0037d";
pub const ACCEPTED_RUST_REVISION: &str = "a92dc7f7464ad6ddfece4402bd7b86dbfa86166d";
const RECEIPT_KIND: &str = "wyrmroot-dw1-b-build-lineage";
const RUN_RECEIPT_KIND: &str = "wyrmroot-dw1-b-run-receipt";
const PROVENANCE_KIND: &str = "wyrmroot-dw1-b-kernel-build";
const WYR_BUILD_KIND: &str = "wyrmroot-dw1-b-wyr-source-build";
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
const GENERATED_ABI_REVISION: &str = "cfc69bd8a49819ce1cda1a132cf56e55c93f92e4";
const NATIVE_TARGET: &str = "x86_64-unknown-wyrmroot";
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
    "wyr_build_receipt",
    "provenance",
    "provenance_sha256",
    "ovmf_code",
    "ovmf_code_sha256",
    "ovmf_vars",
    "ovmf_vars_sha256",
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
const WYR_BUILD_RECEIPT_KEYS: &[&str] = &[
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
    "profile",
    "deep_layout_sha256",
    "generated_layout_policy_sha256",
    "uefi_effective_config_sha256",
    "uefi_inspector_sha256",
    "uefi_inspection_report_sha256",
    "toolchain_validation_report_sha256",
    "loader_command",
    "bootstrap_command",
    "init_command",
    "hello_command",
    "hog_command",
    "progress_command",
    "loader_sha256",
    "bootstrap_sha256",
    "init_sha256",
    "hello_sha256",
    "cpu_hog_sha256",
    "progress_sha256",
];
const RUN_RECEIPT_KEYS: &[&str] = &[
    "kind",
    "schema_version",
    "selector",
    "test_id",
    "request_sha256",
    "build_receipt_sha256",
    "wyr_build_receipt_sha256",
    "esp_sha256",
    "bootfs_sha256",
    "serial_log_sha256",
    "ovmf_code_sha256",
    "ovmf_vars_sha256",
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
    wyr_build_receipt: PathBuf,
    provenance: PathBuf,
    provenance_sha256: String,
    ovmf_code: PathBuf,
    ovmf_code_sha256: String,
    ovmf_vars: PathBuf,
    ovmf_vars_sha256: String,
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
    loader: &'a [u8],
    kernel: &'a [u8],
    symbols: &'a [u8],
    bootstrap: &'a [u8],
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
        || required(&values, "rust_revision")? != ACCEPTED_RUST_REVISION
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
        wyr_build_receipt: input(&parent, required(&values, "wyr_build_receipt")?)?,
        provenance: input(&parent, required(&values, "provenance")?)?,
        provenance_sha256: digest(&values, "provenance_sha256")?,
        ovmf_code: input(&parent, required(&values, "ovmf_code")?)?,
        ovmf_code_sha256: digest(&values, "ovmf_code_sha256")?,
        ovmf_vars: input(&parent, required(&values, "ovmf_vars")?)?,
        ovmf_vars_sha256: digest(&values, "ovmf_vars_sha256")?,
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
    build_product(path, false)
}

pub fn rebuild(path: &Path) -> Result<String, Failure> {
    build_product(path, true)
}

fn build_product(path: &Path, verify_rebuild: bool) -> Result<String, Failure> {
    let request = load(path)?;
    if verify_rebuild {
        verify_acceptance_source(&request)?;
        preflight_source_build_environment()?;
    }
    refuse_product_outputs(&request)?;
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
    let wyr_build_receipt = read_bounded(
        &request.wyr_build_receipt,
        "Wyr source-build receipt",
        64 * 1024,
    )?;
    verify_wyr_build_receipt(
        &request,
        &wyr_build_receipt,
        [&loader, &bootstrap, &init, &hello, &hog, &progress],
    )?;
    if verify_rebuild {
        verify_current_cargo_lock(&wyr_build_receipt)?;
    }
    verify_product_inputs(
        &request,
        ProductInputs {
            loader: &loader,
            kernel: &kernel,
            symbols: &symbols,
            bootstrap: &bootstrap,
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
    if verify_rebuild {
        fs::create_dir_all(&request.run_directory).map_err(io_failure)?;
        canonical_build_wyr_artifacts(&request)?;
    }
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
        [
            &loader,
            &kernel,
            &symbols,
            &bootstrap,
            &provenance,
            &esp,
            &wyr_build_receipt,
        ],
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

fn refuse_product_outputs(request: &Request) -> Result<(), Failure> {
    for path in [&request.bootfs, &request.esp, &request.receipt] {
        if fs::symlink_metadata(path).is_ok() {
            return Err(Failure::task(
                "DW1-B image refuses pre-existing product outputs",
            ));
        }
    }
    Ok(())
}

pub fn measure(init: &Path, hello: &Path, hog: &Path, progress: &Path) -> Result<String, Failure> {
    let hog_bytes = read(hog, "cpu hog")?;
    let hog_layout = verify_loader_elf("cpu hog", &hog_bytes)?;
    if !contains_exact_hog_steady_loop(&hog_bytes, &hog_layout) {
        return Err(Failure::task(
            "DW1-B measured cpu hog lacks the executed steady-loop control flow",
        ));
    }
    let bootfs = build_archive(
        &read(init, "init")?,
        &read(hello, "hello")?,
        &hog_bytes,
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
    verify_acceptance_source(&request)?;
    let wyr_build_receipt = read_bounded(
        &request.wyr_build_receipt,
        "Wyr source-build receipt",
        64 * 1024,
    )?;
    verify_current_cargo_lock(&wyr_build_receipt)?;
    inspect_recorded_request(&request)
}

fn inspect_recorded(path: &Path) -> Result<String, Failure> {
    let request = load(path)?;
    inspect_recorded_request(&request)
}

fn inspect_recorded_request(request: &Request) -> Result<String, Failure> {
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
    let wyr_build_receipt = read_bounded(
        &request.wyr_build_receipt,
        "Wyr source-build receipt",
        64 * 1024,
    )?;
    verify_wyr_build_receipt(
        request,
        &wyr_build_receipt,
        [
            &loader,
            &bootstrap,
            &artifacts[0],
            &artifacts[1],
            &artifacts[2],
            &artifacts[3],
        ],
    )?;
    verify_product_inputs(
        request,
        ProductInputs {
            loader: &loader,
            kernel: &kernel,
            symbols: &symbols,
            bootstrap: &bootstrap,
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
    inspect_canonical_esp(request)?;
    verify_receipt(
        request,
        &bootfs,
        [&artifacts[0], &artifacts[1], &artifacts[2], &artifacts[3]],
        [
            &loader,
            &kernel,
            &symbols,
            &bootstrap,
            &provenance,
            &esp,
            &wyr_build_receipt,
        ],
    )?;
    Ok(format!(
        "DW1_B_INSPECTION_PASS entries=4 bootfs_bytes={} bootfs_pages={} bootfs_sha256={}\n",
        bootfs.len(),
        bootfs.len().div_ceil(4096),
        sha256::bytes_digest(&bootfs)
    ))
}

fn inspect_canonical_esp(request: &Request) -> Result<(), Failure> {
    let image_args = crate::cli::G3ImageArguments {
        image: request.esp.display().to_string(),
        loader: request.loader.display().to_string(),
        kernel: request.kernel.display().to_string(),
        bootstrap: request.bootstrap.display().to_string(),
        bootfs: request.bootfs.display().to_string(),
    };
    crate::g3_image::inspect(&image_args).map(|_| ())
}

pub fn run(request_path: &Path) -> Result<String, Failure> {
    let (request, bytes) = execute_run(request_path, |run| {
        let outcome = crate::h_integration::run_canonical_one_cpu_selector(
            &crate::h_integration::CanonicalSelectorRun {
                ovmf_code: &run.ovmf_code,
                ovmf_vars: &run.ovmf_vars,
                esp: &run.esp,
                serial_log: &run.serial_log,
                stderr_log: &run.stderr_log,
                selector: SELECTOR,
                timeout_seconds: run.timeout_seconds,
            },
        )?;
        Ok(RunObservation {
            qemu_exit_status: outcome.qemu_exit_status,
            timed_out: outcome.timed_out,
        })
    })?;
    parse_evidence(&request, &bytes)
}

pub fn evidence(request_path: &Path) -> Result<String, Failure> {
    run(request_path)
}

fn parse_evidence(request: &Request, bytes: &[u8]) -> Result<String, Failure> {
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

struct RunInvocation {
    ovmf_code: PathBuf,
    ovmf_vars: PathBuf,
    esp: PathBuf,
    serial_log: PathBuf,
    stderr_log: PathBuf,
    timeout_seconds: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RunObservation {
    qemu_exit_status: Option<i32>,
    timed_out: bool,
}

fn execute_run(
    request_path: &Path,
    executor: impl FnOnce(&RunInvocation) -> Result<RunObservation, Failure>,
) -> Result<(Request, Vec<u8>), Failure> {
    let _ = inspect_recorded(request_path)?;
    let request = load(request_path)?;
    execute_run_loaded_with_validation(request_path, request, executor, || {
        inspect_recorded(request_path).map(|_| ())
    })
}

#[cfg(test)]
fn execute_run_loaded(
    request_path: &Path,
    request: Request,
    executor: impl FnOnce(&RunInvocation) -> Result<RunObservation, Failure>,
) -> Result<(Request, Vec<u8>), Failure> {
    execute_run_loaded_with_validation(request_path, request, executor, || Ok(()))
}

fn execute_run_loaded_with_validation(
    request_path: &Path,
    request: Request,
    executor: impl FnOnce(&RunInvocation) -> Result<RunObservation, Failure>,
    post_run_validator: impl FnOnce() -> Result<(), Failure>,
) -> Result<(Request, Vec<u8>), Failure> {
    if request.serial_log.parent() != Some(request.run_directory.as_path())
        || request.run_receipt.parent() != Some(request.run_directory.as_path())
    {
        return Err(Failure::task(
            "DW1-B serial and run receipt must be direct children of the run directory",
        ));
    }
    ensure_run_directory(&request.run_directory)?;
    let snapshot_request = request.run_directory.join("request.toml");
    let snapshot_esp = request.run_directory.join("booted-esp.img");
    let snapshot_code = request.run_directory.join("OVMF_CODE.fd");
    let snapshot_vars = request.run_directory.join("OVMF_VARS.fd");
    let snapshot_bootfs = request.run_directory.join("bootfs.img");
    let snapshot_build_receipt = request.run_directory.join("build-receipt.toml");
    let snapshot_wyr_build_receipt = request.run_directory.join("wyr-source-build.toml");
    let stderr_log = request.run_directory.join("qemu.stderr.log");
    for path in [
        &request.serial_log,
        &request.run_receipt,
        &snapshot_request,
        &snapshot_esp,
        &snapshot_code,
        &snapshot_vars,
        &snapshot_bootfs,
        &snapshot_build_receipt,
        &snapshot_wyr_build_receipt,
        &stderr_log,
    ] {
        if fs::symlink_metadata(path).is_ok() {
            return Err(Failure::task(
                "DW1-B run refuses caller-created or reused run products",
            ));
        }
    }
    let request_bytes = read_bounded(request_path, "request", 64 * 1024)?;
    if sha256::bytes_digest(&request_bytes) != request.request_sha256 {
        return Err(Failure::task("DW1-B request changed before run snapshot"));
    }
    write_new_file(&snapshot_request, &request_bytes)?;
    snapshot_exact(&request.esp, &snapshot_esp, None, "ESP")?;
    snapshot_exact(
        &request.ovmf_code,
        &snapshot_code,
        Some(&request.ovmf_code_sha256),
        "OVMF code",
    )?;
    snapshot_exact(
        &request.ovmf_vars,
        &snapshot_vars,
        Some(&request.ovmf_vars_sha256),
        "OVMF vars",
    )?;
    snapshot_exact(&request.bootfs, &snapshot_bootfs, None, "bootfs")?;
    snapshot_exact(
        &request.receipt,
        &snapshot_build_receipt,
        None,
        "build receipt",
    )?;
    snapshot_exact(
        &request.wyr_build_receipt,
        &snapshot_wyr_build_receipt,
        None,
        "Wyr source-build receipt",
    )?;
    let initial_esp_hash = sha256::file_digest(&snapshot_esp)
        .map_err(|error| Failure::task(format!("could not hash run-local ESP: {error}")))?;
    let invocation = RunInvocation {
        ovmf_code: snapshot_code.clone(),
        ovmf_vars: snapshot_vars,
        esp: snapshot_esp.clone(),
        serial_log: request.serial_log.clone(),
        stderr_log,
        timeout_seconds: request.timeout_seconds,
    };
    let observation = executor(&invocation)?;
    let serial = read_run_serial(&request.serial_log)?;
    let final_esp_hash = sha256::file_digest(&snapshot_esp)
        .map_err(|error| Failure::task(format!("could not rehash run-local ESP: {error}")))?;
    let final_code_hash = sha256::file_digest(&snapshot_code)
        .map_err(|error| Failure::task(format!("could not rehash run-local OVMF code: {error}")))?;
    if final_esp_hash != initial_esp_hash || final_code_hash != request.ovmf_code_sha256 {
        return Err(Failure::task(
            "DW1-B read-only boot media changed during canonical execution",
        ));
    }
    let request_after = read_bounded(request_path, "request", 64 * 1024)?;
    let live_esp = read_bounded(&request.esp, "ESP", crate::g3_image::IMAGE_BYTES)?;
    let live_bootfs = read_bounded(&request.bootfs, "bootfs", crate::g3_image::IMAGE_BYTES)?;
    let live_build_receipt = read_bounded(&request.receipt, "build receipt", 64 * 1024)?;
    let live_wyr_build_receipt = read_bounded(
        &request.wyr_build_receipt,
        "Wyr source-build receipt",
        64 * 1024,
    )?;
    let bootfs = read_bounded(
        &snapshot_bootfs,
        "run-local bootfs",
        crate::g3_image::IMAGE_BYTES,
    )?;
    let build_receipt = read_bounded(
        &snapshot_build_receipt,
        "run-local build receipt",
        64 * 1024,
    )?;
    let wyr_build_receipt = read_bounded(
        &snapshot_wyr_build_receipt,
        "run-local Wyr source-build receipt",
        64 * 1024,
    )?;
    if sha256::bytes_digest(&request_after) != request.request_sha256
        || sha256::bytes_digest(&live_esp) != initial_esp_hash
        || live_bootfs != bootfs
        || live_build_receipt != build_receipt
        || live_wyr_build_receipt != wyr_build_receipt
    {
        return Err(Failure::task(
            "DW1-B request or product changed during canonical execution",
        ));
    }
    post_run_validator()?;
    let receipt = render_run_receipt(
        &request,
        &serial,
        &initial_esp_hash,
        &build_receipt,
        &wyr_build_receipt,
        &bootfs,
        observation,
    )?;
    write_new_file(&request.run_receipt, receipt.as_bytes())?;
    if observation.timed_out {
        return Err(Failure::task(format!(
            "DW1-B canonical QEMU timed out after {} seconds",
            request.timeout_seconds
        )));
    }
    if observation.qemu_exit_status != Some(33) {
        return Err(Failure::task(format!(
            "DW1-B canonical QEMU did not produce debug-exit status 33: {:?}",
            observation.qemu_exit_status
        )));
    }
    let esp = read_bounded(
        &snapshot_esp,
        "run-local booted ESP",
        crate::g3_image::IMAGE_BYTES,
    )?;
    let verified =
        verify_run_receipt_against(&request, &esp, &bootfs, &build_receipt, &wyr_build_receipt)?;
    Ok((request, verified))
}

fn ensure_run_directory(path: &Path) -> Result<(), Failure> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if !metadata.is_dir() || metadata.file_type().is_symlink() {
                return Err(Failure::task("DW1-B run path is not a real directory"));
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            fs::create_dir(path).map_err(io_failure)?;
        }
        Err(error) => {
            return Err(Failure::task(format!(
                "could not inspect DW1-B run directory: {error}"
            )));
        }
    }
    Ok(())
}

fn render_run_receipt(
    request: &Request,
    serial: &[u8],
    esp_sha256: &str,
    build_receipt: &[u8],
    wyr_build_receipt: &[u8],
    bootfs: &[u8],
    observation: RunObservation,
) -> Result<String, Failure> {
    Ok(format!(
        "kind = \"{RUN_RECEIPT_KIND}\"\nschema_version = 2\nselector = \"{SELECTOR}\"\ntest_id = {TEST_ID}\nrequest_sha256 = \"{}\"\nbuild_receipt_sha256 = \"{}\"\nwyr_build_receipt_sha256 = \"{}\"\nesp_sha256 = \"{esp_sha256}\"\nbootfs_sha256 = \"{}\"\nserial_log_sha256 = \"{}\"\novmf_code_sha256 = \"{}\"\novmf_vars_sha256 = \"{}\"\nrun_directory = \"{}\"\nserial_log = \"{}\"\ntimeout_seconds = {}\nqemu_exit_status = {}\ntimed_out = {}\n",
        request.request_sha256,
        sha256::bytes_digest(build_receipt),
        sha256::bytes_digest(wyr_build_receipt),
        sha256::bytes_digest(bootfs),
        sha256::bytes_digest(serial),
        request.ovmf_code_sha256,
        request.ovmf_vars_sha256,
        relative_path_text(request, &request.run_directory)?,
        relative_path_text(request, &request.serial_log)?,
        request.timeout_seconds,
        observation.qemu_exit_status.unwrap_or(-1),
        observation.timed_out,
    ))
}

#[cfg(test)]
fn verify_run_receipt(request: &Request) -> Result<Vec<u8>, Failure> {
    let build_receipt = read_bounded(&request.receipt, "build receipt", 64 * 1024)?;
    let wyr_build_receipt = read_bounded(
        &request.wyr_build_receipt,
        "Wyr source-build receipt",
        64 * 1024,
    )?;
    let esp = read(&request.esp, "ESP")?;
    let bootfs = read(&request.bootfs, "bootfs")?;
    verify_run_receipt_against(request, &esp, &bootfs, &build_receipt, &wyr_build_receipt)
}

fn verify_run_receipt_against(
    request: &Request,
    esp: &[u8],
    bootfs: &[u8],
    build_receipt: &[u8],
    wyr_build_receipt: &[u8],
) -> Result<Vec<u8>, Failure> {
    let receipt_bytes = read_bounded(&request.run_receipt, "run receipt", 64 * 1024)?;
    let receipt_text = core::str::from_utf8(&receipt_bytes)
        .map_err(|_| Failure::task("DW1-B run receipt is not UTF-8"))?;
    let values = parse_scalars(receipt_text)?;
    exact_keys(&values, RUN_RECEIPT_KEYS, "DW1-B run receipt")?;
    let serial = read_bounded(&request.serial_log, "serial log", 16 * 1024 * 1024)?;
    for (key, expected) in [
        ("kind", RUN_RECEIPT_KIND.to_owned()),
        ("schema_version", "2".to_owned()),
        ("selector", SELECTOR.to_owned()),
        ("test_id", TEST_ID.to_string()),
        ("request_sha256", request.request_sha256.clone()),
        ("build_receipt_sha256", sha256::bytes_digest(build_receipt)),
        (
            "wyr_build_receipt_sha256",
            sha256::bytes_digest(wyr_build_receipt),
        ),
        ("esp_sha256", sha256::bytes_digest(esp)),
        ("bootfs_sha256", sha256::bytes_digest(bootfs)),
        ("serial_log_sha256", sha256::bytes_digest(&serial)),
        ("ovmf_code_sha256", request.ovmf_code_sha256.clone()),
        ("ovmf_vars_sha256", request.ovmf_vars_sha256.clone()),
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

fn read_run_serial(path: &Path) -> Result<Vec<u8>, Failure> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| Failure::task(format!("could not inspect DW1-B serial log: {error}")))?;
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.nlink() != 1
        || metadata.len() > 16 * 1024 * 1024
    {
        return Err(Failure::task(
            "DW1-B serial log is not a bounded single-link regular file",
        ));
    }
    read(path, "serial log")
}

fn snapshot_exact(
    source: &Path,
    destination: &Path,
    expected_sha256: Option<&str>,
    label: &str,
) -> Result<(), Failure> {
    let bytes = read_bounded(source, label, crate::g3_image::IMAGE_BYTES)?;
    if expected_sha256.is_some_and(|expected| sha256::bytes_digest(&bytes) != expected) {
        return Err(Failure::task(format!(
            "DW1-B {label} changed before run snapshot"
        )));
    }
    write_new_file(destination, &bytes)
}

fn write_new_file(path: &Path, bytes: &[u8]) -> Result<(), Failure> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| Failure::task(format!("could not create DW1-B run product: {error}")))?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|error| Failure::task(format!("could not write DW1-B run product: {error}")))
}

const LOADER_COMMAND: &str = "xtask-central-deterministic-uefi-release-pair";
const BOOTSTRAP_FEATURES: &str = "native-bootstrap,wyr0-init0-integration";
const BOOTSTRAP_COMMAND: &str = "cargo build --offline --locked --release --target x86_64-unknown-wyrmroot --package wyrmroot-bootstrap --bin wyrmroot-bootstrap --features native-bootstrap,wyr0-init0-integration";
const SELECTOR26_INIT_PATH: &[u8] = b"system/init0";
const INIT_COMMAND: &str = "cargo build --offline --locked --release --target x86_64-unknown-wyrmroot --package wyrmroot-init0 --bin wyrmroot-init0 --features native-init0,dw1b-preemption-integration";
const HELLO_COMMAND: &str = "cargo build --offline --locked --release --target x86_64-unknown-wyrmroot --package wyrmroot-hello --bin wyrmroot-hello --features native-hello";
const HOG_COMMAND: &str = "cargo build --offline --locked --release --target x86_64-unknown-wyrmroot --package wyrmroot-dw1b-preemption --bin wyrmroot-dw1b-cpu-hog --features native-payloads";
const PROGRESS_COMMAND: &str = "cargo build --offline --locked --release --target x86_64-unknown-wyrmroot --package wyrmroot-dw1b-preemption --bin wyrmroot-dw1b-progress --features native-payloads";

struct WyrArtifactSet {
    loader: Vec<u8>,
    bootstrap: Vec<u8>,
    init: Vec<u8>,
    hello: Vec<u8>,
    hog: Vec<u8>,
    progress: Vec<u8>,
    debug_loader: Vec<u8>,
    debug_symbols: Vec<u8>,
    effective_uefi_config: String,
    uefi_inspection_report: String,
    receipt: String,
}

impl WyrArtifactSet {
    fn primary(&self) -> [&[u8]; 6] {
        [
            &self.loader,
            &self.bootstrap,
            &self.init,
            &self.hello,
            &self.hog,
            &self.progress,
        ]
    }
}

pub fn freeze(output: &Path) -> Result<String, Failure> {
    let revision = verify_clean_source()?;
    preflight_source_build_environment()?;
    if fs::symlink_metadata(output).is_ok() {
        return Err(Failure::task(
            "DW1-B freeze refuses a pre-existing output path",
        ));
    }
    let parent = output
        .parent()
        .ok_or_else(|| Failure::task("DW1-B freeze output has no parent"))?;
    let parent = fs::canonicalize(parent)
        .map_err(|error| Failure::task(format!("could not resolve freeze parent: {error}")))?;
    let name = output
        .file_name()
        .ok_or_else(|| Failure::task("DW1-B freeze output has no final component"))?;
    let output = parent.join(name);
    fs::create_dir(&output)
        .map_err(|error| Failure::task(format!("could not create freeze output: {error}")))?;
    let set = build_wyr_artifact_set(&output.join("build"), &revision)?;
    let artifacts = output.join("artifacts");
    fs::create_dir(&artifacts)
        .map_err(|error| Failure::task(format!("could not create freeze artifacts: {error}")))?;
    for (name, bytes) in [
        ("loader.efi", set.loader.as_slice()),
        ("bootstrap.elf", set.bootstrap.as_slice()),
        ("wyrmroot-init0", set.init.as_slice()),
        ("wyrmroot-hello", set.hello.as_slice()),
        ("wyrmroot-dw1b-cpu-hog", set.hog.as_slice()),
        ("wyrmroot-dw1b-progress", set.progress.as_slice()),
        ("loader-debug.efi", set.debug_loader.as_slice()),
        ("loader.pdb", set.debug_symbols.as_slice()),
    ] {
        write_new_file(&artifacts.join(name), bytes)?;
    }
    write_new_file(
        &output.join("uefi-effective-config.txt"),
        set.effective_uefi_config.as_bytes(),
    )?;
    write_new_file(
        &output.join("uefi-inspection.json"),
        set.uefi_inspection_report.as_bytes(),
    )?;
    write_new_file(
        &output.join("wyr-source-build.toml"),
        set.receipt.as_bytes(),
    )?;
    let hashes = render_freeze_hashes(set.primary());
    write_new_file(&output.join("wyr-source-hashes.toml"), hashes.as_bytes())?;
    verify_clean_source_revision(&revision)?;
    Ok(format!(
        "DW1_B_FREEZE_PASS revision={revision} loader_sha256={} bootfs_inputs_sha256={}:{}:{}:{}\n",
        sha256::bytes_digest(&set.loader),
        sha256::bytes_digest(&set.init),
        sha256::bytes_digest(&set.hello),
        sha256::bytes_digest(&set.hog),
        sha256::bytes_digest(&set.progress),
    ))
}

fn preflight_source_build_environment() -> Result<(), Failure> {
    let repository = crate::tasks::repository_root()?;
    let manifest = crate::metadata::BuildManifest::load(&repository)?;
    let _cargo_home = crate::tasks::project_cargo_home(&repository, &manifest)?;
    Ok(())
}

fn render_freeze_hashes(artifacts: [&[u8]; 6]) -> String {
    format!(
        "schema_version = 1\nloader_sha256 = \"{}\"\nbootstrap_sha256 = \"{}\"\ninit_sha256 = \"{}\"\nhello_sha256 = \"{}\"\ncpu_hog_sha256 = \"{}\"\nprogress_sha256 = \"{}\"\n",
        sha256::bytes_digest(artifacts[0]),
        sha256::bytes_digest(artifacts[1]),
        sha256::bytes_digest(artifacts[2]),
        sha256::bytes_digest(artifacts[3]),
        sha256::bytes_digest(artifacts[4]),
        sha256::bytes_digest(artifacts[5]),
    )
}

fn canonical_build_wyr_artifacts(request: &Request) -> Result<(), Failure> {
    for variable in [
        "RUSTC",
        "RUSTFLAGS",
        "CARGO_ENCODED_RUSTFLAGS",
        "RUSTC_WRAPPER",
        "RUSTC_WORKSPACE_WRAPPER",
        "CARGO_BUILD_TARGET",
        "CARGO_TARGET_DIR",
        "WYRMROOT_DEEP_LAYOUT_POLICY_RS",
    ] {
        if env::var_os(variable).is_some() {
            return Err(Failure::task(format!(
                "DW1-B canonical source build refuses ambient {variable}"
            )));
        }
    }
    let set = build_wyr_artifact_set(
        &request.run_directory.join("canonical-source-rebuild"),
        &request.wyrmroot_revision,
    )?;
    let frozen = [
        read_expected(&request.loader, "loader", &request.loader_sha256)?,
        read_expected(&request.bootstrap, "bootstrap", &request.bootstrap_sha256)?,
        read_expected(&request.init, "init", &request.init_sha256)?,
        read_expected(&request.hello, "hello", &request.hello_sha256)?,
        read_expected(&request.cpu_hog, "cpu hog", &request.cpu_hog_sha256)?,
        read_expected(&request.progress, "progress", &request.progress_sha256)?,
    ];
    for (rebuilt, frozen) in set.primary().into_iter().zip(&frozen) {
        if rebuilt != frozen.as_slice() {
            return Err(Failure::task(
                "DW1-B canonical rebuild does not reproduce the frozen artifact set",
            ));
        }
    }
    let frozen_receipt = read_bounded(
        &request.wyr_build_receipt,
        "Wyr source-build receipt",
        64 * 1024,
    )?;
    require_matching_wyr_receipt(&frozen_receipt, set.receipt.as_bytes())?;
    Ok(())
}

fn require_matching_wyr_receipt(frozen: &[u8], rebuilt: &[u8]) -> Result<(), Failure> {
    if frozen != rebuilt {
        return Err(Failure::task(
            "DW1-B canonical rebuild receipt does not match the frozen source build",
        ));
    }
    Ok(())
}

fn build_wyr_artifact_set(
    build_root: &Path,
    source_revision: &str,
) -> Result<WyrArtifactSet, Failure> {
    fs::create_dir(build_root).map_err(|error| {
        Failure::task(format!("could not create fresh DW1-B build root: {error}"))
    })?;
    let repository = crate::tasks::repository_root()?;
    let manifest = BuildManifest::load(&repository)?;
    if manifest.deepwyrm_revision()? != GENERATED_ABI_REVISION
        || manifest.rust_revision()? != ACCEPTED_RUST_REVISION
        || manifest.rust_toolchain_name()? != ACCEPTED_TOOLCHAIN_NAME
    {
        return Err(Failure::task(
            "DW1-B source build metadata does not name the accepted ABI and Rust toolchain",
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
    let loader = read_cargo_build_output(&uefi.loader, "loader", 64 * 1024 * 1024)?;
    let debug_loader = read_cargo_build_output(
        &uefi.debug_loader,
        "retained debug loader",
        64 * 1024 * 1024,
    )?;
    let debug_symbols =
        read_cargo_build_output(&uefi.debug_symbols, "loader PDB", 512 * 1024 * 1024)?;
    let specs = [
        BuildSpec::new(
            "bootstrap",
            NATIVE_TARGET,
            "wyrmroot-bootstrap",
            "wyrmroot-bootstrap",
            BOOTSTRAP_FEATURES,
            "wyrmroot-bootstrap",
        ),
        BuildSpec::new(
            "init",
            NATIVE_TARGET,
            "wyrmroot-init0",
            "wyrmroot-init0",
            "native-init0,dw1b-preemption-integration",
            "wyrmroot-init0",
        ),
        BuildSpec::new(
            "hello",
            NATIVE_TARGET,
            "wyrmroot-hello",
            "wyrmroot-hello",
            "native-hello",
            "wyrmroot-hello",
        ),
        BuildSpec::new(
            "hog",
            NATIVE_TARGET,
            "wyrmroot-dw1b-preemption",
            "wyrmroot-dw1b-cpu-hog",
            "native-payloads",
            "wyrmroot-dw1b-cpu-hog",
        ),
        BuildSpec::new(
            "progress",
            NATIVE_TARGET,
            "wyrmroot-dw1b-preemption",
            "wyrmroot-dw1b-progress",
            "native-payloads",
            "wyrmroot-dw1b-progress",
        ),
    ];
    let mut artifacts = Vec::with_capacity(specs.len());
    for spec in specs {
        toolchain.accepted().verify_unchanged()?;
        layout.verify_unchanged()?;
        let target_dir = build_root.join(spec.label);
        fs::create_dir(&target_dir).map_err(io_failure)?;
        let encoded_rustflags = native_remap_flags(&repository, &cargo_home, &target_dir)?;
        let status = Command::new(&toolchain.accepted().cargo)
            .args(["build", "--offline", "--locked", "--release", "--target"])
            .arg(spec.target)
            .args([
                "--package",
                spec.package,
                "--bin",
                spec.binary,
                "--features",
                spec.features,
            ])
            .arg("--target-dir")
            .arg(&target_dir)
            .env("RUSTC", &toolchain.accepted().rustc)
            .env("CARGO_HOME", &cargo_home)
            .env("CARGO_ENCODED_RUSTFLAGS", encoded_rustflags)
            .env("CARGO_INCREMENTAL", "0")
            .env("SOURCE_DATE_EPOCH", "0")
            .env_remove("LD_AUDIT")
            .env_remove("LD_LIBRARY_PATH")
            .env_remove("LD_PRELOAD")
            .current_dir(&repository)
            .stdin(Stdio::null())
            .status()
            .map_err(|error| {
                Failure::task(format!("could not run DW1-B {} build: {error}", spec.label))
            })?;
        if !status.success() {
            return Err(Failure::task(format!(
                "DW1-B canonical {} release build failed",
                spec.label
            )));
        }
        let source = target_dir
            .join(spec.target)
            .join("release")
            .join(spec.artifact);
        let bytes = read_cargo_build_output(&source, spec.label, 64 * 1024 * 1024)?;
        artifacts.push(bytes);
    }
    let [bootstrap, init, hello, hog, progress]: [Vec<u8>; 5] = artifacts
        .try_into()
        .map_err(|_| Failure::task("DW1-B build produced the wrong artifact count"))?;
    verify_clean_source_revision(source_revision)?;
    toolchain.accepted().verify_unchanged()?;
    layout.verify_unchanged()?;
    let receipt = render_wyr_build_receipt(
        source_revision,
        toolchain.accepted(),
        &layout,
        &uefi,
        [&loader, &bootstrap, &init, &hello, &hog, &progress],
        &toolchain.validation_report_sha256(),
    )?;
    Ok(WyrArtifactSet {
        loader,
        bootstrap,
        init,
        hello,
        hog,
        progress,
        debug_loader,
        debug_symbols,
        effective_uefi_config: uefi.effective_config,
        uefi_inspection_report: uefi.inspection_report,
        receipt,
    })
}

struct BuildSpec<'a> {
    label: &'a str,
    target: &'a str,
    package: &'a str,
    binary: &'a str,
    features: &'a str,
    artifact: &'a str,
}

impl<'a> BuildSpec<'a> {
    const fn new(
        label: &'a str,
        target: &'a str,
        package: &'a str,
        binary: &'a str,
        features: &'a str,
        artifact: &'a str,
    ) -> Self {
        Self {
            label,
            target,
            package,
            binary,
            features,
            artifact,
        }
    }
}

fn render_wyr_build_receipt(
    source_revision: &str,
    toolchain: &crate::toolchain_artifact::AcceptedToolchain,
    layout: &crate::deep_layout::DeepLayoutBuild,
    uefi: &crate::tasks::DeterministicUefiArtifacts,
    artifacts: [&[u8]; 6],
    toolchain_validation_report_sha256: &str,
) -> Result<String, Failure> {
    let repository = crate::tasks::repository_root()?;
    let rustc_sha256 = sha256::file_digest(&toolchain.rustc)
        .map_err(|error| Failure::task(format!("could not hash accepted rustc: {error}")))?;
    let cargo_lock_sha256 = sha256::file_digest(&repository.join("Cargo.lock"))
        .map_err(|error| Failure::task(format!("could not hash Cargo.lock: {error}")))?;
    let uefi_inspector_sha256 =
        sha256::file_digest(&repository.join("toolchain/inspect-uefi-artifact.sh"))
            .map_err(|error| Failure::task(format!("could not hash UEFI inspector: {error}")))?;
    Ok(format!(
        "kind = \"{WYR_BUILD_KIND}\"\nschema_version = 2\nwyrmroot_revision = \"{}\"\nrust_revision = \"{ACCEPTED_RUST_REVISION}\"\nrustc_sha256 = \"{}\"\ncargo_sha256 = \"{}\"\nrust_lld_sha256 = \"{}\"\ntoolchain_manifest_sha256 = \"{}\"\ntoolchain_tree_sha256 = \"{}\"\ncargo_lock_sha256 = \"{}\"\nprofile = \"release-separate-invocations\"\ndeep_layout_sha256 = \"{}\"\ngenerated_layout_policy_sha256 = \"{}\"\nuefi_effective_config_sha256 = \"{}\"\nuefi_inspector_sha256 = \"{}\"\nuefi_inspection_report_sha256 = \"{}\"\ntoolchain_validation_report_sha256 = \"{}\"\nloader_command = \"{LOADER_COMMAND}\"\nbootstrap_command = \"{BOOTSTRAP_COMMAND}\"\ninit_command = \"{INIT_COMMAND}\"\nhello_command = \"{HELLO_COMMAND}\"\nhog_command = \"{HOG_COMMAND}\"\nprogress_command = \"{PROGRESS_COMMAND}\"\nloader_sha256 = \"{}\"\nbootstrap_sha256 = \"{}\"\ninit_sha256 = \"{}\"\nhello_sha256 = \"{}\"\ncpu_hog_sha256 = \"{}\"\nprogress_sha256 = \"{}\"\n",
        source_revision,
        rustc_sha256,
        toolchain.cargo_sha256,
        toolchain.rust_lld_sha256,
        toolchain.manifest_sha256,
        toolchain.toolchain_tree_sha256,
        cargo_lock_sha256,
        layout.layout_sha256,
        layout.policy_sha256,
        uefi.effective_config_sha256,
        uefi_inspector_sha256,
        uefi.inspection_report_sha256,
        toolchain_validation_report_sha256,
        sha256::bytes_digest(artifacts[0]),
        sha256::bytes_digest(artifacts[1]),
        sha256::bytes_digest(artifacts[2]),
        sha256::bytes_digest(artifacts[3]),
        sha256::bytes_digest(artifacts[4]),
        sha256::bytes_digest(artifacts[5]),
    ))
}

fn verify_wyr_build_receipt(
    request: &Request,
    receipt: &[u8],
    artifacts: [&[u8]; 6],
) -> Result<(), Failure> {
    let text = core::str::from_utf8(receipt)
        .map_err(|_| Failure::task("DW1-B Wyr source-build receipt is not UTF-8"))?;
    let values = parse_scalars(text)?;
    exact_keys(
        &values,
        WYR_BUILD_RECEIPT_KEYS,
        "DW1-B Wyr source-build receipt",
    )?;
    require_sha256(required(&values, "cargo_lock_sha256")?, "cargo_lock_sha256")?;
    let expected = [
        ("kind", WYR_BUILD_KIND.to_owned()),
        ("schema_version", "2".to_owned()),
        ("wyrmroot_revision", request.wyrmroot_revision.clone()),
        ("rust_revision", ACCEPTED_RUST_REVISION.to_owned()),
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
        ("profile", "release-separate-invocations".to_owned()),
        ("loader_command", LOADER_COMMAND.to_owned()),
        ("bootstrap_command", BOOTSTRAP_COMMAND.to_owned()),
        ("init_command", INIT_COMMAND.to_owned()),
        ("hello_command", HELLO_COMMAND.to_owned()),
        ("hog_command", HOG_COMMAND.to_owned()),
        ("progress_command", PROGRESS_COMMAND.to_owned()),
        ("loader_sha256", sha256::bytes_digest(artifacts[0])),
        ("bootstrap_sha256", sha256::bytes_digest(artifacts[1])),
        ("init_sha256", sha256::bytes_digest(artifacts[2])),
        ("hello_sha256", sha256::bytes_digest(artifacts[3])),
        ("cpu_hog_sha256", sha256::bytes_digest(artifacts[4])),
        ("progress_sha256", sha256::bytes_digest(artifacts[5])),
    ];
    for (key, expected) in expected {
        if required(&values, key)? != expected {
            return Err(Failure::task(format!(
                "DW1-B Wyr source-build receipt field {key} does not match"
            )));
        }
    }
    for key in [
        "deep_layout_sha256",
        "generated_layout_policy_sha256",
        "uefi_effective_config_sha256",
        "uefi_inspector_sha256",
        "uefi_inspection_report_sha256",
        "toolchain_validation_report_sha256",
    ] {
        require_sha256(required(&values, key)?, key)?;
    }
    Ok(())
}

fn verify_current_cargo_lock(receipt: &[u8]) -> Result<(), Failure> {
    let text = core::str::from_utf8(receipt)
        .map_err(|_| Failure::task("DW1-B Wyr source-build receipt is not UTF-8"))?;
    let values = parse_scalars(text)?;
    let recorded = required(&values, "cargo_lock_sha256")?;
    require_sha256(recorded, "cargo_lock_sha256")?;
    let repository = crate::tasks::repository_root()?;
    let current = sha256::file_digest(&repository.join("Cargo.lock"))
        .map_err(|error| Failure::task(format!("could not hash Cargo.lock: {error}")))?;
    if recorded != current {
        return Err(Failure::task(
            "DW1-B Wyr source-build receipt Cargo.lock does not match current source",
        ));
    }
    Ok(())
}

fn build_archive(
    init: &[u8],
    hello: &[u8],
    hog: &[u8],
    progress: &[u8],
) -> Result<Vec<u8>, Failure> {
    let mut builder = Builder::new();
    for (path, bytes) in [
        (SELECTOR26_INIT_PATH, init),
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
        (SELECTOR26_INIT_PATH, artifacts[0]),
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
    verify_efi_loader(inputs.loader)?;
    verify_loader_elf("bootstrap", inputs.bootstrap)?;
    let init = verify_loader_elf("init", inputs.init)?;
    verify_loader_elf("hello", inputs.hello)?;
    let hog = verify_loader_elf("cpu hog", inputs.hog)?;
    let progress = verify_loader_elf("progress", inputs.progress)?;
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
    if !contains_exact_hog_steady_loop(inputs.hog, &hog) {
        return Err(Failure::task(
            "DW1-B cpu hog lacks the exact audited pause/jump steady loop in executable bytes",
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
    executable_segments: Vec<(u64, usize, usize)>,
}

fn verify_loader_elf(label: &str, bytes: &[u8]) -> Result<ElfLayout, Failure> {
    const EMPTY: LoadSegment = LoadSegment {
        header_index: 0,
        file_offset: 0,
        file_size: 0,
        memory_size: 0,
        virtual_address: 0,
        mapping_start: 0,
        mapping_size: 0,
        leading_bytes: 0,
        protection: SegmentProtection::Read,
    };
    let mut segments = [EMPTY; MAX_LOAD_SEGMENTS];
    let plan = elf::plan(bytes, &mut segments).map_err(|error| {
        Failure::task(format!(
            "DW1-B {label} violates the loader ELF contract: {error:?}"
        ))
    })?;
    let mut load_file_ranges = Vec::with_capacity(plan.segments.len());
    let mut executable_segments = Vec::new();
    for segment in plan.segments {
        let start = usize::try_from(segment.file_offset)
            .map_err(|_| Failure::task("DW1-B loader ELF file offset overflow"))?;
        let end = usize::try_from(segment.file_offset + segment.file_size)
            .map_err(|_| Failure::task("DW1-B loader ELF file range overflow"))?;
        load_file_ranges.push((start, end));
        if segment.protection == SegmentProtection::ReadExecute {
            executable_segments.push((segment.virtual_address, start, end));
        }
    }
    Ok(ElfLayout {
        load_file_ranges,
        executable_segments,
    })
}

fn contains_loaded_marker(bytes: &[u8], layout: &ElfLayout, marker: &[u8]) -> bool {
    layout.load_file_ranges.iter().any(|(start, end)| {
        bytes[*start..*end]
            .windows(marker.len())
            .any(|window| window == marker)
    })
}

fn contains_exact_hog_steady_loop(bytes: &[u8], layout: &ElfLayout) -> bool {
    const STEADY_LOOP: &[u8] = &[0xf3, 0x90, 0xeb, 0xfc];
    let Ok(symbols) = elf_symbols(bytes) else {
        return false;
    };
    let mut hog_symbols = symbols
        .iter()
        .filter(|symbol| symbol.name.ends_with("11run_cpu_hog") && symbol.size != 0);
    let Some(hog) = hog_symbols.next() else {
        return false;
    };
    if hog_symbols.next().is_some() {
        return false;
    }
    let Some(close) = symbols
        .iter()
        .find(|symbol| symbol.name.ends_with("12close_handle") && symbol.size != 0)
    else {
        return false;
    };
    let Some((segment_virtual, segment_start, _segment_end)) = layout
        .executable_segments
        .iter()
        .find(|(virtual_address, start, end)| {
            hog.value >= *virtual_address
                && hog.value.checked_add(hog.size).is_some_and(|symbol_end| {
                    symbol_end <= *virtual_address + u64::try_from(end - start).unwrap_or(0)
                })
        })
    else {
        return false;
    };
    let symbol_start =
        *segment_start + usize::try_from(hog.value - *segment_virtual).unwrap_or(usize::MAX);
    let symbol_end = symbol_start.saturating_add(usize::try_from(hog.size).unwrap_or(usize::MAX));
    let Some(function) = bytes.get(symbol_start..symbol_end) else {
        return false;
    };
    let loops = function
        .windows(STEADY_LOOP.len())
        .enumerate()
        .filter(|(_, window)| *window == STEADY_LOOP)
        .map(|(index, _)| index)
        .collect::<Vec<_>>();
    if loops.len() != 1 || loops[0] < 32 {
        return false;
    }
    let loop_at = loops[0];
    if function.get(loop_at - 8..loop_at) != Some(&[0x0f, 0x1f, 0x84, 0, 0, 0, 0, 0])
        || function
            .get(loop_at - 14..loop_at - 8)
            .is_none_or(|bytes| bytes[..2] != [0x0f, 0x85])
        || function.get(loop_at - 17..loop_at - 14) != Some(&[0x80, 0xf9, 0x02])
    {
        return false;
    }
    let branch_at = loop_at - 14;
    let branch_displacement =
        i32::from_le_bytes(function[branch_at + 2..branch_at + 6].try_into().unwrap());
    let branch_target = (branch_at + 6).wrapping_add_signed(branch_displacement as isize);
    if branch_target >= branch_at || branch_target >= function.len() {
        return false;
    }
    let call = (loop_at.saturating_sub(48)..loop_at - 17)
        .rev()
        .find(|index| function[*index] == 0xe8);
    let Some(call) = call else { return false };
    let Some(displacement) = function.get(call + 1..call + 5) else {
        return false;
    };
    let displacement = i32::from_le_bytes(displacement.try_into().unwrap());
    let call_address = hog.value + u64::try_from(call).unwrap_or(u64::MAX) + 5;
    call_address.wrapping_add_signed(i64::from(displacement)) == close.value
}

struct ElfSymbol {
    name: String,
    value: u64,
    size: u64,
}

fn elf_symbols(bytes: &[u8]) -> Result<Vec<ElfSymbol>, Failure> {
    let section_offset = usize::try_from(read_u64(bytes, 40)?)
        .map_err(|_| Failure::task("DW1-B ELF section offset overflow"))?;
    let section_size = usize::from(read_u16(bytes, 58)?);
    let section_count = usize::from(read_u16(bytes, 60)?);
    if section_size != 64 || !(1..=128).contains(&section_count) {
        return Err(Failure::task(
            "DW1-B ELF section table is absent or invalid",
        ));
    }
    let table = bytes
        .get(
            section_offset
                ..section_offset
                    .checked_add(section_size * section_count)
                    .ok_or_else(|| Failure::task("DW1-B ELF section table overflow"))?,
        )
        .ok_or_else(|| Failure::task("DW1-B ELF section table is truncated"))?;
    let sections = table.chunks_exact(64).collect::<Vec<_>>();
    let symtab = sections
        .iter()
        .filter(|section| u32::from_le_bytes(section[4..8].try_into().unwrap()) == 2)
        .copied()
        .collect::<Vec<_>>();
    if symtab.len() != 1 {
        return Err(Failure::task("DW1-B ELF requires one static symbol table"));
    }
    let symtab = symtab[0];
    let string_index = usize::try_from(u32::from_le_bytes(symtab[40..44].try_into().unwrap()))
        .map_err(|_| Failure::task("DW1-B ELF string-table index overflow"))?;
    let strings_section = sections
        .get(string_index)
        .ok_or_else(|| Failure::task("DW1-B ELF symbol strings are absent"))?;
    let strings = section_bytes(bytes, strings_section)?;
    if u64::from_le_bytes(symtab[56..64].try_into().unwrap()) != 24 {
        return Err(Failure::task("DW1-B ELF symbol entry size is invalid"));
    }
    let entries = section_bytes(bytes, symtab)?;
    if entries.len() % 24 != 0 || entries.len() / 24 > 4096 {
        return Err(Failure::task("DW1-B ELF symbol table is invalid"));
    }
    let mut symbols = Vec::new();
    for entry in entries.chunks_exact(24) {
        if entry[4] & 0x0f != 2 || u16::from_le_bytes(entry[6..8].try_into().unwrap()) == 0 {
            continue;
        }
        let name_offset = usize::try_from(u32::from_le_bytes(entry[..4].try_into().unwrap()))
            .map_err(|_| Failure::task("DW1-B ELF symbol name overflow"))?;
        let tail = strings
            .get(name_offset..)
            .ok_or_else(|| Failure::task("DW1-B ELF symbol name is out of range"))?;
        let end = tail
            .iter()
            .position(|byte| *byte == 0)
            .ok_or_else(|| Failure::task("DW1-B ELF symbol name is unterminated"))?;
        let name = core::str::from_utf8(&tail[..end])
            .map_err(|_| Failure::task("DW1-B ELF symbol name is not UTF-8"))?;
        symbols.push(ElfSymbol {
            name: name.to_owned(),
            value: u64::from_le_bytes(entry[8..16].try_into().unwrap()),
            size: u64::from_le_bytes(entry[16..24].try_into().unwrap()),
        });
    }
    Ok(symbols)
}

fn section_bytes<'a>(bytes: &'a [u8], section: &[u8]) -> Result<&'a [u8], Failure> {
    let offset = usize::try_from(u64::from_le_bytes(section[24..32].try_into().unwrap()))
        .map_err(|_| Failure::task("DW1-B ELF section offset overflow"))?;
    let size = usize::try_from(u64::from_le_bytes(section[32..40].try_into().unwrap()))
        .map_err(|_| Failure::task("DW1-B ELF section size overflow"))?;
    bytes
        .get(
            offset
                ..offset
                    .checked_add(size)
                    .ok_or_else(|| Failure::task("DW1-B ELF section range overflow"))?,
        )
        .ok_or_else(|| Failure::task("DW1-B ELF section is truncated"))
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, Failure> {
    bytes
        .get(offset..offset + 2)
        .map(|value| u16::from_le_bytes(value.try_into().unwrap()))
        .ok_or_else(|| Failure::task("DW1-B ELF header is truncated"))
}

fn read_u64(bytes: &[u8], offset: usize) -> Result<u64, Failure> {
    bytes
        .get(offset..offset + 8)
        .map(|value| u64::from_le_bytes(value.try_into().unwrap()))
        .ok_or_else(|| Failure::task("DW1-B ELF header is truncated"))
}

fn verify_efi_loader(bytes: &[u8]) -> Result<(), Failure> {
    if bytes.len() < 0x100 || &bytes[..2] != b"MZ" {
        return Err(Failure::task("DW1-B loader is not a PE32+ EFI image"));
    }
    let pe_offset = usize::try_from(u32::from_le_bytes(bytes[0x3c..0x40].try_into().unwrap()))
        .map_err(|_| Failure::task("DW1-B loader PE header offset overflow"))?;
    let coff = bytes
        .get(pe_offset..pe_offset + 24)
        .ok_or_else(|| Failure::task("DW1-B loader PE header is truncated"))?;
    if &coff[..4] != b"PE\0\0" || u16::from_le_bytes(coff[4..6].try_into().unwrap()) != 0x8664 {
        return Err(Failure::task("DW1-B loader is not x86_64 PE"));
    }
    let section_count = usize::from(u16::from_le_bytes(coff[6..8].try_into().unwrap()));
    let optional_size = usize::from(u16::from_le_bytes(coff[20..22].try_into().unwrap()));
    let characteristics = u16::from_le_bytes(coff[22..24].try_into().unwrap());
    if !(1..=96).contains(&section_count) || optional_size < 112 || characteristics & 2 == 0 {
        return Err(Failure::task("DW1-B loader COFF contract is invalid"));
    }
    let optional = bytes
        .get(pe_offset + 24..pe_offset + 24 + optional_size)
        .ok_or_else(|| Failure::task("DW1-B loader optional header is truncated"))?;
    if optional.len() < 168
        || u16::from_le_bytes(optional[..2].try_into().unwrap()) != 0x20b
        || u32::from_le_bytes(optional[16..20].try_into().unwrap()) == 0
        || u16::from_le_bytes(optional[68..70].try_into().unwrap()) != 10
        || u32::from_le_bytes(optional[108..112].try_into().unwrap()) < 7
    {
        return Err(Failure::task(
            "DW1-B loader is not an executable EFI application",
        ));
    }
    let table = pe_offset + 24 + optional_size;
    let table_end = table
        .checked_add(section_count * 40)
        .ok_or_else(|| Failure::task("DW1-B loader section table overflow"))?;
    let sections = bytes
        .get(table..table_end)
        .ok_or_else(|| Failure::task("DW1-B loader section table is truncated"))?;
    for section in sections.chunks_exact(40) {
        let raw_size = usize::try_from(u32::from_le_bytes(section[16..20].try_into().unwrap()))
            .map_err(|_| Failure::task("DW1-B loader section size overflow"))?;
        let raw_offset = usize::try_from(u32::from_le_bytes(section[20..24].try_into().unwrap()))
            .map_err(|_| Failure::task("DW1-B loader section offset overflow"))?;
        let flags = u32::from_le_bytes(section[36..40].try_into().unwrap());
        if raw_offset
            .checked_add(raw_size)
            .is_none_or(|end| end > bytes.len())
            || flags & 0x2000_0000 != 0 && flags & 0x8000_0000 != 0
        {
            return Err(Failure::task("DW1-B loader section contract is invalid"));
        }
    }
    let import_rva = u32::from_le_bytes(optional[120..124].try_into().unwrap());
    let import_size = u32::from_le_bytes(optional[124..128].try_into().unwrap());
    if import_rva != 0 || import_size != 0 {
        return Err(Failure::task("DW1-B production loader contains PE imports"));
    }
    let debug_rva = u32::from_le_bytes(optional[160..164].try_into().unwrap());
    let debug_size = usize::try_from(u32::from_le_bytes(optional[164..168].try_into().unwrap()))
        .map_err(|_| Failure::task("DW1-B loader debug directory size overflows"))?;
    if debug_rva == 0 || debug_size == 0 || debug_size % 28 != 0 {
        return Err(Failure::task(
            "DW1-B production loader lacks a canonical PE debug directory",
        ));
    }
    let debug_offset = sections.chunks_exact(40).find_map(|section| {
        let virtual_size = u32::from_le_bytes(section[8..12].try_into().unwrap());
        let virtual_address = u32::from_le_bytes(section[12..16].try_into().unwrap());
        let raw_size = u32::from_le_bytes(section[16..20].try_into().unwrap());
        let raw_offset = u32::from_le_bytes(section[20..24].try_into().unwrap());
        let span = virtual_size.max(raw_size);
        (debug_rva >= virtual_address
            && debug_rva.checked_add(debug_size as u32)? <= virtual_address.checked_add(span)?)
        .then(|| usize::try_from(raw_offset + (debug_rva - virtual_address)).ok())
        .flatten()
    });
    let debug_offset = debug_offset
        .ok_or_else(|| Failure::task("DW1-B loader debug directory is not file-backed"))?;
    let debug_end = debug_offset
        .checked_add(debug_size)
        .ok_or_else(|| Failure::task("DW1-B loader debug directory overflows"))?;
    let debug = bytes
        .get(debug_offset..debug_end)
        .ok_or_else(|| Failure::task("DW1-B loader debug directory is truncated"))?;
    let mut repro = 0;
    for entry in debug.chunks_exact(28) {
        let kind = u32::from_le_bytes(entry[12..16].try_into().unwrap());
        if kind == 2 {
            return Err(Failure::task(
                "DW1-B production loader contains a CodeView record",
            ));
        }
        if kind == 16 {
            repro += 1;
        }
        let data_size = usize::try_from(u32::from_le_bytes(entry[16..20].try_into().unwrap()))
            .map_err(|_| Failure::task("DW1-B loader debug payload size overflows"))?;
        let data_offset = usize::try_from(u32::from_le_bytes(entry[24..28].try_into().unwrap()))
            .map_err(|_| Failure::task("DW1-B loader debug payload offset overflows"))?;
        if data_size != 0
            && data_offset
                .checked_add(data_size)
                .is_none_or(|end| end > bytes.len())
        {
            return Err(Failure::task(
                "DW1-B loader debug payload is outside the image",
            ));
        }
    }
    if repro != 1 {
        return Err(Failure::task(
            "DW1-B production loader lacks exactly one Repro record",
        ));
    }
    Ok(())
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
    platform: [&[u8]; 7],
) -> String {
    format!(
        "kind = \"{RECEIPT_KIND}\"\nschema_version = 5\nselector = \"{SELECTOR}\"\ntest_id = 26\nrequest_sha256 = \"{}\"\ndeepwyrm_revision = \"{}\"\ndeepwyrm_abi_tree = \"{DEEPWYRM_ABI_TREE}\"\nwyrmroot_revision = \"{}\"\nrust_revision = \"{}\"\nloader_sha256 = \"{}\"\nkernel_sha256 = \"{}\"\nsymbols_sha256 = \"{}\"\nbootstrap_sha256 = \"{}\"\nprovenance_sha256 = \"{}\"\nesp_sha256 = \"{}\"\nwyr_build_receipt_sha256 = \"{}\"\nbootfs_sha256 = \"{}\"\ninit_sha256 = \"{}\"\nhello_sha256 = \"{}\"\ncpu_hog_sha256 = \"{}\"\nprogress_sha256 = \"{}\"\nbootfs_bytes = {}\nbootfs_pages = {}\nkernel_bootfs_env = \"DEEPWYRM_DW1B_BOOTFS_MAX_PAGES={}\"\nevidence_nonce = \"{:016X}\"\nchallenge_digest = \"{DIGEST:016X}\"\ntimeout_seconds = {}\n",
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
        sha256::bytes_digest(platform[6]),
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
    platform: [&[u8]; 7],
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
fn require_sha256(value: &str, key: &str) -> Result<(), Failure> {
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
    Ok(())
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
        &request.wyr_build_receipt,
        &request.provenance,
        &request.ovmf_code,
        &request.ovmf_vars,
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

fn native_remap_flags(
    repository: &Path,
    cargo_home: &Path,
    target: &Path,
) -> Result<String, Failure> {
    let repository = fs::canonicalize(repository).map_err(io_failure)?;
    let cargo_home = fs::canonicalize(cargo_home).map_err(io_failure)?;
    let target = fs::canonicalize(target).map_err(io_failure)?;
    for path in [&repository, &cargo_home, &target] {
        if path.to_string_lossy().contains('\u{1f}') {
            return Err(Failure::task(
                "DW1-B build path contains Cargo's encoded-rustflags separator",
            ));
        }
    }
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

fn verify_clean_source() -> Result<String, Failure> {
    let repository = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let revision = Command::new("git")
        .args(["-C", repository.to_str().unwrap(), "rev-parse", "HEAD"])
        .output()
        .map_err(|error| Failure::task(format!("could not inspect Wyrmroot HEAD: {error}")))?;
    if !revision.status.success() {
        return Err(Failure::task("could not resolve Wyrmroot HEAD"));
    }
    let revision = core::str::from_utf8(&revision.stdout)
        .map_err(|_| Failure::task("Wyrmroot HEAD is not UTF-8"))?
        .trim()
        .to_owned();
    verify_clean_source_revision(&revision)?;
    Ok(revision)
}

fn verify_clean_source_revision(expected: &str) -> Result<(), Failure> {
    let repository = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let revision = Command::new("git")
        .args(["-C", repository.to_str().unwrap(), "rev-parse", "HEAD"])
        .output()
        .map_err(|error| Failure::task(format!("could not inspect Wyrmroot HEAD: {error}")))?;
    let actual = core::str::from_utf8(&revision.stdout)
        .map_err(|_| Failure::task("Wyrmroot HEAD is not UTF-8"))?
        .trim();
    let status = Command::new("git")
        .args([
            "-C",
            repository.to_str().unwrap(),
            "status",
            "--porcelain=v1",
            "--untracked-files=all",
        ])
        .output()
        .map_err(|error| Failure::task(format!("could not inspect Wyrmroot status: {error}")))?;
    if !revision.status.success()
        || actual != expected
        || !status.status.success()
        || !status.stdout.is_empty()
    {
        return Err(Failure::task(
            "DW1-B acceptance requires the exact clean Wyrmroot revision",
        ));
    }
    Ok(())
}

fn verify_acceptance_source(request: &Request) -> Result<(), Failure> {
    verify_clean_source_revision(&request.wyrmroot_revision)
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

fn read_cargo_build_output(path: &Path, label: &str, maximum: u64) -> Result<Vec<u8>, Failure> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|e| Failure::task(format!("could not inspect DW1-B {label}: {e}")))?;
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.len() == 0
        || metadata.len() > maximum
    {
        return Err(Failure::task(format!(
            "DW1-B {label} is not a bounded regular Cargo build output"
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
        let archive = Archive::new(&first).unwrap();
        assert_eq!(archive.lookup(b"system/init0").unwrap().data(), b"i");
        assert!(archive.lookup(b"system/init").is_err());
    }

    #[test]
    fn canonical_run_reuses_the_inspected_product_without_rebuilding() {
        let source = include_str!("dw1b.rs");
        let body = source
            .split_once("pub fn run(request_path: &Path)")
            .expect("canonical run entry")
            .1
            .split_once("pub fn evidence(request_path: &Path)")
            .expect("legacy evidence entry")
            .0;
        assert!(body.contains("execute_run(request_path"));
        assert!(!body.contains("build(request_path"));

        let execution = source
            .split_once("fn execute_run(\n")
            .expect("run execution boundary")
            .1
            .split_once("#[cfg(test)]\nfn execute_run_loaded(")
            .expect("test execution boundary")
            .0;
        assert!(execution.contains("inspect_recorded(request_path)"));
        assert!(!execution.contains("inspect(request_path)"));
        assert!(source.contains("ensure_run_directory(&request.run_directory)?"));
    }

    #[test]
    fn source_build_preflights_the_project_cargo_home_before_outputs() {
        let source = include_str!("dw1b.rs");
        let build = source
            .split_once("fn build_product(path: &Path, verify_rebuild: bool)")
            .expect("build entry")
            .1
            .split_once("pub fn measure(")
            .expect("build boundary")
            .0;
        assert!(
            build.find("preflight_source_build_environment()")
                < build.find("verify_product_inputs(")
        );
        assert!(
            build.find("verify_product_inputs(")
                < build.find("fs::create_dir_all(&request.run_directory)")
        );
        assert!(
            build.find("canonical_build_wyr_artifacts(&request)")
                < build.find("fs::write(&request.bootfs")
        );
        let image_entry = source
            .split_once("pub fn build(path: &Path)")
            .expect("image entry")
            .1
            .split_once("pub fn rebuild(path: &Path)")
            .expect("image entry boundary")
            .0;
        assert!(image_entry.contains("build_product(path, false)"));
        let rebuild_entry = source
            .split_once("pub fn rebuild(path: &Path)")
            .expect("rebuild entry")
            .1
            .split_once("fn build_product(")
            .expect("rebuild entry boundary")
            .0;
        assert!(rebuild_entry.contains("build_product(path, true)"));
        assert!(build.contains("if verify_rebuild {"));
        assert!(build.contains("verify_acceptance_source(&request)?"));
        assert!(build.contains("verify_current_cargo_lock(&wyr_build_receipt)?"));

        let freeze = source
            .split_once("pub fn freeze(output: &Path)")
            .expect("freeze entry")
            .1
            .split_once("fn preflight_source_build_environment()")
            .expect("freeze boundary")
            .0;
        assert!(
            freeze.find("preflight_source_build_environment()")
                < freeze.find("fs::create_dir(&output)")
        );

        let versions = include_str!("../../../toolchain/versions.toml");
        assert!(versions.contains(
            "accepted_artifact_root = \"artifacts/toolchains/accepted/RUST-WYR0-I-B-SYSROOTS-007\""
        ));
        assert!(versions.contains("project_cargo_home = \".tmp/cargo-home/offline-v1\""));
        assert!(!source.contains("canonical_environment_directory(\"CARGO_HOME\")"));
    }

    #[test]
    fn fresh_cargo_build_outputs_may_be_hard_linked_before_owned_copy() {
        let root = fixture();
        let source = root.join("cargo-artifact");
        let alias = root.join("cargo-artifact-alias");
        fs::write(&source, b"fresh artifact").unwrap();
        fs::hard_link(&source, &alias).unwrap();
        assert_eq!(
            read_cargo_build_output(&source, "fixture", 1024).unwrap(),
            b"fresh artifact"
        );
        assert!(read_bounded(&source, "fixture", 1024).is_err());
        fs::remove_dir_all(root).unwrap();
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
                &format!("wyrmroot_revision = \"{}\"", current_test_revision()),
                "wyrmroot_revision = \"0000000000000000000000000000000000000000\"",
            ),
            valid.replace(
                ACCEPTED_RUST_REVISION,
                "b92dc7f7464ad6ddfece4402bd7b86dbfa86166d",
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
    fn evidence_run_owns_receipt_and_rejects_caller_crafted_status() {
        let crafted_root = fixture();
        fs::create_dir_all(crafted_root.join("out")).unwrap();
        fs::create_dir_all(crafted_root.join("run")).unwrap();
        let crafted_path = crafted_root.join("request.toml");
        fs::write(&crafted_path, request_text()).unwrap();
        fs::write(crafted_root.join("out/receipt.toml"), b"build receipt").unwrap();
        fs::write(crafted_root.join("out/esp.img"), b"esp").unwrap();
        fs::write(crafted_root.join("out/bootfs.img"), b"bootfs").unwrap();
        fs::write(crafted_root.join("run/run-receipt.toml"), b"caller crafted").unwrap();
        let crafted_request = load(&crafted_path).unwrap();
        let mut executed = false;
        assert!(
            execute_run_loaded(&crafted_path, crafted_request, |_| {
                executed = true;
                unreachable!()
            })
            .is_err()
        );
        assert!(!executed);
        fs::remove_dir_all(crafted_root).unwrap();

        let root = fixture();
        fs::create_dir_all(root.join("out")).unwrap();
        fs::create_dir_all(root.join("run")).unwrap();
        let request_path = root.join("request.toml");
        fs::write(&request_path, request_text()).unwrap();
        fs::write(root.join("out/receipt.toml"), b"build receipt").unwrap();
        fs::write(root.join("out/esp.img"), b"esp").unwrap();
        fs::write(root.join("out/bootfs.img"), b"bootfs").unwrap();
        let request = load(&request_path).unwrap();
        let serial = valid_evidence_log(1);
        let expected_serial = serial.clone();
        let (_, observed) = execute_run_loaded(&request_path, request.clone(), |run| {
            fs::write(&run.serial_log, &serial).unwrap();
            Ok(RunObservation {
                qemu_exit_status: Some(33),
                timed_out: false,
            })
        })
        .unwrap();
        assert_eq!(observed, expected_serial);

        let run_receipt = fs::read_to_string(root.join("run/run-receipt.toml")).unwrap();
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
    fn mid_run_receipt_and_bootfs_mutation_fail_before_run_receipt() {
        for mutation in ["main-receipt", "wyr-receipt", "bootfs"] {
            let root = fixture();
            fs::create_dir_all(root.join("out")).unwrap();
            fs::create_dir_all(root.join("run")).unwrap();
            let request_path = root.join("request.toml");
            fs::write(&request_path, request_text()).unwrap();
            fs::write(root.join("out/receipt.toml"), b"build receipt").unwrap();
            fs::write(root.join("out/esp.img"), b"esp").unwrap();
            fs::write(root.join("out/bootfs.img"), b"bootfs").unwrap();
            let request = load(&request_path).unwrap();
            let error = execute_run_loaded(&request_path, request, |run| {
                fs::write(&run.serial_log, valid_evidence_log(1)).unwrap();
                let target = match mutation {
                    "main-receipt" => root.join("out/receipt.toml"),
                    "wyr-receipt" => root.join("out/wyr-build.toml"),
                    "bootfs" => root.join("out/bootfs.img"),
                    _ => unreachable!(),
                };
                fs::write(target, b"mutated during execution").unwrap();
                Ok(RunObservation {
                    qemu_exit_status: Some(33),
                    timed_out: false,
                })
            })
            .unwrap_err();
            assert!(error.message.contains("changed during canonical execution"));
            assert!(!root.join("run/run-receipt.toml").exists());
            fs::remove_dir_all(root).unwrap();
        }
    }

    #[test]
    fn canonical_template_names_exact_candidate_and_digest() {
        let template = include_str!("../../../toolchain/templates/dw1-b-request.toml");
        assert!(template.contains(DEEPWYRM_CANDIDATE));
        assert!(template.contains(DEEPWYRM_ABI_TREE));
        assert!(template.contains("challenge_digest = \"5E4E054B5C244ACE\""));
        assert!(template.contains("bootfs_pages = 31"));
        assert!(template.contains(ACCEPTED_RUST_REVISION));
        assert!(template.contains("REPLACE_WITH_INTEGRATED_WYRMROOT_COMMIT"));
        assert!(!template.contains("revision = \"0000000000000000000000000000000000000000\""));
    }

    #[test]
    fn selector_26_bootstrap_uses_the_init0_launch_profile() {
        assert_eq!(
            BOOTSTRAP_FEATURES,
            "native-bootstrap,wyr0-init0-integration"
        );
        assert!(BOOTSTRAP_COMMAND.ends_with("--features native-bootstrap,wyr0-init0-integration"));
        assert_eq!(SELECTOR26_INIT_PATH, b"system/init0");
    }

    #[test]
    fn elf_audit_requires_static_loaded_identity() {
        let marker = b"WYRMDW1B-HOG-V1:steady-spin-only";
        let valid = valid_hog_elf(marker);
        let layout = verify_loader_elf("fixture", &valid).unwrap();
        assert!(contains_loaded_marker(&valid, &layout, marker));
        assert!(contains_exact_hog_steady_loop(&valid, &layout));

        let mut unreachable = valid.clone();
        let loop_at = unreachable
            .windows(4)
            .position(|window| window == [0xf3, 0x90, 0xeb, 0xfc])
            .unwrap();
        unreachable[loop_at - 12..loop_at - 8].copy_from_slice(&4_i32.to_le_bytes());
        let layout = verify_loader_elf("fixture", &unreachable).unwrap();
        assert!(!contains_exact_hog_steady_loop(&unreachable, &layout));

        let mut appended = valid_elf(b"different loaded bytes");
        let layout = verify_loader_elf("fixture", &appended).unwrap();
        appended.extend_from_slice(marker);
        assert!(!contains_loaded_marker(&appended, &layout, marker));

        let mut zero_entry = valid.clone();
        zero_entry[24..32].copy_from_slice(&0_u64.to_le_bytes());
        assert!(verify_loader_elf("fixture", &zero_entry).is_err());

        let mut dynamic = valid.clone();
        dynamic[64..68].copy_from_slice(&2_u32.to_le_bytes());
        assert!(verify_loader_elf("fixture", &dynamic).is_err());

        let mut writable_executable = valid;
        writable_executable[68..72].copy_from_slice(&7_u32.to_le_bytes());
        assert!(verify_loader_elf("fixture", &writable_executable).is_err());

        let mut bad_alignment = valid_elf(marker);
        bad_alignment[112..120].copy_from_slice(&3_u64.to_le_bytes());
        assert!(verify_loader_elf("fixture", &bad_alignment).is_err());

        let loader = valid_pe();
        verify_efi_loader(&loader).unwrap();
        let mut codeview = loader.clone();
        codeview[0x20c..0x210].copy_from_slice(&2_u32.to_le_bytes());
        assert!(verify_efi_loader(&codeview).is_err());
        let mut timestamped = loader.clone();
        timestamped[0x204..0x208].copy_from_slice(&1_u32.to_le_bytes());
        timestamped[0x20c..0x210].fill(0);
        assert!(verify_efi_loader(&timestamped).is_err());
        let mut imported = loader.clone();
        imported[0x110..0x114].copy_from_slice(&0x1000_u32.to_le_bytes());
        imported[0x114..0x118].copy_from_slice(&20_u32.to_le_bytes());
        assert!(verify_efi_loader(&imported).is_err());
        let mut wrong_subsystem = loader;
        wrong_subsystem[220..222].copy_from_slice(&3_u16.to_le_bytes());
        assert!(verify_efi_loader(&wrong_subsystem).is_err());
    }

    #[test]
    fn product_validation_inspects_loader_bootstrap_and_real_hog_loop() {
        let root = fixture();
        let request_path = root.join("request.toml");
        fs::write(&request_path, request_text()).unwrap();
        let request = load(&request_path).unwrap();
        let kernel = b"kernel";
        let symbols = b"symbols";
        let provenance = format!(
            "kind = \"{PROVENANCE_KIND}\"\nschema_version = 1\nselector = \"{SELECTOR}\"\ntest_id = 26\ndeepwyrm_revision = \"{DEEPWYRM_CANDIDATE}\"\ndeepwyrm_abi_tree = \"{DEEPWYRM_ABI_TREE}\"\nrust_revision = \"{ACCEPTED_RUST_REVISION}\"\nkernel_sha256 = \"{}\"\nsymbols_sha256 = \"{}\"\nDEEPWYRM_DW1B_EVIDENCE_NONCE = \"0000000000000001\"\nDEEPWYRM_DW1B_CHALLENGE_DIGEST = \"{DIGEST:016X}\"\nDEEPWYRM_DW1B_BOOTFS_MAX_PAGES = 1\n",
            sha256::bytes_digest(kernel),
            sha256::bytes_digest(symbols),
        );
        let loader = valid_pe();
        let bootstrap = valid_elf(b"bootstrap");
        let init = valid_elf(b"WYRMINIT0-PROFILE-V1:dw1b-preemption");
        let hello = valid_elf(b"hello");
        let hog = valid_hog_elf(b"WYRMDW1B-HOG-V1:steady-spin-only");
        let progress = valid_elf(b"WYRMDW1B-PROGRESS-V1:eight-rounds");
        macro_rules! inputs {
            ($loader:expr, $bootstrap:expr, $hog:expr) => {
                ProductInputs {
                    loader: $loader,
                    kernel,
                    symbols,
                    bootstrap: $bootstrap,
                    init: &init,
                    hello: &hello,
                    hog: $hog,
                    progress: &progress,
                    provenance: provenance.as_bytes(),
                }
            };
        }
        verify_product_inputs(&request, inputs!(&loader, &bootstrap, &hog)).unwrap();

        let mut wrong_loader = loader.clone();
        wrong_loader[220..222].copy_from_slice(&3_u16.to_le_bytes());
        assert!(verify_product_inputs(&request, inputs!(&wrong_loader, &bootstrap, &hog)).is_err());
        let mut wrong_bootstrap = bootstrap.clone();
        wrong_bootstrap[64..68].copy_from_slice(&2_u32.to_le_bytes());
        assert!(verify_product_inputs(&request, inputs!(&loader, &wrong_bootstrap, &hog)).is_err());
        let mut hog_without_loop = valid_hog_elf(b"WYRMDW1B-HOG-V1:steady-spin-only");
        let loop_start = hog_without_loop
            .windows(4)
            .position(|window| window == [0xf3, 0x90, 0xeb, 0xfc])
            .unwrap();
        hog_without_loop[loop_start..loop_start + 4].fill(0x90);
        assert!(
            verify_product_inputs(&request, inputs!(&loader, &bootstrap, &hog_without_loop))
                .is_err()
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn source_build_receipt_rejects_a_structurally_valid_substitute_loader() {
        let root = fixture();
        let request_path = root.join("request.toml");
        fs::write(&request_path, request_text()).unwrap();
        let request = load(&request_path).unwrap();
        let loader = valid_pe();
        let bootstrap = valid_elf(b"bootstrap");
        let init = valid_elf(b"init");
        let hello = valid_elf(b"hello");
        let hog = valid_hog_elf(b"WYRMDW1B-HOG-V1:steady-spin-only");
        let progress = valid_elf(b"progress");
        let artifacts = [&loader[..], &bootstrap, &init, &hello, &hog, &progress];
        let receipt = test_wyr_build_receipt(&request, artifacts);
        verify_wyr_build_receipt(&request, receipt.as_bytes(), artifacts).unwrap();

        let mut substitute = loader.clone();
        substitute[400] ^= 0x5a;
        verify_efi_loader(&substitute).unwrap();
        assert!(
            verify_wyr_build_receipt(
                &request,
                receipt.as_bytes(),
                [&substitute, &bootstrap, &init, &hello, &hog, &progress],
            )
            .is_err()
        );
        let layout_mutation =
            receipt.replace("deep_layout_sha256 = \"", "deep_layout_sha256 = \"0");
        assert!(
            require_matching_wyr_receipt(receipt.as_bytes(), layout_mutation.as_bytes()).is_err()
        );
        let config_mutation = receipt.replace(
            "uefi_effective_config_sha256 = \"",
            "uefi_effective_config_sha256 = \"0",
        );
        assert!(
            require_matching_wyr_receipt(receipt.as_bytes(), config_mutation.as_bytes()).is_err()
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn recorded_receipt_accepts_a_historical_cargo_lock() {
        let root = fixture();
        let request_path = root.join("request.toml");
        fs::write(&request_path, request_text()).unwrap();
        let request = load(&request_path).unwrap();
        let loader = valid_pe();
        let bootstrap = valid_elf(b"bootstrap");
        let init = valid_elf(b"init");
        let hello = valid_elf(b"hello");
        let hog = valid_hog_elf(b"WYRMDW1B-HOG-V1:steady-spin-only");
        let progress = valid_elf(b"progress");
        let artifacts = [&loader[..], &bootstrap, &init, &hello, &hog, &progress];
        let current_receipt = test_wyr_build_receipt(&request, artifacts);
        let repository = crate::tasks::repository_root().unwrap();
        let current_lock = sha256::file_digest(&repository.join("Cargo.lock")).unwrap();
        let historical_lock = sha256::bytes_digest(b"historical Cargo.lock");
        assert_ne!(current_lock, historical_lock);
        let historical_receipt = current_receipt.replacen(&current_lock, &historical_lock, 1);

        verify_wyr_build_receipt(&request, historical_receipt.as_bytes(), artifacts).unwrap();
        assert!(verify_current_cargo_lock(historical_receipt.as_bytes()).is_err());

        let invalid_receipt = historical_receipt.replacen(&historical_lock, SHA256_ZERO, 1);
        assert!(verify_wyr_build_receipt(&request, invalid_receipt.as_bytes(), artifacts).is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn canonical_esp_inspection_rejects_loader_and_bootstrap_substitution() {
        let root = fixture();
        fs::create_dir_all(root.join("out")).unwrap();
        let request_path = root.join("request.toml");
        fs::write(&request_path, request_text()).unwrap();
        let request = load(&request_path).unwrap();
        let image_args = crate::cli::G3ImageArguments {
            image: request.esp.display().to_string(),
            loader: request.loader.display().to_string(),
            kernel: request.kernel.display().to_string(),
            bootstrap: request.bootstrap.display().to_string(),
            bootfs: request.bootfs.display().to_string(),
        };
        fs::write(&request.bootfs, b"bootfs").unwrap();
        crate::g3_image::build(&image_args).unwrap();
        inspect_canonical_esp(&request).unwrap();

        fs::write(&request.loader, b"substituted loader").unwrap();
        assert!(inspect_canonical_esp(&request).is_err());
        fs::write(&request.loader, [0]).unwrap();
        fs::write(&request.bootstrap, b"substituted bootstrap").unwrap();
        assert!(inspect_canonical_esp(&request).is_err());

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn observed_timeout_is_recorded_but_never_accepted() {
        let root = fixture();
        fs::create_dir_all(root.join("out")).unwrap();
        fs::create_dir_all(root.join("run")).unwrap();
        let request_path = root.join("request.toml");
        fs::write(&request_path, request_text()).unwrap();
        fs::write(root.join("out/receipt.toml"), b"build receipt").unwrap();
        fs::write(root.join("out/esp.img"), b"esp").unwrap();
        fs::write(root.join("out/bootfs.img"), b"bootfs").unwrap();
        let request = load(&request_path).unwrap();
        let error = execute_run_loaded(&request_path, request, |run| {
            fs::write(&run.serial_log, b"partial serial").unwrap();
            Ok(RunObservation {
                qemu_exit_status: None,
                timed_out: true,
            })
        })
        .unwrap_err();
        assert!(error.message.contains("timed out"));
        let receipt = fs::read_to_string(root.join("run/run-receipt.toml")).unwrap();
        assert!(receipt.contains("qemu_exit_status = -1"));
        assert!(receipt.contains("timed_out = true"));
        fs::remove_dir_all(root).unwrap();
    }

    fn fixture() -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("wyrmroot-dw1b-{nonce}"));
        fs::create_dir_all(root.join("inputs")).unwrap();
        fs::create_dir_all(root.join("out")).unwrap();
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
            "ovmf-code",
            "ovmf-vars",
        ] {
            fs::write(root.join("inputs").join(name), b"x").unwrap();
        }
        fs::write(root.join("out/wyr-build.toml"), b"x").unwrap();
        root
    }

    fn request_text() -> String {
        let input_hash = sha256::bytes_digest(b"x");
        let wyrmroot_revision = current_test_revision();
        format!(
            "schema_version = 5\ndeepwyrm_revision = \"{DEEPWYRM_CANDIDATE}\"\ndeepwyrm_abi_tree = \"{DEEPWYRM_ABI_TREE}\"\nwyrmroot_revision = \"{wyrmroot_revision}\"\nrust_revision = \"{ACCEPTED_RUST_REVISION}\"\nselector = \"{SELECTOR}\"\ntest_id = 26\ntimeout_seconds = 30\nloader = \"inputs/loader\"\nloader_sha256 = \"{input_hash}\"\nkernel = \"inputs/kernel\"\nkernel_sha256 = \"{input_hash}\"\nsymbols = \"inputs/symbols\"\nsymbols_sha256 = \"{input_hash}\"\nbootstrap = \"inputs/bootstrap\"\nbootstrap_sha256 = \"{input_hash}\"\ninit = \"inputs/init\"\ninit_sha256 = \"{input_hash}\"\nhello = \"inputs/hello\"\nhello_sha256 = \"{input_hash}\"\ncpu_hog = \"inputs/hog\"\ncpu_hog_sha256 = \"{input_hash}\"\nprogress = \"inputs/progress\"\nprogress_sha256 = \"{input_hash}\"\nwyr_build_receipt = \"out/wyr-build.toml\"\nprovenance = \"inputs/provenance\"\nprovenance_sha256 = \"{input_hash}\"\novmf_code = \"inputs/ovmf-code\"\novmf_code_sha256 = \"{input_hash}\"\novmf_vars = \"inputs/ovmf-vars\"\novmf_vars_sha256 = \"{input_hash}\"\nbootfs = \"out/bootfs.img\"\nesp = \"out/esp.img\"\nrun_directory = \"run\"\nserial_log = \"run/serial.log\"\nrun_receipt = \"run/run-receipt.toml\"\nevidence_nonce = \"0000000000000001\"\nchallenge_digest = \"{DIGEST:016X}\"\nbootfs_pages = 1\nreceipt = \"out/receipt.toml\"\n"
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

    fn current_test_revision() -> String {
        let output = Command::new("git")
            .args(["rev-parse", "HEAD"])
            .output()
            .unwrap();
        String::from_utf8(output.stdout).unwrap().trim().to_owned()
    }

    fn test_wyr_build_receipt(request: &Request, artifacts: [&[u8]; 6]) -> String {
        let repository = crate::tasks::repository_root().unwrap();
        let cargo_lock = sha256::file_digest(&repository.join("Cargo.lock")).unwrap();
        let metadata = sha256::bytes_digest(b"fixture metadata");
        format!(
            "kind = \"{WYR_BUILD_KIND}\"\nschema_version = 2\nwyrmroot_revision = \"{}\"\nrust_revision = \"{ACCEPTED_RUST_REVISION}\"\nrustc_sha256 = \"{ACCEPTED_RUSTC_SHA256}\"\ncargo_sha256 = \"{ACCEPTED_CARGO_SHA256}\"\nrust_lld_sha256 = \"{ACCEPTED_RUST_LLD_SHA256}\"\ntoolchain_manifest_sha256 = \"{ACCEPTED_TOOLCHAIN_MANIFEST_SHA256}\"\ntoolchain_tree_sha256 = \"{ACCEPTED_TOOLCHAIN_TREE_SHA256}\"\ncargo_lock_sha256 = \"{cargo_lock}\"\nprofile = \"release-separate-invocations\"\ndeep_layout_sha256 = \"{metadata}\"\ngenerated_layout_policy_sha256 = \"{metadata}\"\nuefi_effective_config_sha256 = \"{metadata}\"\nuefi_inspector_sha256 = \"{metadata}\"\nuefi_inspection_report_sha256 = \"{metadata}\"\ntoolchain_validation_report_sha256 = \"{metadata}\"\nloader_command = \"{LOADER_COMMAND}\"\nbootstrap_command = \"{BOOTSTRAP_COMMAND}\"\ninit_command = \"{INIT_COMMAND}\"\nhello_command = \"{HELLO_COMMAND}\"\nhog_command = \"{HOG_COMMAND}\"\nprogress_command = \"{PROGRESS_COMMAND}\"\nloader_sha256 = \"{}\"\nbootstrap_sha256 = \"{}\"\ninit_sha256 = \"{}\"\nhello_sha256 = \"{}\"\ncpu_hog_sha256 = \"{}\"\nprogress_sha256 = \"{}\"\n",
            request.wyrmroot_revision,
            sha256::bytes_digest(artifacts[0]),
            sha256::bytes_digest(artifacts[1]),
            sha256::bytes_digest(artifacts[2]),
            sha256::bytes_digest(artifacts[3]),
            sha256::bytes_digest(artifacts[4]),
            sha256::bytes_digest(artifacts[5]),
        )
    }

    fn valid_elf(marker: &[u8]) -> Vec<u8> {
        let mut elf = vec![0_u8; 120];
        elf[..4].copy_from_slice(b"\x7fELF");
        elf[4] = 2;
        elf[5] = 1;
        elf[6] = 1;
        elf[16..18].copy_from_slice(&2_u16.to_le_bytes());
        elf[18..20].copy_from_slice(&62_u16.to_le_bytes());
        elf[20..24].copy_from_slice(&1_u32.to_le_bytes());
        elf[24..32].copy_from_slice(&0x0040_0000_u64.to_le_bytes());
        elf[32..40].copy_from_slice(&64_u64.to_le_bytes());
        elf[52..54].copy_from_slice(&64_u16.to_le_bytes());
        elf[54..56].copy_from_slice(&56_u16.to_le_bytes());
        elf[56..58].copy_from_slice(&1_u16.to_le_bytes());
        elf[64..68].copy_from_slice(&1_u32.to_le_bytes());
        elf[68..72].copy_from_slice(&5_u32.to_le_bytes());
        elf[80..88].copy_from_slice(&0x0040_0000_u64.to_le_bytes());
        elf.extend_from_slice(marker);
        elf.extend_from_slice(&[0xf3, 0x90, 0xeb, 0xfc]);
        let size = u64::try_from(elf.len()).unwrap();
        elf[96..104].copy_from_slice(&size.to_le_bytes());
        elf[104..112].copy_from_slice(&size.to_le_bytes());
        elf[112..120].copy_from_slice(&0x1000_u64.to_le_bytes());
        elf
    }

    fn valid_hog_elf(marker: &[u8]) -> Vec<u8> {
        let mut elf = valid_elf(marker);
        elf.truncate(elf.len() - 4);
        let close_offset = elf.len();
        elf.push(0xc3);
        let run_offset = elf.len();
        elf.extend_from_slice(&[0x90; 8]);
        let call_offset = elf.len();
        elf.push(0xe8);
        let call_displacement =
            i32::try_from(close_offset).unwrap() - i32::try_from(call_offset + 5).unwrap();
        elf.extend_from_slice(&call_displacement.to_le_bytes());
        elf.extend_from_slice(&[0x48, 0x89, 0xc1, 0xb8, 4, 1, 0xb0, 0xd1]);
        elf.extend_from_slice(&[0x80, 0xf9, 0x02, 0x0f, 0x85]);
        elf.extend_from_slice(&(-30_i32).to_le_bytes());
        elf.extend_from_slice(&[0x0f, 0x1f, 0x84, 0, 0, 0, 0, 0]);
        elf.extend_from_slice(&[0xf3, 0x90, 0xeb, 0xfc]);
        let run_size = elf.len() - run_offset;
        let strings = b"\0_RNvNtCsa7HzTacrzfa_16wyrmroot_runtime6native12close_handle\0_RNvCslacJCwVW9f1_24wyrmroot_dw1b_preemption11run_cpu_hog\0";
        let string_offset = elf.len();
        elf.extend_from_slice(strings);
        while !elf.len().is_multiple_of(8) {
            elf.push(0);
        }
        let symbol_offset = elf.len();
        elf.extend_from_slice(&[0; 24]);
        let mut close = [0_u8; 24];
        close[..4].copy_from_slice(&1_u32.to_le_bytes());
        close[4] = 0x12;
        close[6..8].copy_from_slice(&1_u16.to_le_bytes());
        close[8..16].copy_from_slice(
            &(0x0040_0000_u64 + u64::try_from(close_offset).unwrap()).to_le_bytes(),
        );
        close[16..24].copy_from_slice(&1_u64.to_le_bytes());
        elf.extend_from_slice(&close);
        let mut run = [0_u8; 24];
        let run_name = 1 + b"_RNvNtCsa7HzTacrzfa_16wyrmroot_runtime6native12close_handle".len() + 1;
        run[..4].copy_from_slice(&u32::try_from(run_name).unwrap().to_le_bytes());
        run[4] = 0x12;
        run[6..8].copy_from_slice(&1_u16.to_le_bytes());
        run[8..16]
            .copy_from_slice(&(0x0040_0000_u64 + u64::try_from(run_offset).unwrap()).to_le_bytes());
        run[16..24].copy_from_slice(&u64::try_from(run_size).unwrap().to_le_bytes());
        elf.extend_from_slice(&run);
        while !elf.len().is_multiple_of(8) {
            elf.push(0);
        }
        let section_offset = elf.len();
        elf.extend_from_slice(&[0; 64]);
        let mut text = [0_u8; 64];
        text[4..8].copy_from_slice(&1_u32.to_le_bytes());
        text[8..16].copy_from_slice(&6_u64.to_le_bytes());
        text[16..24].copy_from_slice(&0x0040_0000_u64.to_le_bytes());
        text[32..40].copy_from_slice(&u64::try_from(symbol_offset).unwrap().to_le_bytes());
        text[48..56].copy_from_slice(&16_u64.to_le_bytes());
        elf.extend_from_slice(&text);
        let mut symtab = [0_u8; 64];
        symtab[4..8].copy_from_slice(&2_u32.to_le_bytes());
        symtab[24..32].copy_from_slice(&u64::try_from(symbol_offset).unwrap().to_le_bytes());
        symtab[32..40].copy_from_slice(&72_u64.to_le_bytes());
        symtab[40..44].copy_from_slice(&3_u32.to_le_bytes());
        symtab[56..64].copy_from_slice(&24_u64.to_le_bytes());
        elf.extend_from_slice(&symtab);
        let mut strtab = [0_u8; 64];
        strtab[4..8].copy_from_slice(&3_u32.to_le_bytes());
        strtab[24..32].copy_from_slice(&u64::try_from(string_offset).unwrap().to_le_bytes());
        strtab[32..40].copy_from_slice(&u64::try_from(strings.len()).unwrap().to_le_bytes());
        strtab[48..56].copy_from_slice(&1_u64.to_le_bytes());
        elf.extend_from_slice(&strtab);
        elf[40..48].copy_from_slice(&u64::try_from(section_offset).unwrap().to_le_bytes());
        elf[58..60].copy_from_slice(&64_u16.to_le_bytes());
        elf[60..62].copy_from_slice(&4_u16.to_le_bytes());
        let size = u64::try_from(elf.len()).unwrap();
        elf[96..104].copy_from_slice(&size.to_le_bytes());
        elf[104..112].copy_from_slice(&size.to_le_bytes());
        elf
    }

    fn valid_pe() -> Vec<u8> {
        let mut pe = vec![0_u8; 1024];
        pe[..2].copy_from_slice(b"MZ");
        pe[0x3c..0x40].copy_from_slice(&0x80_u32.to_le_bytes());
        pe[0x80..0x84].copy_from_slice(b"PE\0\0");
        pe[0x84..0x86].copy_from_slice(&0x8664_u16.to_le_bytes());
        pe[0x86..0x88].copy_from_slice(&1_u16.to_le_bytes());
        pe[0x94..0x96].copy_from_slice(&240_u16.to_le_bytes());
        pe[0x96..0x98].copy_from_slice(&2_u16.to_le_bytes());
        pe[0x98..0x9a].copy_from_slice(&0x20b_u16.to_le_bytes());
        pe[0xa8..0xac].copy_from_slice(&0x1000_u32.to_le_bytes());
        pe[0xdc..0xde].copy_from_slice(&10_u16.to_le_bytes());
        pe[0x104..0x108].copy_from_slice(&16_u32.to_le_bytes());
        pe[0x138..0x13c].copy_from_slice(&0x1000_u32.to_le_bytes());
        pe[0x13c..0x140].copy_from_slice(&28_u32.to_le_bytes());
        pe[0x190..0x194].copy_from_slice(&0x200_u32.to_le_bytes());
        pe[0x194..0x198].copy_from_slice(&0x1000_u32.to_le_bytes());
        pe[0x198..0x19c].copy_from_slice(&0x200_u32.to_le_bytes());
        pe[0x19c..0x1a0].copy_from_slice(&0x200_u32.to_le_bytes());
        pe[0x1ac..0x1b0].copy_from_slice(&0x6000_0020_u32.to_le_bytes());
        pe[0x20c..0x210].copy_from_slice(&16_u32.to_le_bytes());
        pe
    }
}
