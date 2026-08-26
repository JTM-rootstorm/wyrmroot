//! DW1-B selector-26 request, four-entry product, receipt, and evidence parser.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Component, Path, PathBuf};

use wyrmroot_bootfs::archive::Archive;
use wyrmroot_bootfs::builder::{Builder, FileMode};

use crate::error::Failure;
use crate::sha256;

pub const SCHEMA_VERSION: u32 = 5;
pub const SELECTOR: &str = "normal-preemption-up";
pub const TEST_ID: u32 = 26;
pub const DIGEST: u64 = 0x5E4E_054B_5C24_4ACE;
pub const DEEPWYRM_CANDIDATE: &str = "0859684651e32655cc9f322fcca5b732d2cb12ca";
pub const DEEPWYRM_ABI_TREE: &str = "1c6a74f130e386eee95b3780c75950beefd0037d";
const RECEIPT_KIND: &str = "wyrmroot-dw1-b-build-lineage";
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
    "kernel",
    "symbols",
    "bootstrap",
    "init",
    "hello",
    "cpu_hog",
    "progress",
    "provenance",
    "bootfs",
    "esp",
    "run_directory",
    "evidence_nonce",
    "challenge_digest",
    "bootfs_pages",
    "receipt",
];

#[derive(Clone, Debug)]
pub struct Request {
    request_sha256: String,
    deepwyrm_revision: String,
    wyrmroot_revision: String,
    rust_revision: String,
    loader: PathBuf,
    kernel: PathBuf,
    symbols: PathBuf,
    bootstrap: PathBuf,
    init: PathBuf,
    hello: PathBuf,
    cpu_hog: PathBuf,
    progress: PathBuf,
    provenance: PathBuf,
    bootfs: PathBuf,
    esp: PathBuf,
    run_directory: PathBuf,
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
    let digest = parse_hex_u64(required(&values, "challenge_digest")?)?;
    if digest != DIGEST || required(&values, "challenge_digest")? != format!("{DIGEST:016X}") {
        return Err(Failure::task(
            "DW1-B challenge digest does not match the frozen transcript",
        ));
    }
    let request = Request {
        request_sha256: sha256::bytes_digest(&bytes),
        deepwyrm_revision: revision(&values, "deepwyrm_revision")?,
        wyrmroot_revision: revision(&values, "wyrmroot_revision")?,
        rust_revision: revision(&values, "rust_revision")?,
        loader: input(&parent, required(&values, "loader")?)?,
        kernel: input(&parent, required(&values, "kernel")?)?,
        symbols: input(&parent, required(&values, "symbols")?)?,
        bootstrap: input(&parent, required(&values, "bootstrap")?)?,
        init: input(&parent, required(&values, "init")?)?,
        hello: input(&parent, required(&values, "hello")?)?,
        cpu_hog: input(&parent, required(&values, "cpu_hog")?)?,
        progress: input(&parent, required(&values, "progress")?)?,
        provenance: input(&parent, required(&values, "provenance")?)?,
        bootfs: output(&parent, required(&values, "bootfs")?)?,
        esp: output(&parent, required(&values, "esp")?)?,
        run_directory: output(&parent, required(&values, "run_directory")?)?,
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
    let loader = read(&request.loader, "loader")?;
    let kernel = read(&request.kernel, "kernel")?;
    let symbols = read(&request.symbols, "symbols")?;
    let bootstrap = read(&request.bootstrap, "bootstrap")?;
    let provenance = read(&request.provenance, "provenance")?;
    let init = read(&request.init, "init")?;
    let hello = read(&request.hello, "hello")?;
    let hog = read(&request.cpu_hog, "cpu hog")?;
    let progress = read(&request.progress, "progress")?;
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
    let loader = read(&request.loader, "loader")?;
    let kernel = read(&request.kernel, "kernel")?;
    let symbols = read(&request.symbols, "symbols")?;
    let bootstrap = read(&request.bootstrap, "bootstrap")?;
    let provenance = read(&request.provenance, "provenance")?;
    let esp = read(&request.esp, "ESP")?;
    let bootfs = read(&request.bootfs, "bootfs")?;
    let artifacts = [
        read(&request.init, "init")?,
        read(&request.hello, "hello")?,
        read(&request.cpu_hog, "cpu hog")?,
        read(&request.progress, "progress")?,
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

pub fn evidence(request_path: &Path, log: &Path, debug_exit: u32) -> Result<String, Failure> {
    if debug_exit != 33 {
        return Err(Failure::task(
            "DW1-B evidence requires QEMU debug-exit status 33",
        ));
    }
    let _ = inspect(request_path)?;
    let request = load(request_path)?;
    let bytes =
        fs::read(log).map_err(|e| Failure::task(format!("could not read DW1-B log: {e}")))?;
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
    for (label, elf) in [
        ("kernel", inputs.kernel),
        ("symbols", inputs.symbols),
        ("init", inputs.init),
        ("hello", inputs.hello),
        ("cpu hog", inputs.hog),
        ("progress", inputs.progress),
    ] {
        verify_static_elf(label, elf)?;
    }
    if !contains_bytes(inputs.init, b"WYRMINIT0-PROFILE-V1:dw1b-preemption")
        || !contains_bytes(inputs.hog, b"WYRMDW1B-HOG-V1:steady-spin-only")
        || !contains_bytes(inputs.progress, b"WYRMDW1B-PROGRESS-V1:eight-rounds")
    {
        return Err(Failure::task("DW1-B payload profile marker mismatch"));
    }
    let provenance = core::str::from_utf8(inputs.provenance)
        .map_err(|_| Failure::task("DW1-B provenance is not UTF-8"))?;
    for expected in [
        format!("deepwyrm_revision={DEEPWYRM_CANDIDATE}"),
        format!("deepwyrm_abi_tree={DEEPWYRM_ABI_TREE}"),
        format!(
            "DEEPWYRM_DW1B_EVIDENCE_NONCE={:016X}",
            request.evidence_nonce
        ),
        format!("DEEPWYRM_DW1B_CHALLENGE_DIGEST={DIGEST:016X}"),
        format!("DEEPWYRM_DW1B_BOOTFS_MAX_PAGES={}", request.bootfs_pages),
    ] {
        if provenance.lines().filter(|line| *line == expected).count() != 1 {
            return Err(Failure::task(format!(
                "DW1-B provenance lacks exact line {expected}"
            )));
        }
    }
    Ok(())
}

fn verify_static_elf(label: &str, bytes: &[u8]) -> Result<(), Failure> {
    if bytes.len() < 64
        || &bytes[..4] != b"\x7fELF"
        || bytes[4] != 2
        || bytes[5] != 1
        || u16::from_le_bytes([bytes[16], bytes[17]]) != 2
        || u16::from_le_bytes([bytes[18], bytes[19]]) != 62
    {
        return Err(Failure::task(format!(
            "DW1-B {label} is not a static x86_64 executable ELF"
        )));
    }
    let phoff = usize::try_from(u64::from_le_bytes(bytes[32..40].try_into().unwrap()))
        .map_err(|_| Failure::task("DW1-B ELF program-header offset overflow"))?;
    let phentsize = usize::from(u16::from_le_bytes([bytes[54], bytes[55]]));
    let phnum = usize::from(u16::from_le_bytes([bytes[56], bytes[57]]));
    if phentsize < 56 {
        return Err(Failure::task("DW1-B ELF program-header size is invalid"));
    }
    for index in 0..phnum {
        let offset = phoff
            .checked_add(index.saturating_mul(phentsize))
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
    }
    Ok(())
}

fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
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
        || !v
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        return Err(Failure::task(format!("DW1-B {key} is not a commit")));
    }
    Ok(v.to_owned())
}
fn clean_path(parent: &Path, value: &str, output: bool) -> Result<PathBuf, Failure> {
    let p = Path::new(value);
    if p.is_absolute() || p.components().any(|c| !matches!(c, Component::Normal(_))) {
        return Err(Failure::task("DW1-B path is not canonical relative"));
    }
    let p = parent.join(p);
    if output {
        if p.exists() {
            let resolved = fs::canonicalize(&p)
                .map_err(|e| Failure::task(format!("could not resolve DW1-B output: {e}")))?;
            if !resolved.starts_with(parent)
                || fs::symlink_metadata(&p).is_ok_and(|m| m.file_type().is_symlink())
            {
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
        let resolved = fs::canonicalize(&p)
            .map_err(|e| Failure::task(format!("could not resolve DW1-B input: {e}")))?;
        if !resolved.starts_with(parent)
            || fs::symlink_metadata(&p).is_ok_and(|m| m.file_type().is_symlink())
        {
            return Err(Failure::task("DW1-B input escapes through a symlink"));
        }
        Ok(resolved)
    } else {
        Err(Failure::task("DW1-B input is not a file"))
    }
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
        &request.receipt,
    ];
    let mut unique = BTreeSet::new();
    for path in paths {
        if !unique.insert(path) {
            return Err(Failure::task(
                "DW1-B input, output, or run-directory paths alias",
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
    }

    #[test]
    fn schema_rejects_revision_timeout_alias_traversal_and_symlink() {
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
        }
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn serial_text_without_exact_debug_exit_is_never_evidence() {
        assert!(evidence(Path::new("missing"), Path::new("missing"), 32).is_err());
    }

    #[test]
    fn canonical_template_names_exact_candidate_and_digest() {
        let template = include_str!("../../../toolchain/templates/dw1-b-request.toml");
        assert!(template.contains(DEEPWYRM_CANDIDATE));
        assert!(template.contains(DEEPWYRM_ABI_TREE));
        assert!(template.contains("challenge_digest = \"5E4E054B5C244ACE\""));
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
        format!(
            "schema_version = 5\ndeepwyrm_revision = \"{DEEPWYRM_CANDIDATE}\"\ndeepwyrm_abi_tree = \"{DEEPWYRM_ABI_TREE}\"\nwyrmroot_revision = \"0000000000000000000000000000000000000000\"\nrust_revision = \"0000000000000000000000000000000000000000\"\nselector = \"{SELECTOR}\"\ntest_id = 26\ntimeout_seconds = 30\nloader = \"inputs/loader\"\nkernel = \"inputs/kernel\"\nsymbols = \"inputs/symbols\"\nbootstrap = \"inputs/bootstrap\"\ninit = \"inputs/init\"\nhello = \"inputs/hello\"\ncpu_hog = \"inputs/hog\"\nprogress = \"inputs/progress\"\nprovenance = \"inputs/provenance\"\nbootfs = \"out/bootfs.img\"\nesp = \"out/esp.img\"\nrun_directory = \"run\"\nevidence_nonce = \"0000000000000001\"\nchallenge_digest = \"{DIGEST:016X}\"\nbootfs_pages = 1\nreceipt = \"out/receipt.toml\"\n"
        )
    }
}
