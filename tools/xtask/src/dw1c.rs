//! Selector-28 immutable designated-VM handoff preparation.
//!
//! This is deliberately preparation-only: Wyrmroot owns deterministic product
//! identity and libvirt input manifests, while the root coordinator owns the
//! persistent-domain lifecycle and the 46-record `DW1C` verifier.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};

use crate::error::Failure;
use crate::sha256;

const SELECTOR: &str = "normal-preemption-smp";
const TEST_ID: &str = "28";
const MACHINE: &str = "pc-q35-10.2";
const DOMAIN_UUID: &str = "33005e22-d7c2-4b13-b1ac-b82eda95e584";
const O_NOFOLLOW: i32 = 0x2_0000;
const MAX_INPUT_BYTES: u64 = 512 * 1024 * 1024;
const ABSENT: &str = "absent";
const PASSES: [&str; 6] = [
    "smoke", "stress-1", "stress-2", "stress-3", "stress-4", "stress-5",
];
const INPUTS: [&str; 19] = [
    "loader",
    "kernel",
    "symbols",
    "bootstrap",
    "actor1",
    "actor2",
    "actor3",
    "actor4",
    "actor5",
    "actor6",
    "actor7",
    "actor8",
    "actor9",
    "actor10",
    "provenance",
    "bootfs",
    "esp",
    "ovmf_code",
    "ovmf_vars_template",
];
const REQUEST_KEYS: [&str; 52] = [
    "schema_version",
    "selector",
    "test_id",
    "timeout_seconds",
    "vcpus",
    "memory_mib",
    "deepwyrm_revision",
    "wyrmroot_revision",
    "rust_revision",
    "evidence_nonce",
    "progress_digest",
    "build_receipt",
    "build_receipt_sha256",
    "campaign_directory",
    "loader_path",
    "loader_sha256",
    "kernel_path",
    "kernel_sha256",
    "symbols_path",
    "symbols_sha256",
    "bootstrap_path",
    "bootstrap_sha256",
    "actor1_path",
    "actor1_sha256",
    "actor2_path",
    "actor2_sha256",
    "actor3_path",
    "actor3_sha256",
    "actor4_path",
    "actor4_sha256",
    "actor5_path",
    "actor5_sha256",
    "actor6_path",
    "actor6_sha256",
    "actor7_path",
    "actor7_sha256",
    "actor8_path",
    "actor8_sha256",
    "actor9_path",
    "actor9_sha256",
    "actor10_path",
    "actor10_sha256",
    "provenance_path",
    "provenance_sha256",
    "bootfs_path",
    "bootfs_sha256",
    "esp_path",
    "esp_sha256",
    "ovmf_code_path",
    "ovmf_code_sha256",
    "ovmf_vars_template_path",
    "ovmf_vars_template_sha256",
];

/// Creates a fresh six-pass campaign containing immutable all-string TOML
/// handoffs and exact q35/OVMF domain XML.  It never invokes QEMU or libvirt.
pub fn prepare(request_path: &Path) -> Result<String, Failure> {
    let request = Request::load(request_path)?;
    let campaign = create_fresh_directory(&request.campaign_directory, "DW1-C campaign directory")?;
    let immutable =
        create_fresh_directory(&campaign.join("immutable"), "DW1-C immutable directory")?;
    let request_snapshot = snapshot(request_path, &immutable.join("request.toml"))?;
    let receipt_snapshot = snapshot_expected(
        &request.build_receipt,
        &request.values["build_receipt_sha256"],
        &immutable.join("build-receipt.toml"),
    )?;
    let mut inputs = BTreeMap::new();
    for label in INPUTS {
        let source = request.path(label)?;
        inputs.insert(
            label,
            snapshot_expected(
                &source,
                &request.values[&format!("{label}_sha256")],
                &immutable.join(file_name(label)),
            )?,
        );
    }
    let mut campaign_fields = base_fields(&request, &request_snapshot, &receipt_snapshot, &inputs)?;
    campaign_fields.insert("kind".into(), "wyrmroot-dw1-c-vm-campaign".into());
    campaign_fields.insert("campaign_pass_count".into(), PASSES.len().to_string());
    for pass in PASSES {
        let directory = create_fresh_directory(&campaign.join(pass), "DW1-C pass directory")?;
        let vars_source = request.path("ovmf_vars_template")?;
        let vars = snapshot_with_mode(&vars_source, &directory.join("OVMF_VARS.fd"), 0o600)?;
        let xml = domain_xml(&inputs, &vars)?;
        let xml_snapshot = write_new(&directory.join("domain.xml"), xml.as_bytes(), 0o444)?;
        let mut fields = base_fields(&request, &request_snapshot, &receipt_snapshot, &inputs)?;
        fields.insert("kind".into(), "wyrmroot-dw1-c-vm-handoff".into());
        fields.insert("campaign_pass".into(), pass.into());
        fields.insert("domain_xml_path".into(), text_path(&xml_snapshot.path)?);
        fields.insert("domain_xml_sha256".into(), xml_snapshot.sha256);
        fields.insert("ovmf_vars_path".into(), text_path(&vars.path)?);
        fields.insert("ovmf_vars_initial_sha256".into(), vars.sha256);
        let serial = directory.join("serial.log");
        let evidence = directory.join("evidence.log");
        let result = directory.join("result.json");
        fields.insert("serial_log_path".into(), text_path(&serial)?);
        fields.insert("evidence_log_path".into(), text_path(&evidence)?);
        fields.insert("result_json_path".into(), text_path(&result)?);
        // The root-owned runner exclusively creates this path.  The alias is
        // intentional and explicit; all other pass outputs are distinct.
        fields.insert("run_receipt_path".into(), text_path(&result)?);
        fields.insert("run_receipt_sha256".into(), ABSENT.into());
        ensure_absent_outputs(&[&serial, &evidence, &result])?;
        let handoff = render(&fields)?;
        let handoff_snapshot =
            write_new(&directory.join("handoff.toml"), handoff.as_bytes(), 0o444)?;
        campaign_fields.insert(
            format!("{pass}_handoff_path"),
            text_path(&handoff_snapshot.path)?,
        );
        campaign_fields.insert(format!("{pass}_handoff_sha256"), handoff_snapshot.sha256);
    }
    let campaign_handoff = render(&campaign_fields)?;
    let output = write_new(
        &campaign.join("campaign.toml"),
        campaign_handoff.as_bytes(),
        0o444,
    )?;
    Ok(format!(
        "DW1_C_PREPARE_PASS selector={SELECTOR} test_id={TEST_ID} passes=6 campaign={} sha256={}\n",
        output.path.display(),
        output.sha256
    ))
}

#[derive(Clone)]
struct Snapshot {
    path: PathBuf,
    sha256: String,
}

struct Request {
    root: PathBuf,
    values: BTreeMap<String, String>,
    build_receipt: PathBuf,
    campaign_directory: PathBuf,
}

impl Request {
    fn load(path: &Path) -> Result<Self, Failure> {
        let bytes = read_regular(path, "DW1-C request")?;
        let values = scalars(
            core::str::from_utf8(&bytes)
                .map_err(|_| Failure::task("DW1-C request is not UTF-8"))?,
        )?;
        let expected = REQUEST_KEYS.into_iter().collect::<BTreeSet<_>>();
        let actual = values.keys().map(String::as_str).collect::<BTreeSet<_>>();
        if actual != expected {
            return Err(Failure::task("DW1-C request key set is not exact"));
        }
        for (key, expected) in [
            ("selector", SELECTOR),
            ("test_id", TEST_ID),
            ("timeout_seconds", "240"),
            ("vcpus", "4"),
            ("memory_mib", "2048"),
        ] {
            if values.get(key).map(String::as_str) != Some(expected) {
                return Err(Failure::task(format!(
                    "DW1-C request requires {key}={expected}"
                )));
            }
        }
        for key in [
            "deepwyrm_revision",
            "wyrmroot_revision",
            "rust_revision",
            "evidence_nonce",
            "progress_digest",
            "build_receipt",
            "build_receipt_sha256",
            "campaign_directory",
        ] {
            if values.get(key).is_none_or(String::is_empty) {
                return Err(Failure::task(format!("DW1-C request is missing {key}")));
            }
        }
        for key in ["deepwyrm_revision", "wyrmroot_revision", "rust_revision"] {
            let value = &values[key];
            if value.len() != 40
                || !value
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
            {
                return Err(Failure::task(format!(
                    "DW1-C request {key} is not a lowercase Git revision"
                )));
            }
        }
        for key in ["evidence_nonce", "progress_digest"] {
            let value = &values[key];
            if value.len() != 16
                || value == "0000000000000000"
                || !value
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_lowercase())
            {
                return Err(Failure::task(format!(
                    "DW1-C request {key} is not nonzero uppercase 16-hex"
                )));
            }
        }
        for label in INPUTS {
            for suffix in ["path", "sha256"] {
                if values
                    .get(&format!("{label}_{suffix}"))
                    .is_none_or(String::is_empty)
                {
                    return Err(Failure::task(format!(
                        "DW1-C request is missing {label}_{suffix}"
                    )));
                }
            }
        }
        let mut hash_keys = vec!["build_receipt_sha256".to_owned()];
        hash_keys.extend(INPUTS.map(|label| format!("{label}_sha256")));
        for key in hash_keys {
            let value = &values[&key];
            if value.len() != 64
                || !value
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
            {
                return Err(Failure::task(format!(
                    "DW1-C request {key} is not lowercase SHA-256"
                )));
            }
        }
        let root = fs::canonicalize(
            path.parent()
                .ok_or_else(|| Failure::task("DW1-C request has no parent"))?,
        )
        .map_err(io)?;
        let build_receipt = input_path(&root, values.get("build_receipt").unwrap())?;
        let campaign_directory = output_path(&root, values.get("campaign_directory").unwrap())?;
        Ok(Self {
            root,
            values,
            build_receipt,
            campaign_directory,
        })
    }
    fn path(&self, label: &str) -> Result<PathBuf, Failure> {
        input_path(
            &self.root,
            self.values
                .get(&format!("{label}_path"))
                .ok_or_else(|| Failure::task("missing input path"))?,
        )
    }
}

fn base_fields(
    request: &Request,
    request_snapshot: &Snapshot,
    receipt: &Snapshot,
    inputs: &BTreeMap<&str, Snapshot>,
) -> Result<BTreeMap<String, String>, Failure> {
    let mut fields = BTreeMap::new();
    for (key, value) in [
        ("schema_version", "1"),
        ("vcpus", "4"),
        ("memory_mib", "2048"),
        ("machine", MACHINE),
        ("firmware", "OVMF"),
        ("selector", SELECTOR),
        ("test_id", TEST_ID),
        ("timeout_seconds", "240"),
        ("evidence_protocol", "DW1C/01"),
        ("evidence_record_count", "46"),
        ("kernel_result_protocol", "DWTEST1"),
        ("kernel_result_test_id", TEST_ID),
        ("kernel_result_detail", "0"),
        ("com1", "kernel-diagnostics-host-capture"),
        ("com2", "absent"),
        ("network", "none"),
        ("host_shares", "none"),
        ("system_disk", "absent"),
    ] {
        fields.insert(key.into(), value.into());
    }
    for key in [
        "deepwyrm_revision",
        "wyrmroot_revision",
        "rust_revision",
        "evidence_nonce",
        "progress_digest",
    ] {
        fields.insert(key.into(), request.values[key].clone());
    }
    fields.insert("request_path".into(), text_path(&request_snapshot.path)?);
    fields.insert("request_sha256".into(), request_snapshot.sha256.clone());
    fields.insert("build_receipt_path".into(), text_path(&receipt.path)?);
    fields.insert("build_receipt_sha256".into(), receipt.sha256.clone());
    for (label, snapshot) in inputs {
        fields.insert(format!("{label}_path"), text_path(&snapshot.path)?);
        fields.insert(format!("{label}_sha256"), snapshot.sha256.clone());
    }
    Ok(fields)
}

fn domain_xml(inputs: &BTreeMap<&str, Snapshot>, vars: &Snapshot) -> Result<String, Failure> {
    Ok(format!(
        "<domain xmlns:qemu=\"http://libvirt.org/schemas/domain/qemu/1.0\" type=\"qemu\">\n  <name>OS-Project</name>\n  <uuid>{DOMAIN_UUID}</uuid>\n  <memory unit=\"KiB\">2097152</memory>\n  <currentMemory unit=\"KiB\">2097152</currentMemory>\n  <vcpu placement=\"static\">4</vcpu>\n  <sysinfo type=\"fwcfg\"><entry name=\"opt/org.deepwyrm.test.selector\">{SELECTOR}</entry><entry name=\"opt/org.deepwyrm.test.test_id\">{TEST_ID}</entry></sysinfo>\n  <os><type arch=\"x86_64\" machine=\"{MACHINE}\">hvm</type><loader readonly=\"yes\" secure=\"no\" type=\"pflash\" format=\"raw\">{}</loader><nvram type=\"file\" format=\"raw\"><source file=\"{}\"/></nvram><boot dev=\"hd\"/></os>\n  <features><acpi/><apic/></features>\n  <clock offset=\"utc\"><timer name=\"rtc\" tickpolicy=\"catchup\"/><timer name=\"pit\" tickpolicy=\"delay\"/><timer name=\"hpet\" present=\"no\"/></clock>\n  <on_poweroff>destroy</on_poweroff><on_reboot>restart</on_reboot><on_crash>destroy</on_crash>\n  <pm><suspend-to-mem enabled=\"no\"/><suspend-to-disk enabled=\"no\"/></pm>\n  <devices><emulator>/usr/bin/qemu-system-x86_64</emulator><disk type=\"file\" device=\"disk\"><driver name=\"qemu\" type=\"raw\"/><source file=\"{}\"/><target dev=\"vda\" bus=\"virtio\"/><readonly/></disk><controller type=\"pci\" index=\"0\" model=\"pcie-root\"/><serial type=\"pty\"><target type=\"isa-serial\" port=\"0\"/></serial><console type=\"pty\"><target type=\"serial\" port=\"0\"/></console></devices>\n  <qemu:commandline><qemu:arg value=\"-device\"/><qemu:arg value=\"isa-debug-exit,iobase=0xf4,iosize=0x04\"/></qemu:commandline>\n</domain>\n",
        xml(&inputs["ovmf_code"].path)?,
        xml(&vars.path)?,
        xml(&inputs["esp"].path)?
    ))
}

fn file_name(label: &str) -> String {
    format!("{label}.bin")
}
fn create_fresh_directory(path: &Path, label: &str) -> Result<PathBuf, Failure> {
    if path.exists() {
        return Err(Failure::task(format!("{label} already exists")));
    }
    fs::create_dir_all(path).map_err(io)?;
    Ok(path.to_path_buf())
}
fn ensure_absent_outputs(paths: &[&Path]) -> Result<(), Failure> {
    let mut seen = BTreeSet::new();
    for path in paths {
        if !seen.insert(*path) || path.exists() {
            return Err(Failure::task(
                "DW1-C pass output exists or aliases another output",
            ));
        }
    }
    Ok(())
}
fn snapshot(source: &Path, target: &Path) -> Result<Snapshot, Failure> {
    snapshot_with_mode(source, target, 0o444)
}
fn snapshot_with_mode(source: &Path, target: &Path, mode: u32) -> Result<Snapshot, Failure> {
    let bytes = read_regular(source, "DW1-C immutable input")?;
    write_new(target, &bytes, mode)
}
fn snapshot_expected(source: &Path, expected: &str, target: &Path) -> Result<Snapshot, Failure> {
    let bytes = read_regular(source, "DW1-C immutable input")?;
    if sha256::bytes_digest(&bytes) != expected {
        return Err(Failure::task(
            "DW1-C immutable input hash does not match request",
        ));
    }
    write_new(target, &bytes, 0o444)
}
fn write_new(path: &Path, bytes: &[u8], mode: u32) -> Result<Snapshot, Failure> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .custom_flags(O_NOFOLLOW)
        .open(path)
        .map_err(io)?;
    file.write_all(bytes)
        .and_then(|_| file.sync_all())
        .map_err(io)?;
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).map_err(io)?;
    Ok(Snapshot {
        path: path.to_path_buf(),
        sha256: sha256::bytes_digest(bytes),
    })
}
fn read_regular(path: &Path, label: &str) -> Result<Vec<u8>, Failure> {
    let meta = fs::symlink_metadata(path).map_err(io)?;
    if meta.file_type().is_symlink()
        || !meta.is_file()
        || meta.nlink() != 1
        || meta.len() == 0
        || meta.len() > MAX_INPUT_BYTES
    {
        return Err(Failure::task(format!(
            "{label} is not a bounded single-link regular file"
        )));
    }
    fs::read(path).map_err(io)
}
fn input_path(root: &Path, value: &str) -> Result<PathBuf, Failure> {
    bounded_relative(root, value, false)
}
fn output_path(root: &Path, value: &str) -> Result<PathBuf, Failure> {
    bounded_relative(root, value, true)
}
fn bounded_relative(root: &Path, value: &str, allow_missing: bool) -> Result<PathBuf, Failure> {
    let relative = Path::new(value);
    if relative.is_absolute()
        || relative
            .components()
            .any(|c| !matches!(c, Component::Normal(_)))
    {
        return Err(Failure::task(
            "DW1-C path is not canonical request-relative",
        ));
    }
    let path = root.join(relative);
    if !allow_missing && !path.exists() {
        return Err(Failure::task("DW1-C input path is absent"));
    }
    Ok(path)
}
fn text_path(path: &Path) -> Result<String, Failure> {
    path.to_str()
        .map(str::to_owned)
        .ok_or_else(|| Failure::task("DW1-C path is not UTF-8"))
}
fn xml(path: &Path) -> Result<String, Failure> {
    let value = text_path(path)?;
    if value.contains(['&', '<', '>', '\"', '\'']) {
        return Err(Failure::task("DW1-C XML path requires escaping"));
    }
    Ok(value)
}
fn render(fields: &BTreeMap<String, String>) -> Result<String, Failure> {
    let mut out = String::new();
    for (key, value) in fields {
        if key.is_empty()
            || !key
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
            || value.contains(['\n', '\r', '\"', '\\'])
        {
            return Err(Failure::task(
                "DW1-C handoff field is not safe all-string TOML",
            ));
        }
        out.push_str(&format!("{key} = \"{value}\"\n"));
    }
    Ok(out)
}
fn scalars(text: &str) -> Result<BTreeMap<String, String>, Failure> {
    let mut out = BTreeMap::new();
    for line in text
        .lines()
        .filter(|line| !line.trim().is_empty() && !line.trim_start().starts_with('#'))
    {
        let (key, value) = line
            .split_once('=')
            .ok_or_else(|| Failure::task("DW1-C request is not scalar TOML"))?;
        let key = key.trim();
        let value = value
            .trim()
            .strip_prefix('\"')
            .and_then(|x| x.strip_suffix('\"'))
            .ok_or_else(|| Failure::task("DW1-C request values must be quoted strings"))?;
        if out.insert(key.to_owned(), value.to_owned()).is_some() {
            return Err(Failure::task("DW1-C request duplicates a field"));
        }
    }
    Ok(out)
}
fn io(error: std::io::Error) -> Failure {
    Failure::task(format!("DW1-C I/O failure: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn domain_is_exact_four_cpu_no_nic_or_share() {
        let p = PathBuf::from("/tmp/a");
        let s = Snapshot {
            path: p,
            sha256: "a".repeat(64),
        };
        let mut inputs = BTreeMap::new();
        for label in INPUTS {
            inputs.insert(label, s.clone());
        }
        let xml = domain_xml(&inputs, &s).unwrap();
        assert!(xml.contains("pc-q35-10.2"));
        assert!(xml.contains(DOMAIN_UUID));
        assert!(xml.contains("<vcpu placement=\"static\">4</vcpu>"));
        assert!(xml.contains("2097152"));
        for required in [
            "<clock offset=\"utc\">",
            "<on_poweroff>destroy</on_poweroff>",
            "<on_reboot>restart</on_reboot>",
            "<on_crash>destroy</on_crash>",
            "<suspend-to-mem enabled=\"no\"/>",
            "<suspend-to-disk enabled=\"no\"/>",
        ] {
            assert!(xml.contains(required));
        }
        assert!(!xml.contains("interface"));
        assert!(!xml.contains("filesystem"));
        assert!(!xml.contains("system_disk"));
    }
    #[test]
    fn render_is_all_string_toml() {
        let mut fields = BTreeMap::new();
        fields.insert("selector".into(), SELECTOR.into());
        assert_eq!(
            render(&fields).unwrap(),
            "selector = \"normal-preemption-smp\"\n"
        );
    }

    #[test]
    fn per_pass_vars_snapshot_is_owner_writable_only() {
        let root = std::env::temp_dir().join(format!("dw1c-vars-{}", std::process::id()));
        fs::create_dir(&root).unwrap();
        let source = root.join("source.fd");
        fs::write(&source, b"vars").unwrap();
        let target = root.join("OVMF_VARS.fd");
        snapshot_with_mode(&source, &target, 0o600).unwrap();
        assert_eq!(
            fs::metadata(&target).unwrap().permissions().mode() & 0o777,
            0o600
        );
        fs::remove_dir_all(root).unwrap();
    }
}
