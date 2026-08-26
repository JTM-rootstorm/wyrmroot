//! Deterministic WYR1-A designated-VM preparation.
//!
//! This module only prepares root-run inputs. It never invokes QEMU, libvirt,
//! or the designated VM, and it never claims either profile passed.

use std::collections::BTreeSet;
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};

use crate::error::Failure;
use crate::sha256;
use crate::wyr1::{self, Profile, Request};

const HANDOFF_SCHEMA_VERSION: u32 = 1;
const HANDOFF_KIND: &str = "wyrmroot-wyr1-a-vm-handoff";
const DOMAIN_NAME: &str = "OS-Project";
const DOMAIN_UUID: &str = "33005e22-d7c2-4b13-b1ac-b82eda95e584";
const DOMAIN_MACHINE: &str = "pc-q35-10.2";
const QEMU_PATH: &str = "/usr/bin/qemu-system-x86_64";
const ESP_FD_GROUP: &str = "dw-f13-esp-v1";
const VARS_FD_GROUP: &str = "dw-f13-ovmf-vars-v1";
const MAX_INPUT_BYTES: u64 = 512 * 1024 * 1024;
const O_NOFOLLOW: i32 = 0x2_0000;

pub struct PreparedBundles {
    pub default: PathBuf,
    pub smp: PathBuf,
    pub esp_sha256: String,
}

#[derive(Clone)]
struct Snapshot {
    path: PathBuf,
    sha256: String,
}

struct ImmutableInputs {
    request: Snapshot,
    receipt: Snapshot,
    loader: Snapshot,
    kernel: Snapshot,
    symbols: Snapshot,
    bootstrap: Snapshot,
    init: Snapshot,
    registryd: Snapshot,
    devmgr: Snapshot,
    uart16550d: Snapshot,
    consoled: Snapshot,
    wyrmsh: Snapshot,
    manifest: Snapshot,
    bootfs: Snapshot,
    esp: Snapshot,
    provenance: Snapshot,
    ovmf_code: Snapshot,
    ovmf_vars_template: Snapshot,
}

pub fn prepare(request: &Request) -> Result<PreparedBundles, Failure> {
    let root = create_fresh_run_root(request)?;
    let immutable_directory = root.join("immutable");
    create_directory(&immutable_directory, "WYR1 immutable snapshot directory")?;
    let inputs = snapshot_inputs(request, &immutable_directory)?;
    if inputs.request.sha256 != request.request_sha256 {
        return Err(Failure::task(
            "WYR1 request changed before VM handoff snapshotting",
        ));
    }
    verify_snapshotted_receipt(request, &inputs)?;

    let default = prepare_profile(request, &inputs, &root, Profile::Default)?;
    let smp = prepare_profile(request, &inputs, &root, Profile::Smp)?;
    Ok(PreparedBundles {
        default,
        smp,
        esp_sha256: inputs.esp.sha256,
    })
}

fn verify_snapshotted_receipt(request: &Request, inputs: &ImmutableInputs) -> Result<(), Failure> {
    let snapshot = Request {
        path: inputs.request.path.clone(),
        loader: inputs.loader.path.clone(),
        kernel: inputs.kernel.path.clone(),
        symbols: inputs.symbols.path.clone(),
        bootstrap: inputs.bootstrap.path.clone(),
        init: inputs.init.path.clone(),
        registryd: inputs.registryd.path.clone(),
        devmgr: inputs.devmgr.path.clone(),
        uart16550d: inputs.uart16550d.path.clone(),
        consoled: inputs.consoled.path.clone(),
        wyrmsh: inputs.wyrmsh.path.clone(),
        rrc_manifest: inputs.manifest.path.clone(),
        bootfs: inputs.bootfs.path.clone(),
        esp: inputs.esp.path.clone(),
        provenance: inputs.provenance.path.clone(),
        ovmf_code: inputs.ovmf_code.path.clone(),
        ovmf_vars_template: inputs.ovmf_vars_template.path.clone(),
        receipt: inputs.receipt.path.clone(),
        ..request.clone()
    };
    wyr1::verify_receipt(&snapshot, Profile::Default)
        .map(|_| ())
        .map_err(|error| {
            Failure::task(format!(
                "snapshotted WYR1 receipt did not rejoin immutable inputs: {}",
                error.message
            ))
        })
}

fn create_fresh_run_root(request: &Request) -> Result<PathBuf, Failure> {
    let request_parent = request
        .path
        .parent()
        .ok_or_else(|| Failure::task("WYR1 request has no parent"))?;
    let relative = request
        .run_directory
        .strip_prefix(request_parent)
        .map_err(|_| Failure::task("WYR1 run directory is not request-relative"))?;
    let resolved_parent = if request_parent.as_os_str().is_empty() {
        Path::new(".")
    } else {
        request_parent
    };
    let parent = fs::canonicalize(resolved_parent).map_err(|error| {
        Failure::task(format!("could not resolve WYR1 request parent: {error}"))
    })?;
    if relative.as_os_str().is_empty()
        || relative
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(Failure::task(
            "WYR1 run directory is not a canonical bounded path",
        ));
    }
    let mut current = parent;
    let components = relative.components().collect::<Vec<_>>();
    for (index, component) in components.into_iter().enumerate() {
        let Component::Normal(name) = component else {
            unreachable!("components were validated")
        };
        current.push(name);
        if index + 1 == relative.components().count() {
            create_directory(&current, "fresh WYR1 run directory")?;
        } else if current.exists() {
            let metadata = fs::symlink_metadata(&current).map_err(|error| {
                Failure::task(format!("could not inspect WYR1 output parent: {error}"))
            })?;
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                return Err(Failure::task("WYR1 output parent is not a real directory"));
            }
        } else {
            create_directory(&current, "WYR1 output parent")?;
        }
    }
    Ok(current)
}

fn create_directory(path: &Path, label: &str) -> Result<(), Failure> {
    fs::create_dir(path)
        .map_err(|error| Failure::task(format!("could not create {label}: {error}")))?;
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| Failure::task(format!("could not inspect {label}: {error}")))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() || metadata.nlink() < 2 {
        return Err(Failure::task(format!("{label} is not a stable directory")));
    }
    Ok(())
}

fn snapshot_inputs(request: &Request, directory: &Path) -> Result<ImmutableInputs, Failure> {
    let specifications = [
        (&request.path, "request.toml"),
        (&request.receipt, "build-receipt.toml"),
        (&request.loader, "loader.efi"),
        (&request.kernel, "deepwyrm.elf"),
        (&request.symbols, "deepwyrm.symbols"),
        (&request.bootstrap, "bootstrap.elf"),
        (&request.init, "system-init.elf"),
        (&request.registryd, "registryd.elf"),
        (&request.devmgr, "devmgr.elf"),
        (&request.uart16550d, "uart16550d.elf"),
        (&request.consoled, "consoled.elf"),
        (&request.wyrmsh, "wyrmsh.elf"),
        (&request.rrc_manifest, "rrc-a-v1.bin"),
        (&request.bootfs, "bootfs.img"),
        (&request.esp, "esp.img"),
        (&request.provenance, "provenance.toml"),
        (&request.ovmf_code, "OVMF_CODE.fd"),
        (&request.ovmf_vars_template, "OVMF_VARS_TEMPLATE.fd"),
    ];
    let mut identities = BTreeSet::new();
    let mut snapshots = Vec::with_capacity(specifications.len());
    for (source, name) in specifications {
        let path_metadata = fs::symlink_metadata(source).map_err(|error| {
            Failure::task(format!(
                "could not inspect WYR1 immutable input {name}: {error}"
            ))
        })?;
        if path_metadata.file_type().is_symlink()
            || !path_metadata.is_file()
            || path_metadata.nlink() != 1
            || path_metadata.len() == 0
            || path_metadata.len() > MAX_INPUT_BYTES
        {
            return Err(Failure::task(format!(
                "WYR1 immutable input {name} is not a bounded single-link regular file"
            )));
        }
        if !identities.insert((path_metadata.dev(), path_metadata.ino())) {
            return Err(Failure::task("WYR1 immutable input paths alias"));
        }
        let mut file = OpenOptions::new()
            .read(true)
            .custom_flags(O_NOFOLLOW)
            .open(source)
            .map_err(|error| {
                Failure::task(format!(
                    "could not open WYR1 immutable input {name}: {error}"
                ))
            })?;
        let metadata = file.metadata().map_err(|error| {
            Failure::task(format!(
                "could not stat WYR1 immutable input {name}: {error}"
            ))
        })?;
        if file_identity(&metadata) != file_identity(&path_metadata) {
            return Err(Failure::task(format!(
                "WYR1 immutable input {name} changed before opening"
            )));
        }
        let mut bytes = Vec::with_capacity(metadata.len() as usize);
        file.read_to_end(&mut bytes).map_err(|error| {
            Failure::task(format!(
                "could not read WYR1 immutable input {name}: {error}"
            ))
        })?;
        let opened_after = file.metadata().map_err(|error| {
            Failure::task(format!(
                "could not recheck opened WYR1 immutable input {name}: {error}"
            ))
        })?;
        let path_after = fs::symlink_metadata(source).map_err(|error| {
            Failure::task(format!(
                "could not recheck WYR1 immutable input {name}: {error}"
            ))
        })?;
        if file_identity(&metadata) != file_identity(&opened_after)
            || file_identity(&metadata) != file_identity(&path_after)
            || bytes.len() as u64 != metadata.len()
        {
            return Err(Failure::task(format!(
                "WYR1 immutable input {name} changed while snapshotting"
            )));
        }
        snapshots.push(write_snapshot(&directory.join(name), &bytes, 0o444)?);
    }
    let mut next = snapshots.into_iter();
    Ok(ImmutableInputs {
        request: next.next().unwrap(),
        receipt: next.next().unwrap(),
        loader: next.next().unwrap(),
        kernel: next.next().unwrap(),
        symbols: next.next().unwrap(),
        bootstrap: next.next().unwrap(),
        init: next.next().unwrap(),
        registryd: next.next().unwrap(),
        devmgr: next.next().unwrap(),
        uart16550d: next.next().unwrap(),
        consoled: next.next().unwrap(),
        wyrmsh: next.next().unwrap(),
        manifest: next.next().unwrap(),
        bootfs: next.next().unwrap(),
        esp: next.next().unwrap(),
        provenance: next.next().unwrap(),
        ovmf_code: next.next().unwrap(),
        ovmf_vars_template: next.next().unwrap(),
    })
}

fn file_identity(metadata: &fs::Metadata) -> (u64, u64, u64, i64, i64, i64, i64) {
    (
        metadata.dev(),
        metadata.ino(),
        metadata.len(),
        metadata.mtime(),
        metadata.mtime_nsec(),
        metadata.ctime(),
        metadata.ctime_nsec(),
    )
}

fn write_snapshot(path: &Path, bytes: &[u8], mode: u32) -> Result<Snapshot, Failure> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| Failure::task(format!("could not create WYR1 snapshot: {error}")))?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|error| Failure::task(format!("could not write WYR1 snapshot: {error}")))?;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
        .map_err(|error| Failure::task(format!("could not set WYR1 snapshot mode: {error}")))?;
    let metadata = file
        .metadata()
        .map_err(|error| Failure::task(format!("could not inspect WYR1 snapshot: {error}")))?;
    if !metadata.is_file() || metadata.nlink() != 1 || metadata.len() != bytes.len() as u64 {
        return Err(Failure::task(
            "WYR1 snapshot is not an exact single-link regular file",
        ));
    }
    Ok(Snapshot {
        path: path.to_path_buf(),
        sha256: sha256::bytes_digest(bytes),
    })
}

fn prepare_profile(
    request: &Request,
    inputs: &ImmutableInputs,
    root: &Path,
    profile: Profile,
) -> Result<PathBuf, Failure> {
    let directory = root.join(profile.name());
    create_directory(
        &directory,
        &format!("fresh WYR1 {} profile", profile.name()),
    )?;
    let vars_bytes = fs::read(&inputs.ovmf_vars_template.path)
        .map_err(|error| Failure::task(format!("could not read staged OVMF vars: {error}")))?;
    let vars = write_snapshot(&directory.join("OVMF_VARS.fd"), &vars_bytes, 0o600)?;
    let (vcpus, memory_mib) = match profile {
        Profile::Default => (1_u32, 1024_u32),
        Profile::Smp => (4, 2048),
    };
    let domain_xml_path = directory.join("domain.xml");
    let domain_xml = domain_xml(inputs, &vars, vcpus, memory_mib)?;
    let domain = write_snapshot(&domain_xml_path, domain_xml.as_bytes(), 0o444)?;
    let handoff_path = directory.join("handoff.toml");
    let handoff = handoff_text(
        request, inputs, &vars, &domain, &directory, profile, vcpus, memory_mib,
    )?;
    validate_handoff_keys(&handoff)?;
    write_snapshot(&handoff_path, handoff.as_bytes(), 0o444)?;
    Ok(handoff_path)
}

fn domain_xml(
    inputs: &ImmutableInputs,
    vars: &Snapshot,
    vcpus: u32,
    memory_mib: u32,
) -> Result<String, Failure> {
    let memory_kib = u64::from(memory_mib) * 1024;
    Ok(format!(
        "<domain xmlns:qemu=\"http://libvirt.org/schemas/domain/qemu/1.0\" type=\"qemu\">\n\
  <name>{DOMAIN_NAME}</name>\n\
  <uuid>{DOMAIN_UUID}</uuid>\n\
  <memory unit=\"KiB\">{memory_kib}</memory>\n\
  <currentMemory unit=\"KiB\">{memory_kib}</currentMemory>\n\
  <vcpu placement=\"static\">{vcpus}</vcpu>\n\
  <sysinfo type=\"fwcfg\">\n\
    <entry name=\"opt/org.deepwyrm.test.selector\">{}</entry>\n\
    <entry name=\"opt/org.deepwyrm.test.test_id\">{}</entry>\n\
  </sysinfo>\n\
  <os>\n\
    <type arch=\"x86_64\" machine=\"{DOMAIN_MACHINE}\">hvm</type>\n\
    <loader readonly=\"yes\" secure=\"no\" type=\"pflash\" format=\"raw\">{}</loader>\n\
    <nvram type=\"file\" format=\"raw\"><source file=\"{}\" fdgroup=\"{VARS_FD_GROUP}\"/></nvram>\n\
    <boot dev=\"hd\"/>\n\
  </os>\n\
  <features><acpi/><apic/></features>\n\
  <clock offset=\"utc\"><timer name=\"rtc\" tickpolicy=\"catchup\"/><timer name=\"pit\" tickpolicy=\"delay\"/><timer name=\"hpet\" present=\"no\"/></clock>\n\
  <on_poweroff>destroy</on_poweroff>\n\
  <on_reboot>restart</on_reboot>\n\
  <on_crash>destroy</on_crash>\n\
  <pm><suspend-to-mem enabled=\"no\"/><suspend-to-disk enabled=\"no\"/></pm>\n\
  <devices>\n\
    <emulator>{QEMU_PATH}</emulator>\n\
    <disk type=\"file\" device=\"disk\"><driver name=\"qemu\" type=\"raw\"/><source file=\"{}\" fdgroup=\"{ESP_FD_GROUP}\"/><target dev=\"vda\" bus=\"virtio\"/><readonly/></disk>\n\
    <controller type=\"pci\" index=\"0\" model=\"pcie-root\"/>\n\
    <serial type=\"pty\"><target type=\"isa-serial\" port=\"0\"/></serial>\n\
    <console type=\"pty\"><target type=\"serial\" port=\"0\"/></console>\n\
  </devices>\n\
  <qemu:commandline>\n\
    <qemu:arg value=\"-device\"/>\n\
    <qemu:arg value=\"isa-debug-exit,iobase=0xf4,iosize=0x04\"/>\n\
  </qemu:commandline>\n\
</domain>\n",
        wyr1::SELECTOR,
        wyr1::TEST_ID,
        xml_path(&inputs.ovmf_code.path)?,
        xml_path(&vars.path)?,
        xml_path(&inputs.esp.path)?,
    ))
}

#[allow(clippy::too_many_arguments)]
fn handoff_text(
    request: &Request,
    inputs: &ImmutableInputs,
    vars: &Snapshot,
    domain: &Snapshot,
    directory: &Path,
    profile: Profile,
    vcpus: u32,
    memory_mib: u32,
) -> Result<String, Failure> {
    let terminal = match request.scenario {
        wyr1::Scenario::Normal => "NORMAL",
        wyr1::Scenario::DegradedRecovery => "DEGRADED",
    };
    let mut fields = vec![
        (
            "schema_version".to_owned(),
            HANDOFF_SCHEMA_VERSION.to_string(),
        ),
        ("kind".to_owned(), HANDOFF_KIND.to_owned()),
        ("profile".to_owned(), profile.name().to_owned()),
        ("vcpus".to_owned(), vcpus.to_string()),
        ("memory_mib".to_owned(), memory_mib.to_string()),
        ("machine".to_owned(), DOMAIN_MACHINE.to_owned()),
        ("firmware".to_owned(), "OVMF".to_owned()),
        (
            "request_schema_version".to_owned(),
            wyr1::SCHEMA_VERSION.to_string(),
        ),
        ("request_path".to_owned(), path_text(&inputs.request.path)?),
        ("request_sha256".to_owned(), inputs.request.sha256.clone()),
        ("receipt_path".to_owned(), path_text(&inputs.receipt.path)?),
        ("receipt_sha256".to_owned(), inputs.receipt.sha256.clone()),
        (
            "deepwyrm_revision".to_owned(),
            request.deepwyrm_revision.clone(),
        ),
        (
            "wyrmroot_revision".to_owned(),
            request.wyrmroot_revision.clone(),
        ),
        ("rust_revision".to_owned(), request.rust_revision.clone()),
        ("scenario".to_owned(), request.scenario.name().to_owned()),
        ("selector".to_owned(), wyr1::SELECTOR.to_owned()),
        ("test_id".to_owned(), wyr1::TEST_ID.to_string()),
        (
            "timeout_seconds".to_owned(),
            request.timeout_seconds.to_string(),
        ),
        (
            "evidence_nonce".to_owned(),
            format!("{:016X}", request.evidence_nonce),
        ),
        ("evidence_protocol".to_owned(), "WYR1EVID1".to_owned()),
        ("expected_evidence_terminal".to_owned(), terminal.to_owned()),
        ("kernel_result_protocol".to_owned(), "DWTEST1".to_owned()),
        (
            "kernel_result_test_id".to_owned(),
            wyr1::TEST_ID.to_string(),
        ),
        (
            "gate_config_sha256".to_owned(),
            sha256::bytes_digest(&wyr1::gate_config_for_request(request)),
        ),
        (
            "com1".to_owned(),
            "kernel-diagnostics-host-capture".to_owned(),
        ),
        ("com2".to_owned(), "absent-phase-a".to_owned()),
        ("network".to_owned(), "none".to_owned()),
        ("host_shares".to_owned(), "none".to_owned()),
        ("system_disk".to_owned(), "absent-phase-a".to_owned()),
        ("domain_xml_path".to_owned(), path_text(&domain.path)?),
        ("domain_xml_sha256".to_owned(), domain.sha256.clone()),
        ("ovmf_vars_path".to_owned(), path_text(&vars.path)?),
        ("ovmf_vars_initial_sha256".to_owned(), vars.sha256.clone()),
        (
            "serial_log_path".to_owned(),
            path_text(&directory.join("serial.log"))?,
        ),
        (
            "evidence_log_path".to_owned(),
            path_text(&directory.join("evidence.log"))?,
        ),
        (
            "result_json_path".to_owned(),
            path_text(&directory.join("result.json"))?,
        ),
    ];
    for (label, snapshot) in [
        ("loader", &inputs.loader),
        ("kernel", &inputs.kernel),
        ("symbols", &inputs.symbols),
        ("bootstrap", &inputs.bootstrap),
        ("init", &inputs.init),
        ("registryd", &inputs.registryd),
        ("devmgr", &inputs.devmgr),
        ("uart16550d", &inputs.uart16550d),
        ("consoled", &inputs.consoled),
        ("wyrmsh", &inputs.wyrmsh),
        ("rrc_manifest", &inputs.manifest),
        ("bootfs", &inputs.bootfs),
        ("esp", &inputs.esp),
        ("provenance", &inputs.provenance),
        ("ovmf_code", &inputs.ovmf_code),
        ("ovmf_vars_template", &inputs.ovmf_vars_template),
    ] {
        fields.push((format!("{label}_path"), path_text(&snapshot.path)?));
        fields.push((format!("{label}_sha256"), snapshot.sha256.clone()));
    }
    let mut seen = BTreeSet::new();
    let mut lines = Vec::with_capacity(fields.len());
    for (key, value) in fields {
        if !seen.insert(key.clone()) {
            return Err(Failure::task(
                "WYR1 VM handoff key set contains a duplicate",
            ));
        }
        lines.push(format!("{key} = \"{}\"", toml_escape(&value)?));
    }
    Ok(format!("{}\n", lines.join("\n")))
}

fn expected_handoff_keys() -> BTreeSet<String> {
    let mut keys = [
        "schema_version",
        "kind",
        "profile",
        "vcpus",
        "memory_mib",
        "machine",
        "firmware",
        "request_schema_version",
        "request_path",
        "request_sha256",
        "receipt_path",
        "receipt_sha256",
        "deepwyrm_revision",
        "wyrmroot_revision",
        "rust_revision",
        "scenario",
        "selector",
        "test_id",
        "timeout_seconds",
        "evidence_nonce",
        "evidence_protocol",
        "expected_evidence_terminal",
        "kernel_result_protocol",
        "kernel_result_test_id",
        "gate_config_sha256",
        "com1",
        "com2",
        "network",
        "host_shares",
        "system_disk",
        "domain_xml_path",
        "domain_xml_sha256",
        "ovmf_vars_path",
        "ovmf_vars_initial_sha256",
        "serial_log_path",
        "evidence_log_path",
        "result_json_path",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect::<BTreeSet<_>>();
    for label in [
        "loader",
        "kernel",
        "symbols",
        "bootstrap",
        "init",
        "registryd",
        "devmgr",
        "uart16550d",
        "consoled",
        "wyrmsh",
        "rrc_manifest",
        "bootfs",
        "esp",
        "provenance",
        "ovmf_code",
        "ovmf_vars_template",
    ] {
        keys.insert(format!("{label}_path"));
        keys.insert(format!("{label}_sha256"));
    }
    keys
}

fn validate_handoff_keys(text: &str) -> Result<(), Failure> {
    let mut keys = BTreeSet::new();
    for (line_number, line) in text.lines().enumerate() {
        let (key, value) = line.split_once(" = ").ok_or_else(|| {
            Failure::task(format!(
                "WYR1 VM handoff line {} is not canonical",
                line_number + 1
            ))
        })?;
        if !key
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
            || !value.starts_with('"')
            || !value.ends_with('"')
            || !keys.insert(key.to_owned())
        {
            return Err(Failure::task(format!(
                "WYR1 VM handoff line {} has an invalid key or scalar",
                line_number + 1
            )));
        }
    }
    if keys != expected_handoff_keys() {
        return Err(Failure::task("WYR1 VM handoff key set drifted"));
    }
    Ok(())
}

fn path_text(path: &Path) -> Result<String, Failure> {
    path.to_str()
        .map(str::to_owned)
        .ok_or_else(|| Failure::task("WYR1 VM handoff path is not UTF-8"))
}

fn toml_escape(value: &str) -> Result<String, Failure> {
    if value.chars().any(char::is_control) {
        return Err(Failure::task(
            "WYR1 VM handoff scalar contains a control character",
        ));
    }
    Ok(value.replace('\\', "\\\\").replace('"', "\\\""))
}

fn xml_path(path: &Path) -> Result<String, Failure> {
    let value = path_text(path)?;
    if value.chars().any(char::is_control) {
        return Err(Failure::task(
            "WYR1 domain XML path contains a control character",
        ));
    }
    Ok(value
        .replace('&', "&amp;")
        .replace('"', "&quot;")
        .replace('<', "&lt;")
        .replace('>', "&gt;"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_root(name: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../target")
            .join(format!(
                "xtask-wyr1-vm-{name}-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ))
    }

    fn fixture_request(root: &Path) -> Request {
        fs::create_dir_all(root).unwrap();
        let request_path = root.join("request.toml");
        fs::write(&request_path, b"schema-5-request\n").unwrap();
        let file = |name: &str| {
            let path = root.join(name);
            fs::write(&path, format!("fixture-{name}\n")).unwrap();
            path
        };
        let request = Request {
            path: request_path.clone(),
            request_sha256: sha256::file_digest(&request_path).unwrap(),
            deepwyrm_revision: "1".repeat(40),
            wyrmroot_revision: "2".repeat(40),
            rust_revision: "3".repeat(40),
            selector: wyr1::SELECTOR.to_owned(),
            test_id: wyr1::TEST_ID,
            scenario: wyr1::Scenario::Normal,
            timeout_seconds: 180,
            loader: file("loader.efi"),
            kernel: file("deepwyrm.elf"),
            symbols: file("deepwyrm.symbols"),
            bootstrap: file("bootstrap.elf"),
            init: file("system-init.elf"),
            registryd: file("registryd.elf"),
            devmgr: file("devmgr.elf"),
            uart16550d: file("uart16550d.elf"),
            consoled: file("consoled.elf"),
            wyrmsh: file("wyrmsh.elf"),
            rrc_manifest: file("rrc-a-v1.bin"),
            bootfs: file("bootfs.img"),
            esp: file("esp.img"),
            provenance: file("provenance.toml"),
            ovmf_code: file("OVMF_CODE.fd"),
            ovmf_vars_template: file("OVMF_VARS_TEMPLATE.fd"),
            run_directory: root.join("runs"),
            evidence_nonce: 0x0123_4567_89ab_cdef,
            receipt: root.join("build-receipt.toml"),
        };
        let receipt = wyr1::receipt_text(
            &request,
            &wyr1::ProductIdentities {
                manifest_expected: sha256::file_digest(&request.rrc_manifest).unwrap(),
                manifest_observed: sha256::file_digest(&request.rrc_manifest).unwrap(),
                bootfs_expected: sha256::file_digest(&request.bootfs).unwrap(),
                bootfs_observed: sha256::file_digest(&request.bootfs).unwrap(),
            },
            &sha256::file_digest(&request.esp).unwrap(),
            Profile::Default,
        )
        .unwrap();
        wyr1::write_receipt(&request, &receipt).unwrap();
        request
    }

    #[test]
    fn domain_profiles_are_exact_and_phase_a_only() {
        let root = PathBuf::from("/tmp/wyr1-vm-profile");
        let snapshot = |name: &str| Snapshot {
            path: root.join(name),
            sha256: "a".repeat(64),
        };
        let inputs = ImmutableInputs {
            request: snapshot("request"),
            receipt: snapshot("receipt"),
            loader: snapshot("loader"),
            kernel: snapshot("kernel"),
            symbols: snapshot("symbols"),
            bootstrap: snapshot("bootstrap"),
            init: snapshot("init"),
            registryd: snapshot("registryd"),
            devmgr: snapshot("devmgr"),
            uart16550d: snapshot("uart"),
            consoled: snapshot("console"),
            wyrmsh: snapshot("shell"),
            manifest: snapshot("manifest"),
            bootfs: snapshot("bootfs"),
            esp: snapshot("esp"),
            provenance: snapshot("provenance"),
            ovmf_code: snapshot("code"),
            ovmf_vars_template: snapshot("template"),
        };
        let vars = snapshot("vars");
        let default = domain_xml(&inputs, &vars, 1, 1024).unwrap();
        let smp = domain_xml(&inputs, &vars, 4, 2048).unwrap();
        assert!(default.contains("<memory unit=\"KiB\">1048576</memory>"));
        assert!(default.contains("<vcpu placement=\"static\">1</vcpu>"));
        assert!(smp.contains("<memory unit=\"KiB\">2097152</memory>"));
        assert!(smp.contains("<vcpu placement=\"static\">4</vcpu>"));
        for xml in [default, smp] {
            assert_eq!(xml.matches("<disk ").count(), 1);
            assert_eq!(xml.matches("<serial ").count(), 1);
            assert!(!xml.contains("interface"));
            assert!(!xml.contains("filesystem"));
            assert!(!xml.contains("qcow2"));
            assert!(!xml.contains("port=\"1\""));
            assert!(xml.contains("isa-debug-exit,iobase=0xf4,iosize=0x04"));
        }
    }

    #[test]
    fn scalar_and_xml_escaping_are_deterministic() {
        assert_eq!(toml_escape("a\\b\"c").unwrap(), "a\\\\b\\\"c");
        assert_eq!(
            xml_path(Path::new("/tmp/a&b<c>\"d")).unwrap(),
            "/tmp/a&amp;b&lt;c&gt;&quot;d"
        );
        assert!(toml_escape("bad\nvalue").is_err());
    }

    #[test]
    fn handoff_schema_rejects_missing_unknown_and_duplicate_keys() {
        let canonical = expected_handoff_keys()
            .into_iter()
            .map(|key| format!("{key} = \"value\"\n"))
            .collect::<String>();
        validate_handoff_keys(&canonical).unwrap();
        let missing = canonical.replacen("bootfs_path = \"value\"\n", "", 1);
        assert!(validate_handoff_keys(&missing).is_err());
        let unknown = format!("{canonical}unknown = \"value\"\n");
        assert!(validate_handoff_keys(&unknown).is_err());
        let duplicate = format!("{canonical}profile = \"smp\"\n");
        assert!(validate_handoff_keys(&duplicate).is_err());
    }

    #[test]
    fn preparation_joins_identities_and_is_reproducible() {
        let root = fixture_root("reproducible");
        let request = fixture_request(&root);
        wyr1::verify_receipt(&request, Profile::Default).unwrap();
        let first = prepare(&request).unwrap();
        let default_text = fs::read(&first.default).unwrap();
        let smp_text = fs::read(&first.smp).unwrap();
        let default_xml = fs::read(root.join("runs/default/domain.xml")).unwrap();
        let smp_xml = fs::read(root.join("runs/smp/domain.xml")).unwrap();
        assert_eq!(first.esp_sha256, sha256::file_digest(&request.esp).unwrap());
        let default = String::from_utf8(default_text.clone()).unwrap();
        let smp = String::from_utf8(smp_text.clone()).unwrap();
        assert!(default.contains("profile = \"default\""));
        assert!(default.contains("vcpus = \"1\""));
        assert!(smp.contains("profile = \"smp\""));
        assert!(smp.contains("vcpus = \"4\""));
        let esp_path = fs::canonicalize(&root)
            .unwrap()
            .join("runs/immutable/esp.img");
        let expected_path = format!("esp_path = \"{}\"", esp_path.display());
        assert!(default.contains(&expected_path));
        assert!(smp.contains(&expected_path));
        let vars_metadata = fs::metadata(root.join("runs/default/OVMF_VARS.fd")).unwrap();
        assert_eq!(vars_metadata.nlink(), 1);
        assert_ne!(vars_metadata.permissions().mode() & 0o200, 0);

        fs::remove_dir_all(root.join("runs")).unwrap();
        let second = prepare(&request).unwrap();
        assert_eq!(default_text, fs::read(second.default).unwrap());
        assert_eq!(smp_text, fs::read(second.smp).unwrap());
        assert_eq!(
            default_xml,
            fs::read(root.join("runs/default/domain.xml")).unwrap()
        );
        assert_eq!(smp_xml, fs::read(root.join("runs/smp/domain.xml")).unwrap());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn receipt_rejects_expected_observed_product_identity_mismatches() {
        let root = fixture_root("receipt-identity-mismatch");
        let request = fixture_request(&root);
        let actual_bootfs = sha256::file_digest(&request.bootfs).unwrap();
        let replacement = if actual_bootfs == "a".repeat(64) {
            "b".repeat(64)
        } else {
            "a".repeat(64)
        };
        let receipt = fs::read_to_string(&request.receipt).unwrap();
        let receipt = receipt
            .replace(
                &format!("bootfs_sha256 = \"{actual_bootfs}\""),
                &format!("bootfs_sha256 = \"{replacement}\""),
            )
            .replace(
                &format!("bootfs_expected_sha256 = \"{actual_bootfs}\""),
                &format!("bootfs_expected_sha256 = \"{replacement}\""),
            );
        fs::write(&request.receipt, receipt).unwrap();
        assert_eq!(
            wyr1::verify_receipt(&request, Profile::Default)
                .unwrap_err()
                .message,
            "WYR1 bootfs expected/observed receipt identity mismatch"
        );
    }

    #[test]
    fn preparation_rejects_tamper_alias_and_noncanonical_output() {
        let tamper_root = fixture_root("tamper");
        let tampered = fixture_request(&tamper_root);
        fs::write(&tampered.path, b"tampered-request\n").unwrap();
        assert!(prepare(&tampered).is_err());
        fs::remove_dir_all(tamper_root).unwrap();

        let alias_root = fixture_root("alias");
        let aliased = fixture_request(&alias_root);
        fs::remove_file(&aliased.symbols).unwrap();
        fs::hard_link(&aliased.kernel, &aliased.symbols).unwrap();
        assert!(prepare(&aliased).is_err());
        fs::remove_dir_all(alias_root).unwrap();

        let path_root = fixture_root("path");
        let mut noncanonical = fixture_request(&path_root);
        noncanonical.run_directory = path_root.join("out/../runs");
        assert!(prepare(&noncanonical).is_err());
        fs::remove_dir_all(path_root).unwrap();
    }
}
