//! DW1-E3A selector-31 request, VM-handoff, and partial-evidence grammar.
//!
//! E3A deliberately stops after sequence 8: one production raw COM2
//! challenge/response round trip. It cannot emit or accept the 26-record
//! terminal, a `DWTEST1` line, or an acceptance receipt.

#![allow(dead_code)]

use std::collections::{BTreeMap, BTreeSet};

use crate::{error::Failure, sha256};

pub(crate) const SELECTOR: &str = "q35-uart-com2-one-round-trip";
pub(crate) const TEST_ID: &str = "31";
pub(crate) const EVIDENCE_PROTOCOL: &str = "DWE3E1";
pub(crate) const REQUEST_KIND: &str = "wyrmroot-dw1-e3a-selector31-request";
pub(crate) const HANDOFF_KIND: &str = "wyrmroot-dw1-e3a-selector31-vm-handoff";
pub(crate) const PROFILE_PAIR_KIND: &str = "wyrmroot-dw1-e3a-selector31-vm-profile-pair";
pub(crate) const RECEIPT_KIND: &str = "wyrmroot-dw1-e3a-selector31-receipt";
pub(crate) const SOURCE_RECEIPT_KIND: &str = "wyrmroot-dw1-e3a-selector31-source-build";
pub(crate) const PARTIAL_RESULT_KIND: &str = "wyrmroot-dw1-e3a-selector31-partial-result";
pub(crate) const READINESS_MARKER: &str =
    "DWE3READY|01|<NONCE16>|<STREAM16>|<CHALLENGE16>|<FNV16>|<FNV32>";
pub(crate) const ACCEPTANCE_CLAIM: &str = "partial-non-acceptance";
pub(crate) const TIMEOUT_SECONDS: &str = "120";

/// Producer-owned entry into the accepted native product builder. The
/// request freezer consumes this snapshot together with its kernel/firmware
/// inputs; callers cannot substitute a sixth normal role for the probe.
pub(crate) fn build_product_snapshot(nonce: &str) -> Result<crate::wyr1c::E3ASnapshot, Failure> {
    crate::wyr1c::build_e3a_snapshot(nonce)
}

pub(crate) const ARTIFACTS: &[(&str, &str)] = &[
    ("loader", "loader.efi"),
    ("kernel", "deepwyrm.elf"),
    ("symbols", "deepwyrm.symbols.elf"),
    ("bootstrap", "bootstrap.elf"),
    ("system_init", "system-init.elf"),
    ("registryd", "registryd.elf"),
    ("devmgr", "devmgr.elf"),
    ("uart16550d", "uart16550d.elf"),
    ("consoled", "consoled.elf"),
    ("wyrmsh", "wyrmsh.elf"),
    ("dw1e3_com2_test", "dw1e3-com2-test.elf"),
    ("rrc_manifest", "rrc-e3a-v1.bin"),
    ("device_manifest", "wrdm-e3a-v1.bin"),
    ("boot_device_table", "boot-device-table.bin"),
    ("bootfs", "bootfs.img"),
    ("ovmf_code", "OVMF_CODE.fd"),
    ("ovmf_vars", "OVMF_VARS.fd"),
];

pub(crate) const REQUEST_KEYS: &[&str] = &[
    "kind",
    "schema_version",
    "selector",
    "test_id",
    "profile",
    "scenario",
    "evidence_protocol",
    "partial_evidence",
    "acceptance_claim",
    "readiness_marker",
    "deepwyrm_revision",
    "generated_abi_revision",
    "generated_abi_tree",
    "wyrmroot_revision",
    "rust_revision",
    "evidence_nonce",
    "challenge_hex",
    "challenge_length",
    "challenge_fnv1a64",
    "challenge_sha256",
    "response_hex",
    "response_length",
    "response_fnv1a64",
    "response_sha256",
    "loader",
    "loader_sha256",
    "kernel",
    "kernel_sha256",
    "symbols",
    "symbols_sha256",
    "bootstrap",
    "bootstrap_sha256",
    "system_init",
    "system_init_sha256",
    "registryd",
    "registryd_sha256",
    "devmgr",
    "devmgr_sha256",
    "uart16550d",
    "uart16550d_sha256",
    "consoled",
    "consoled_sha256",
    "wyrmsh",
    "wyrmsh_sha256",
    "dw1e3_com2_test",
    "dw1e3_com2_test_sha256",
    "rrc_manifest",
    "rrc_manifest_sha256",
    "device_manifest",
    "device_manifest_sha256",
    "boot_device_table",
    "boot_device_table_sha256",
    "bootfs",
    "bootfs_sha256",
    "ovmf_code",
    "ovmf_code_sha256",
    "ovmf_vars",
    "ovmf_vars_sha256",
    "esp",
    "esp_sha256",
    "default_handoff",
    "default_handoff_sha256",
    "smp_handoff",
    "smp_handoff_sha256",
    "profile_pair",
    "receipt",
    "source_receipt",
    "source_receipt_sha256",
];

pub(crate) const HANDOFF_KEYS: &[&str] = &[
    "kind",
    "schema_version",
    "profile",
    "selector",
    "test_id",
    "evidence_protocol",
    "partial_evidence",
    "acceptance_claim",
    "request",
    "request_sha256",
    "esp",
    "esp_sha256",
    "vcpus",
    "memory_mib",
    "machine",
    "firmware",
    "timeout_seconds",
    "scenario",
    "physical_io",
    "terminal_authority",
    "com1_role",
    "com2_role",
    "com2_transport",
    "com1_fd_group",
    "com2_fd_group",
    "esp_fd_group",
    "vars_fd_group",
    "domain_xml",
    "domain_xml_sha256",
    "mutable_ovmf_vars",
    "mutable_ovmf_vars_initial_sha256",
    "com2_socket",
    "com1_serial_log",
    "com2_log",
    "partial_evidence_log",
    "result_path",
    "absent_receipt",
    "readiness_marker",
    "challenge_hex",
    "expected_response_hex",
    "loader",
    "loader_sha256",
    "kernel",
    "kernel_sha256",
    "symbols",
    "symbols_sha256",
    "bootstrap",
    "bootstrap_sha256",
    "system_init",
    "system_init_sha256",
    "registryd",
    "registryd_sha256",
    "devmgr",
    "devmgr_sha256",
    "uart16550d",
    "uart16550d_sha256",
    "consoled",
    "consoled_sha256",
    "wyrmsh",
    "wyrmsh_sha256",
    "dw1e3_com2_test",
    "dw1e3_com2_test_sha256",
    "rrc_manifest",
    "rrc_manifest_sha256",
    "device_manifest",
    "device_manifest_sha256",
    "boot_device_table",
    "boot_device_table_sha256",
    "bootfs",
    "bootfs_sha256",
    "ovmf_code",
    "ovmf_code_sha256",
    "ovmf_vars",
    "ovmf_vars_sha256",
];

pub(crate) const PROFILE_PAIR_KEYS: &[&str] = &[
    "kind",
    "schema_version",
    "selector",
    "test_id",
    "evidence_protocol",
    "partial_evidence",
    "acceptance_claim",
    "request",
    "request_sha256",
    "profiles",
    "default_handoff",
    "default_handoff_sha256",
    "default_vcpus",
    "smp_handoff",
    "smp_handoff_sha256",
    "smp_vcpus",
    "memory_mib",
    "machine",
    "firmware",
    "timeout_seconds",
];

pub(crate) fn render_request(values: &BTreeMap<String, String>) -> Result<String, Failure> {
    require(values, "kind", REQUEST_KIND)?;
    require(values, "schema_version", "1")?;
    require(values, "selector", SELECTOR)?;
    require(values, "test_id", TEST_ID)?;
    require(values, "profile", "dw1e3a-selector31")?;
    require(values, "scenario", "one-production-raw-com2-round-trip")?;
    require(values, "evidence_protocol", EVIDENCE_PROTOCOL)?;
    require(values, "partial_evidence", "true")?;
    require(values, "acceptance_claim", ACCEPTANCE_CLAIM)?;
    require(values, "readiness_marker", READINESS_MARKER)?;
    require(values, "challenge_length", "24")?;
    require(values, "response_length", "24")?;
    require(values, "default_handoff", "default/handoff.toml")?;
    require(values, "smp_handoff", "smp/handoff.toml")?;
    require(values, "profile_pair", "profile-pair.toml")?;
    require(values, "receipt", "build-receipt.toml")?;
    require(values, "source_receipt", "artifacts/e3a-source-build.toml")?;
    reject_terminal(values)?;
    render(values, REQUEST_KEYS)
}

pub(crate) fn render_handoff(values: &BTreeMap<String, String>) -> Result<String, Failure> {
    require(values, "kind", HANDOFF_KIND)?;
    let profile = value(values, "profile")?;
    let expected_vcpus = match profile {
        "default" => "1",
        "smp" => "4",
        _ => {
            return Err(Failure::task(
                "DW1-E3A handoff profile must be default or smp",
            ));
        }
    };
    for (key, expected) in [
        ("schema_version", "1"),
        ("selector", SELECTOR),
        ("test_id", TEST_ID),
        ("evidence_protocol", EVIDENCE_PROTOCOL),
        ("partial_evidence", "true"),
        ("acceptance_claim", ACCEPTANCE_CLAIM),
        ("vcpus", expected_vcpus),
        ("memory_mib", "2048"),
        ("machine", "pc-q35-10.2"),
        ("firmware", "OVMF"),
        ("timeout_seconds", TIMEOUT_SECONDS),
        ("scenario", "one-production-raw-com2-round-trip"),
        ("physical_io", "real-com2-irq3-intended"),
        ("terminal_authority", "deepwyrm-selector31-partial-only"),
        ("com1_role", "trusted-evidence-and-readiness"),
        ("com2_role", "raw-challenge-response"),
        ("com2_transport", "unix-socket-byte-stream"),
        ("com1_fd_group", "dw-e3a-com1-evidence-v1"),
        ("com2_fd_group", "dw-e3a-com2-raw-v1"),
        ("esp_fd_group", "dw-f13-esp-v1"),
        ("vars_fd_group", "dw-f13-ovmf-vars-v1"),
        ("domain_xml", "domain.xml"),
        ("mutable_ovmf_vars", "OVMF_VARS.mutable.fd"),
        ("com2_socket", "com2.sock"),
        ("com1_serial_log", "com1.log"),
        ("com2_log", "com2.bin"),
        ("partial_evidence_log", "partial-evidence.log"),
        ("result_path", "result.toml"),
        ("absent_receipt", "acceptance-receipt.toml"),
        ("readiness_marker", READINESS_MARKER),
    ] {
        require(values, key, expected)?;
    }
    reject_terminal(values)?;
    render(values, HANDOFF_KEYS)
}

pub(crate) fn render_profile_pair(values: &BTreeMap<String, String>) -> Result<String, Failure> {
    for (key, expected) in [
        ("kind", PROFILE_PAIR_KIND),
        ("schema_version", "1"),
        ("selector", SELECTOR),
        ("test_id", TEST_ID),
        ("evidence_protocol", EVIDENCE_PROTOCOL),
        ("partial_evidence", "true"),
        ("acceptance_claim", ACCEPTANCE_CLAIM),
        ("profiles", "default,smp"),
        ("default_handoff", "default/handoff.toml"),
        ("default_vcpus", "1"),
        ("smp_handoff", "smp/handoff.toml"),
        ("smp_vcpus", "4"),
        ("memory_mib", "2048"),
        ("machine", "pc-q35-10.2"),
        ("firmware", "OVMF"),
        ("timeout_seconds", TIMEOUT_SECONDS),
    ] {
        require(values, key, expected)?;
    }
    reject_terminal(values)?;
    render(values, PROFILE_PAIR_KEYS)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PartialEvidence {
    pub(crate) records: usize,
    pub(crate) sha256: String,
    pub(crate) stream_generation: u64,
    pub(crate) challenge_generation: u64,
}

pub(crate) fn parse_partial_evidence(
    bytes: &[u8],
    nonce: &str,
    challenge_length: u64,
    challenge_fnv1a64: u64,
    response_length: u64,
    response_fnv1a64: u64,
) -> Result<PartialEvidence, Failure> {
    if nonce.len() != 16 || bytes.len() != 9 * 204 || bytes.windows(7).any(|w| w == b"DWTEST1") {
        return Err(Failure::task(
            "DW1-E3A evidence is not the exact nine-record partial prefix",
        ));
    }
    let events = [1u8, 2, 3, 4, 5, 6, 7, 8, 9];
    let actors = [0u8, 0, 0, 0, 0, 0, 1, 0, 2];
    let mut joined = None;
    for sequence in 0..9 {
        let record = &bytes[sequence * 204..(sequence + 1) * 204];
        if &record[..6] != b"DWE3E1"
            || &record[7..9] != b"01"
            || record[203] != b'\n'
            || &record[10..26] != nonce.as_bytes()
            || parse_hex(&record[27..35])? != sequence as u64
            || parse_hex(&record[36..38])? != u64::from(events[sequence])
            || parse_hex(&record[39..41])? != u64::from(actors[sequence])
            || parse_hex(&record[195..203])? != u64::from(fnv1a32(&record[..195]))
        {
            return Err(Failure::task("DW1-E3A partial evidence record drifted"));
        }
        let stream = parse_hex(&record[127..143])?;
        let challenge = parse_hex(&record[144..160])?;
        if sequence >= 3 {
            if stream == 0
                || challenge == 0
                || joined.is_some_and(|pair| pair != (stream, challenge))
            {
                return Err(Failure::task("DW1-E3A stream/challenge join drifted"));
            }
            joined = Some((stream, challenge));
        }
        let value = parse_hex(&record[161..177])?;
        let auxiliary = parse_hex(&record[178..194])?;
        if (sequence == 6 && (value != challenge_length || auxiliary != challenge_fnv1a64))
            || (sequence == 8 && (value != response_length || auxiliary != response_fnv1a64))
        {
            return Err(Failure::task("DW1-E3A raw payload evidence drifted"));
        }
    }
    let (stream_generation, challenge_generation) =
        joined.ok_or_else(|| Failure::task("DW1-E3A partial evidence lacks an attached stream"))?;
    Ok(PartialEvidence {
        records: 9,
        sha256: sha256::bytes_digest(bytes),
        stream_generation,
        challenge_generation,
    })
}

fn reject_terminal(values: &BTreeMap<String, String>) -> Result<(), Failure> {
    if values.iter().any(|(key, value)| {
        key.contains("terminal") && key != "terminal_authority"
            || value.contains("DWTEST1")
            || value.contains("26-record")
    }) {
        return Err(Failure::task(
            "DW1-E3A cannot claim selector terminal acceptance",
        ));
    }
    Ok(())
}

fn render(values: &BTreeMap<String, String>, keys: &[&str]) -> Result<String, Failure> {
    let expected: BTreeSet<_> = keys.iter().copied().collect();
    let actual: BTreeSet<_> = values.keys().map(String::as_str).collect();
    if actual != expected {
        return Err(Failure::task("DW1-E3A schema key set drifted"));
    }
    let mut output = String::new();
    for key in keys {
        let escaped = value(values, key)?
            .replace('\\', "\\\\")
            .replace('"', "\\\"");
        output.push_str(key);
        output.push_str(" = \"");
        output.push_str(&escaped);
        output.push_str("\"\n");
    }
    Ok(output)
}

fn require(values: &BTreeMap<String, String>, key: &str, expected: &str) -> Result<(), Failure> {
    if value(values, key)? != expected {
        return Err(Failure::task(format!("DW1-E3A {key} drifted")));
    }
    Ok(())
}

fn value<'a>(values: &'a BTreeMap<String, String>, key: &str) -> Result<&'a str, Failure> {
    values
        .get(key)
        .map(String::as_str)
        .ok_or_else(|| Failure::task(format!("DW1-E3A omitted {key}")))
}

fn parse_hex(bytes: &[u8]) -> Result<u64, Failure> {
    let mut value = 0u64;
    for byte in bytes {
        let digit = match byte {
            b'0'..=b'9' => u64::from(byte - b'0'),
            b'A'..=b'F' => u64::from(byte - b'A' + 10),
            _ => return Err(Failure::task("DW1-E3A evidence hex is malformed")),
        };
        value = value
            .checked_mul(16)
            .and_then(|value| value.checked_add(digit))
            .ok_or_else(|| Failure::task("DW1-E3A evidence hex overflow"))?;
    }
    Ok(value)
}

const fn fnv1a32(bytes: &[u8]) -> u32 {
    let mut hash = 0x811c_9dc5u32;
    let mut index = 0;
    while index < bytes.len() {
        hash ^= bytes[index] as u32;
        hash = hash.wrapping_mul(0x0100_0193);
        index += 1;
    }
    hash
}

#[cfg(test)]
mod tests {
    use super::*;

    fn values(keys: &[&str]) -> BTreeMap<String, String> {
        keys.iter()
            .map(|key| ((*key).to_owned(), "x".to_owned()))
            .collect()
    }

    fn fixed_request() -> BTreeMap<String, String> {
        let mut map = values(REQUEST_KEYS);
        for (key, value) in [
            ("kind", REQUEST_KIND),
            ("schema_version", "1"),
            ("selector", SELECTOR),
            ("test_id", TEST_ID),
            ("profile", "dw1e3a-selector31"),
            ("scenario", "one-production-raw-com2-round-trip"),
            ("evidence_protocol", EVIDENCE_PROTOCOL),
            ("partial_evidence", "true"),
            ("acceptance_claim", ACCEPTANCE_CLAIM),
            ("readiness_marker", READINESS_MARKER),
            ("challenge_length", "24"),
            ("response_length", "24"),
            ("default_handoff", "default/handoff.toml"),
            ("smp_handoff", "smp/handoff.toml"),
            ("profile_pair", "profile-pair.toml"),
            ("receipt", "build-receipt.toml"),
            ("source_receipt", "artifacts/e3a-source-build.toml"),
        ] {
            map.insert(key.into(), value.into());
        }
        map
    }

    fn put_hex(output: &mut [u8], value: u64) {
        let width = output.len();
        for (index, byte) in output.iter_mut().enumerate() {
            let shift = (width - 1 - index) * 4;
            *byte = b"0123456789ABCDEF"[((value >> shift) & 0xf) as usize];
        }
    }

    fn record(sequence: usize, challenge_fnv: u64, response_fnv: u64) -> [u8; 204] {
        let mut bytes = [b'0'; 204];
        bytes[..6].copy_from_slice(b"DWE3E1");
        for delimiter in [
            6, 9, 26, 35, 38, 41, 58, 75, 92, 109, 126, 143, 160, 177, 194,
        ] {
            bytes[delimiter] = b'|';
        }
        bytes[7..9].copy_from_slice(b"01");
        bytes[10..26].copy_from_slice(b"0123456789ABCDEF");
        put_hex(&mut bytes[27..35], sequence as u64);
        put_hex(&mut bytes[36..38], (sequence + 1) as u64);
        put_hex(&mut bytes[39..41], [0u64, 0, 0, 0, 0, 0, 1, 0, 2][sequence]);
        if sequence != 0 {
            for range in [42..58, 59..75, 76..92, 93..109, 110..126] {
                put_hex(&mut bytes[range], 1);
            }
        }
        if sequence >= 3 {
            put_hex(&mut bytes[127..143], 7);
            put_hex(&mut bytes[144..160], 1);
        }
        if sequence == 6 {
            put_hex(&mut bytes[161..177], 24);
            put_hex(&mut bytes[178..194], challenge_fnv);
        } else if sequence == 8 {
            put_hex(&mut bytes[161..177], 24);
            put_hex(&mut bytes[178..194], response_fnv);
        }
        let checksum = fnv1a32(&bytes[..195]);
        put_hex(&mut bytes[195..203], u64::from(checksum));
        bytes[203] = b'\n';
        bytes
    }

    #[test]
    fn request_schema_is_exact_partial_and_has_full_payload_hashes() {
        let rendered = render_request(&fixed_request()).unwrap();
        assert!(rendered.contains("challenge_sha256"));
        assert!(rendered.contains("response_sha256"));
        assert!(!rendered.contains("DWTEST1"));
        let mut extra = fixed_request();
        extra.insert("terminal".into(), "pass".into());
        assert!(render_request(&extra).is_err());
    }

    #[test]
    fn handoff_and_pair_freeze_profiles_transport_and_absent_receipt() {
        for (profile, vcpus) in [("default", "1"), ("smp", "4")] {
            let mut map = values(HANDOFF_KEYS);
            for (key, value) in [
                ("kind", HANDOFF_KIND),
                ("schema_version", "1"),
                ("profile", profile),
                ("selector", SELECTOR),
                ("test_id", TEST_ID),
                ("evidence_protocol", EVIDENCE_PROTOCOL),
                ("partial_evidence", "true"),
                ("acceptance_claim", ACCEPTANCE_CLAIM),
                ("vcpus", vcpus),
                ("memory_mib", "2048"),
                ("machine", "pc-q35-10.2"),
                ("firmware", "OVMF"),
                ("timeout_seconds", "120"),
                ("scenario", "one-production-raw-com2-round-trip"),
                ("physical_io", "real-com2-irq3-intended"),
                ("terminal_authority", "deepwyrm-selector31-partial-only"),
                ("com1_role", "trusted-evidence-and-readiness"),
                ("com2_role", "raw-challenge-response"),
                ("com2_transport", "unix-socket-byte-stream"),
                ("com1_fd_group", "dw-e3a-com1-evidence-v1"),
                ("com2_fd_group", "dw-e3a-com2-raw-v1"),
                ("esp_fd_group", "dw-f13-esp-v1"),
                ("vars_fd_group", "dw-f13-ovmf-vars-v1"),
                ("domain_xml", "domain.xml"),
                ("mutable_ovmf_vars", "OVMF_VARS.mutable.fd"),
                ("com2_socket", "com2.sock"),
                ("com1_serial_log", "com1.log"),
                ("com2_log", "com2.bin"),
                ("partial_evidence_log", "partial-evidence.log"),
                ("result_path", "result.toml"),
                ("absent_receipt", "acceptance-receipt.toml"),
                ("readiness_marker", READINESS_MARKER),
            ] {
                map.insert(key.into(), value.into());
            }
            assert!(render_handoff(&map).is_ok());
        }
        let mut pair = values(PROFILE_PAIR_KEYS);
        for (key, value) in [
            ("kind", PROFILE_PAIR_KIND),
            ("schema_version", "1"),
            ("selector", SELECTOR),
            ("test_id", TEST_ID),
            ("evidence_protocol", EVIDENCE_PROTOCOL),
            ("partial_evidence", "true"),
            ("acceptance_claim", ACCEPTANCE_CLAIM),
            ("profiles", "default,smp"),
            ("default_handoff", "default/handoff.toml"),
            ("default_vcpus", "1"),
            ("smp_handoff", "smp/handoff.toml"),
            ("smp_vcpus", "4"),
            ("memory_mib", "2048"),
            ("machine", "pc-q35-10.2"),
            ("firmware", "OVMF"),
            ("timeout_seconds", "120"),
        ] {
            pair.insert(key.into(), value.into());
        }
        assert!(render_profile_pair(&pair).is_ok());
    }

    #[test]
    fn partial_parser_accepts_only_sequences_zero_through_eight_without_terminal() {
        let challenge_fnv = 0x1122_3344_5566_7788;
        let response_fnv = 0x8877_6655_4433_2211;
        let mut bytes = Vec::new();
        for sequence in 0..9 {
            bytes.extend_from_slice(&record(sequence, challenge_fnv, response_fnv));
        }
        let parsed = parse_partial_evidence(
            &bytes,
            "0123456789ABCDEF",
            24,
            challenge_fnv,
            24,
            response_fnv,
        )
        .unwrap();
        assert_eq!(parsed.records, 9);
        assert_eq!(parsed.stream_generation, 7);
        let mut terminal = bytes.clone();
        terminal.extend_from_slice(b"DWTEST1 31 0\n");
        assert!(
            parse_partial_evidence(
                &terminal,
                "0123456789ABCDEF",
                24,
                challenge_fnv,
                24,
                response_fnv,
            )
            .is_err()
        );
    }
}
