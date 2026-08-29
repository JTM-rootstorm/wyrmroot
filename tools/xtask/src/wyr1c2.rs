//! Selector-free WYR1-C2 product binding.
//!
//! C2 deliberately has no guest selector, run, or evidence command.  It
//! freezes C1's exact native product and adds a reviewed host policy source,
//! its canonical WRDM v1 compilation, and a bounded observation policy.  An
//! ESP cannot be manufactured honestly until the separate selector/guest tuple
//! is admitted, so `image` fails closed instead of reusing selector 25 or 27.

use std::{collections::BTreeMap, fs, path::Path};

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
const SOURCE: &[u8] = include_bytes!("../../../products/wyr1c/q35-com2-role.toml");
const OBSERVATION: &str = concat!(
    "schema = 1\n",
    "selector = \"none\"\n",
    "evidence = \"not-produced\"\n",
    "allowed = \"CoordinatorOperational,WaitingForRegistry,WaitingForDeviceBundle,Rebind\"\n",
    "forbidden = \"DeviceBound,DriverLaunched,HardwareAccepted\"\n",
);

pub(crate) fn freeze(output: &Path) -> Result<String, Failure> {
    reject_nonempty(output)?;
    // C1 already enforces the accepted a92dc7f toolchain, clean Wyrmroot
    // revision, isolated offline native builds, and fresh output.  C2 wraps
    // that exact product rather than duplicating those assumptions.
    wyr1c::product(output)?;
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
            ("selector", "none".to_owned()),
            ("evidence", "not-produced".to_owned()),
        ],
    );
    write_new(&output.join(RECEIPT_NAME), receipt.as_bytes())?;
    inspect(&request_path)?;
    Ok(format!(
        "WYR1_C2_FREEZE_PASS selector=none evidence=not-produced request={}\n",
        request_path.display()
    ))
}

/// C2 intentionally rejects ESP construction before the distinct guest tuple
/// exists.  This prevents stale loader/kernel/bootstrap aliases from becoming
/// a fake selector-29 product.
pub(crate) fn image(request: &Path) -> Result<String, Failure> {
    inspect(request)?;
    Err(Failure::unavailable(
        "WYR1-C2 image is withheld: selector=none has no admitted production guest tuple or ESP authority",
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
    let mut map = BTreeMap::new();
    for line in text.lines() {
        let (key, value) = line
            .split_once(" = ")
            .ok_or_else(|| Failure::task("C2 TOML has malformed line"))?;
        if key.is_empty()
            || !key
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte == b'_')
            || map
                .insert(key.to_owned(), value.trim_matches('"').to_owned())
                .is_some()
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
    fs::write(path, bytes)
        .map_err(|error| Failure::task(format!("could not write C2 product: {error}")))
}
fn read_regular(path: &Path) -> Result<Vec<u8>, Failure> {
    let m = fs::symlink_metadata(path)
        .map_err(|e| Failure::task(format!("could not inspect C2 input: {e}")))?;
    if !m.file_type().is_file() || m.file_type().is_symlink() {
        return Err(Failure::task("C2 input is not a regular file"));
    }
    fs::read(path).map_err(|e| Failure::task(format!("could not read C2 input: {e}")))
}
fn digest_file(path: &Path) -> Result<String, Failure> {
    Ok(sha256::bytes_digest(&read_regular(path)?))
}
fn hex_to_digest(value: &str) -> Result<[u8; 32], Failure> {
    crate::wyr1::decode_digest(value)
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
        let map = parse_request(b"kind = \"x\"\n").unwrap();
        assert!(!map.contains_key("test_id"));
    }
}
