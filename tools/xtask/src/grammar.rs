//! `xtask grammar dump`: the DW1-F/WYR1-F request/receipt/handoff/pair/result
//! grammar, emitted as data.
//!
//! Structural refactor S2T (`DW1_WYR1_STRUCTURAL_REFACTOR_PLAN.md` §4 S2T).
//! `tools/verify-vm-request.py` hand-copies this grammar into its own `F_*`
//! constants and four of its tests (`test_the_receipt_and_esp_shapes_match_the_producer`,
//! `test_the_handoff_and_pair_key_sets_match_the_producer`,
//! `test_the_result_grammar_key_sets_match_the_producer`,
//! `test_the_verifier_key_set_matches_the_producer`) recover the producer's
//! side of that comparison by reading `wyr1f.rs` as text and regexing it.
//! This command exists so that side can load a generated file instead.
//!
//! The generated file is committed as `tools/xtask/grammar/wyr1f-grammar-v1.json`
//! and `tests::the_committed_snapshot_is_the_current_dump` keeps it current.
//! The verifier keeps its own spelling of the grammar on purpose: a schema
//! change made on one side alone must still fail a test, which it would not
//! if the verifier loaded the producer's copy at run time.
//!
//! Every value this module emits comes from calling the exact functions and
//! constants `wyr1f::prepare` itself calls to build a product -- `wyr1f::ARTIFACTS`,
//! `wyr1f::fixed_fields`, `wyr1f::obligation_fields`, `wyr1f::request_keys`,
//! `wyr1f::receipt_fields`, `wyr1f::handoff_fields`, `wyr1f::pair_fields` and
//! `wyr1f::result_keys` (backed by the `RESULT_*_KEYS` groups) -- not a second
//! description of them. `receipt_fields`/`handoff_fields`/`pair_fields` need
//! request values and, for the pair, staged handoff files to run at all; this
//! module supplies placeholders for both, because only the *keys* they
//! produce belong in a grammar. See `tests::dump_reads_the_producer_constants_directly`
//! for the guarantee that this file does not fork its own copy of the schema.

use std::collections::BTreeMap;
use std::fmt::Write as FmtWrite;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::error::Failure;
use crate::{tasks, wyr1c, wyr1f};

const PRODUCTS: [wyr1c::Wyr1fProduct; 3] = [
    wyr1c::Wyr1fProduct::Normal,
    wyr1c::Wyr1fProduct::InstrumentedNormal,
    wyr1c::Wyr1fProduct::Degraded,
];

/// Renders the grammar as one JSON document, to stdout.
pub(crate) fn dump() -> Result<String, Failure> {
    let scratch = scratch_directory()?;
    let rendered = render(&scratch);
    let cleanup = fs::remove_dir_all(&scratch);
    let body = rendered?;
    cleanup
        .map_err(|error| Failure::task(format!("could not remove grammar scratch: {error}")))?;
    Ok(body)
}

/// A placeholder-filled request map, keyed exactly by `wyr1f::request_keys`
/// for this product. `receipt_fields`/`handoff_fields`/`pair_fields` only
/// read these values back out verbatim (no parsing, no validation), so a
/// placeholder is exactly as good as a real value for recovering which keys
/// they produce.
fn synthetic_request(product_kind: wyr1c::Wyr1fProduct) -> BTreeMap<String, String> {
    wyr1f::request_keys(product_kind)
        .into_iter()
        .map(|key| (key, "x".to_owned()))
        .collect()
}

/// A scratch directory holding a placeholder `handoff.toml` for every
/// profile, which is all `wyr1f::pair_fields` reads from disk: its own
/// content is never inspected, only hashed.
fn scratch_directory() -> Result<PathBuf, Failure> {
    let repository = tasks::repository_root()?;
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| Failure::task("system clock is before the Unix epoch"))?
        .as_nanos();
    let path = repository
        .join(".tmp/xtask-grammar-dump")
        .join(format!("{}-{unique}", std::process::id()));
    fs::create_dir_all(&path)
        .map_err(|error| Failure::task(format!("could not create grammar scratch: {error}")))?;
    for (profile, _) in wyr1f::PROFILES {
        let directory = path.join(profile);
        fs::create_dir(&directory).map_err(|error| {
            Failure::task(format!("could not create grammar scratch profile: {error}"))
        })?;
        fs::write(directory.join("handoff.toml"), b"placeholder\n").map_err(|error| {
            Failure::task(format!("could not seed grammar scratch handoff: {error}"))
        })?;
    }
    Ok(path)
}

fn render(scratch: &Path) -> Result<String, Failure> {
    let mut out = String::from("{\n");
    out.push_str("  \"schema_version\": 1,\n");
    out.push_str("  \"kinds\": ");
    out.push_str(&json_object_of_string_pairs([
        ("request", wyr1f::REQUEST_KIND),
        ("receipt", wyr1f::RECEIPT_KIND),
        ("source_receipt", wyr1f::SOURCE_KIND),
        ("result", wyr1f::RESULT_KIND),
        ("handoff", wyr1f::HANDOFF_KIND),
        ("pair", wyr1f::PAIR_KIND),
    ]));
    out.push_str(",\n  \"source_receipt_name\": ");
    out.push_str(&json_string(wyr1f::SOURCE_RECEIPT));
    out.push_str(",\n  \"closure\": {\"selector\": ");
    out.push_str(&json_string(wyr1c::WYR1F_SELECTOR));
    out.push_str(", \"test_id\": ");
    out.push_str(&json_string(wyr1c::WYR1F_TEST_ID));
    out.push_str("},\n  \"profiles\": {");
    for (index, (profile, vcpus)) in wyr1f::PROFILES.into_iter().enumerate() {
        if index > 0 {
            out.push_str(", ");
        }
        out.push_str(&json_string(profile));
        let _ = write!(out, ": {vcpus}");
    }
    out.push_str("},\n  \"artifacts\": ");
    out.push_str(&json_object_of_string_pairs(
        wyr1f::ARTIFACTS.iter().copied(),
    ));
    out.push_str(",\n  \"result_key_groups\": {\n");
    out.push_str("    \"base\": ");
    out.push_str(&json_array_of_strings(wyr1f::RESULT_BASE_KEYS.iter()));
    out.push_str(",\n    \"normal_half\": ");
    out.push_str(&json_array_of_strings(
        wyr1f::RESULT_NORMAL_HALF_KEYS.iter(),
    ));
    out.push_str(",\n    \"degraded_half\": ");
    out.push_str(&json_array_of_strings(
        wyr1f::RESULT_DEGRADED_HALF_KEYS.iter(),
    ));
    out.push_str(",\n    \"instrumented_tail\": ");
    out.push_str(&json_array_of_strings(
        wyr1f::RESULT_INSTRUMENTED_TAIL_KEYS.iter(),
    ));
    out.push_str(",\n    \"production_tail\": ");
    out.push_str(&json_array_of_strings(
        wyr1f::RESULT_PRODUCTION_TAIL_KEYS.iter(),
    ));
    out.push_str("\n  },\n  \"products\": {\n");
    for (index, product_kind) in PRODUCTS.into_iter().enumerate() {
        if index > 0 {
            out.push_str(",\n");
        }
        let (name, body) = product_grammar(product_kind, scratch)?;
        out.push_str("    ");
        out.push_str(&json_string(&name));
        out.push_str(": ");
        out.push_str(&body);
    }
    out.push_str("\n  }\n}\n");
    Ok(out)
}

/// One product's slice of the grammar: its request's fixed values and
/// obligations, and the key sets of its request, receipt, handoff, pair and
/// result grammars.
fn product_grammar(
    product_kind: wyr1c::Wyr1fProduct,
    scratch: &Path,
) -> Result<(String, String), Failure> {
    let fixed = wyr1f::fixed_fields(product_kind);
    let name = fixed
        .iter()
        .find(|(key, _)| *key == "product")
        .map(|(_, value)| (*value).to_owned())
        .ok_or_else(|| Failure::task("WYR1-F grammar dump: fixed_fields carries no `product`"))?;

    let synthetic = synthetic_request(product_kind);
    let hash = "0".repeat(64);
    let receipt_keys = wyr1f::receipt_fields(&hash, &synthetic);
    let profile = wyr1f::PROFILES[0].0;
    let vcpus = wyr1f::PROFILES[0].1;
    let handoff_keys = wyr1f::handoff_fields(
        product_kind,
        profile,
        vcpus,
        &hash,
        &synthetic,
        "<domain/>",
        b"placeholder-vars",
    )?;
    let pair_keys = wyr1f::pair_fields(product_kind, scratch, &hash, &synthetic)?;

    let mut object = String::from("{\n");
    object.push_str("      \"fixed_fields\": ");
    object.push_str(&json_object_of_string_pairs(fixed.iter().copied()));
    object.push_str(",\n      \"obligation_fields\": ");
    object.push_str(&json_object_of_string_pairs(
        wyr1f::obligation_fields().iter().copied(),
    ));
    object.push_str(",\n      \"request_keys\": ");
    object.push_str(&json_array_of_strings(
        wyr1f::request_keys(product_kind).iter(),
    ));
    object.push_str(",\n      \"receipt_keys\": ");
    object.push_str(&json_array_of_strings(receipt_keys.keys()));
    object.push_str(",\n      \"handoff_keys\": ");
    object.push_str(&json_array_of_strings(handoff_keys.keys()));
    object.push_str(",\n      \"pair_keys\": ");
    object.push_str(&json_array_of_strings(pair_keys.keys()));
    object.push_str(",\n      \"result_keys\": ");
    object.push_str(&json_array_of_strings(
        wyr1f::result_keys(product_kind).iter(),
    ));
    object.push_str("\n    }");
    Ok((name, object))
}

fn json_string(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn json_array_of_strings<I, S>(values: I) -> String
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut out = String::from("[");
    let mut first = true;
    for value in values {
        if !first {
            out.push_str(", ");
        }
        first = false;
        out.push_str(&json_string(value.as_ref()));
    }
    out.push(']');
    out
}

fn json_object_of_string_pairs<'a, I>(pairs: I) -> String
where
    I: IntoIterator<Item = (&'a str, &'a str)>,
{
    let mut out = String::from("{");
    let mut first = true;
    for (key, value) in pairs {
        if !first {
            out.push_str(", ");
        }
        first = false;
        out.push_str(&json_string(key));
        out.push_str(": ");
        out.push_str(&json_string(value));
    }
    out.push('}');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `dump` must read `wyr1f`'s constants and functions directly rather
    /// than restate them: every one of these substrings is built the same
    /// way `render`/`product_grammar` build them, straight from the same
    /// `wyr1f` items, so this only fails if `dump`'s own rendering stops
    /// calling them. Mutation check: change one artifact filename literal in
    /// `render`'s `wyr1f::ARTIFACTS.iter().copied()` call to a hardcoded
    /// wrong pair and confirm this test fails.
    #[test]
    fn dump_reads_the_producer_constants_directly() {
        let body = dump().expect("grammar dump");
        assert!(body.contains(&json_string(wyr1f::REQUEST_KIND)));
        assert!(body.contains(&json_string(wyr1f::RECEIPT_KIND)));
        assert!(body.contains(&json_object_of_string_pairs(
            wyr1f::ARTIFACTS.iter().copied()
        )));
        assert!(body.contains(&json_array_of_strings(wyr1f::RESULT_BASE_KEYS.iter())));
        assert!(body.contains(&json_array_of_strings(
            wyr1f::RESULT_INSTRUMENTED_TAIL_KEYS.iter()
        )));
        for product_kind in PRODUCTS {
            let expected_result = json_array_of_strings(wyr1f::result_keys(product_kind).iter());
            assert!(body.contains(&expected_result), "{}", product_kind.cli_value());
            let expected_request = json_array_of_strings(wyr1f::request_keys(product_kind).iter());
            assert!(body.contains(&expected_request), "{}", product_kind.cli_value());
            let expected_fixed =
                json_object_of_string_pairs(wyr1f::fixed_fields(product_kind).iter().copied());
            assert!(body.contains(&expected_fixed), "{}", product_kind.cli_value());
        }
    }

    /// The committed snapshot that `tests/test_verify_vm_request.py` compares
    /// the verifier's own spelling against. Regenerate it with
    /// `tools/pinned-cargo xtask grammar dump > tools/xtask/grammar/wyr1f-grammar-v1.json`.
    #[test]
    fn the_committed_snapshot_is_the_current_dump() {
        const SNAPSHOT: &str = include_str!("../grammar/wyr1f-grammar-v1.json");
        let current = dump().expect("grammar dump");
        assert!(
            current == SNAPSHOT,
            "tools/xtask/grammar/wyr1f-grammar-v1.json is stale; regenerate it with \
             `tools/pinned-cargo xtask grammar dump > tools/xtask/grammar/wyr1f-grammar-v1.json`"
        );
    }

    /// The dump names all three final products by their request `product`
    /// value, the same spelling `F_PRODUCTS` in `tools/verify-vm-request.py`
    /// uses as a dict key.
    #[test]
    fn dump_names_every_product_by_its_request_value() {
        let body = dump().expect("grammar dump");
        for product in ["wyr1-f-normal", "wyr1-f-normal-instrumented", "wyr1-f-degraded"] {
            assert!(body.contains(&json_string(product)), "{product}");
        }
    }

    #[test]
    fn json_string_escapes_control_and_quote_characters() {
        assert_eq!(json_string("a\"b\\c\nd"), "\"a\\\"b\\\\c\\nd\"");
    }
}
