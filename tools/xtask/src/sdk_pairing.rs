//! A built Wyrmroot SDK pairs with this checkout (root `CLAUDE.md` §7).
//!
//! `wyrmroot-sdk/out/sdk-manifest.toml` records what the SDK was built from.
//! A product that carries the SDK's programs refuses one that was not built
//! from the SDK's current, clean HEAD, whose `deepwyrm-syscall` is not the
//! Deepwyrm revision Wyrmroot pins, or that compiled Wyrmroot protocol
//! crates which have changed since. Otherwise a repin, or an SDK change,
//! would leave dev-boot running stale programs without saying so.

use std::collections::BTreeMap;
use std::path::Path;
use std::process::{Command, Stdio};

use crate::error::Failure;

/// What the SDK manifest says, set against this checkout.
#[derive(Debug)]
pub(crate) struct SdkState<'a> {
    /// `[inputs]` of `sdk-manifest.toml`, as `inputs.<key>`.
    pub(crate) manifest: &'a BTreeMap<String, String>,
    pub(crate) pinned_deepwyrm: &'a str,
    pub(crate) sdk_head: &'a str,
    pub(crate) sdk_dirty: bool,
    /// The Wyrmroot crates the SDK compiles in that differ from the revision
    /// it recorded.
    pub(crate) changed_crates: &'a [String],
}

/// Every reason the SDK does not pair, or none.
pub(crate) fn mismatches(state: &SdkState<'_>) -> Vec<String> {
    let input = |key: &str| {
        state
            .manifest
            .get(&format!("inputs.{key}"))
            .map(String::as_str)
    };
    let mut reasons = Vec::new();
    if input("deepwyrm_syscall") != Some(state.pinned_deepwyrm) {
        reasons.push(format!(
            "it was built with deepwyrm-syscall {}, but Wyrmroot pins Deepwyrm {}: repin wyrmroot-sdk/posix/Cargo.toml and rebuild",
            input("deepwyrm_syscall").unwrap_or("(none)"),
            state.pinned_deepwyrm
        ));
    }
    if input("wyrmroot_sdk") != Some(state.sdk_head) {
        reasons.push(format!(
            "it was built from wyrmroot-sdk {}, but the checkout is at {}: rebuild",
            input("wyrmroot_sdk").unwrap_or("(none)"),
            state.sdk_head
        ));
    }
    if input("wyrmroot_sdk_dirty") != Some("false") {
        reasons.push("it was built from a dirty wyrmroot-sdk checkout: commit and rebuild".into());
    }
    if state.sdk_dirty {
        reasons.push("wyrmroot-sdk has uncommitted changes: commit and rebuild".into());
    }
    if input("wyrmroot_dirty") != Some("false") {
        reasons.push("it was built from a dirty Wyrmroot checkout: rebuild".into());
    }
    for path in state.changed_crates {
        reasons.push(format!(
            "it compiled {path}, which has changed since Wyrmroot {}: rebuild",
            input("wyrmroot").unwrap_or("(none)")
        ));
    }
    reasons
}

/// The Wyrmroot paths `posix/Cargo.toml` compiles in (`path =
/// "../../wyrmroot/<path>"`), so a change to one calls for a rebuild.
pub(crate) fn wyrmroot_paths(cargo_toml: &str) -> Vec<String> {
    cargo_toml
        .lines()
        .filter_map(|line| line.split_once("path = \"../../wyrmroot/"))
        .filter_map(|(_, rest)| rest.split_once('"'))
        .map(|(path, _)| path.to_owned())
        .collect()
}

/// Refuses an SDK at `sdk_out` (`wyrmroot-sdk/out`) that does not pair with
/// the Wyrmroot checkout at `repository`.
pub(crate) fn require(
    repository: &Path,
    sdk_out: &Path,
    pinned_deepwyrm: &str,
) -> Result<(), Failure> {
    let sdk = sdk_out
        .parent()
        .ok_or_else(|| Failure::task("the SDK output has no parent checkout"))?;
    let manifest_path = sdk_out.join("sdk-manifest.toml");
    let manifest_text =
        crate::product::read_regular_bounded(&manifest_path, 1 << 20, "SDK manifest")?;
    let manifest_text = String::from_utf8(manifest_text)
        .map_err(|_| Failure::task("the SDK manifest is not UTF-8"))?;
    let manifest = crate::metadata::parse_scalar_toml(&manifest_text, &manifest_path)?;
    if manifest.get("schema").map(String::as_str) != Some("wyrmroot-sdk-manifest-v1") {
        return Err(Failure::task(
            "the SDK manifest is not wyrmroot-sdk-manifest-v1",
        ));
    }
    let sdk_head = git(sdk, &["rev-parse", "HEAD"])?;
    let sdk_dirty = !git(sdk, &["status", "--porcelain", "--untracked-files=no"])?.is_empty();
    let cargo_toml = crate::product::read_regular_bounded(
        &sdk.join("posix/Cargo.toml"),
        1 << 20,
        "SDK posix/Cargo.toml",
    )?;
    let recorded = manifest
        .get("inputs.wyrmroot")
        .ok_or_else(|| Failure::task("the SDK manifest records no Wyrmroot revision"))?;
    let mut changed_crates = Vec::new();
    for path in wyrmroot_paths(&String::from_utf8_lossy(&cargo_toml)) {
        // Against the working tree, so an uncommitted edit counts too.
        let status = Command::new("git")
            .arg("-C")
            .arg(repository)
            .args(["diff", "--quiet", recorded.as_str(), "--", path.as_str()])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map_err(|error| Failure::task(format!("could not run git: {error}")))?;
        match status.code() {
            Some(0) => {}
            Some(1) => changed_crates.push(path),
            _ => {
                return Err(Failure::task(format!(
                    "could not compare {path} with the SDK's Wyrmroot {recorded}"
                )));
            }
        }
    }
    let reasons = mismatches(&SdkState {
        manifest: &manifest,
        pinned_deepwyrm,
        sdk_head: &sdk_head,
        sdk_dirty,
        changed_crates: &changed_crates,
    });
    if reasons.is_empty() {
        Ok(())
    } else {
        Err(Failure::task(format!(
            "the SDK at {} does not pair with this checkout:\n  {}",
            sdk_out.display(),
            reasons.join("\n  ")
        )))
    }
}

fn git(repository: &Path, args: &[&str]) -> Result<String, Failure> {
    let output = Command::new("git")
        .arg("-C")
        .arg(repository)
        .args(args)
        .stdin(Stdio::null())
        .output()
        .map_err(|error| Failure::task(format!("could not run git: {error}")))?;
    if !output.status.success() {
        return Err(Failure::task(format!(
            "git {} failed in {}",
            args.join(" "),
            repository.display()
        )));
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    const PIN: &str = "94ad17eb6b7eaeb3049389d605eadc62c03b2103";
    const HEAD: &str = "de91e4b000000000000000000000000000000000";

    fn manifest(deepwyrm: &str, sdk: &str) -> BTreeMap<String, String> {
        [
            ("inputs.deepwyrm_syscall", deepwyrm),
            ("inputs.wyrmroot_sdk", sdk),
            ("inputs.wyrmroot_sdk_dirty", "false"),
            (
                "inputs.wyrmroot",
                "dfb06aa000000000000000000000000000000000",
            ),
            ("inputs.wyrmroot_dirty", "false"),
        ]
        .into_iter()
        .map(|(key, value)| (key.to_owned(), value.to_owned()))
        .collect()
    }

    fn state<'a>(
        manifest: &'a BTreeMap<String, String>,
        changed: &'a [String],
        dirty: bool,
    ) -> SdkState<'a> {
        SdkState {
            manifest,
            pinned_deepwyrm: PIN,
            sdk_head: HEAD,
            sdk_dirty: dirty,
            changed_crates: changed,
        }
    }

    #[test]
    fn an_sdk_built_from_the_pinned_pair_pairs() {
        let manifest = manifest(PIN, HEAD);
        assert!(mismatches(&state(&manifest, &[], false)).is_empty());
    }

    #[test]
    fn a_stale_deepwyrm_pin_is_refused() {
        let manifest = manifest("942f1b22523b6b22d7a412c1b9f88d860c554e57", HEAD);
        let reasons = mismatches(&state(&manifest, &[], false));
        assert_eq!(reasons.len(), 1);
        assert!(reasons[0].contains("deepwyrm-syscall 942f1b22"));
    }

    #[test]
    fn an_sdk_built_from_another_revision_or_dirty_is_refused() {
        let stale = manifest(PIN, "c1eb55f000000000000000000000000000000000");
        assert_eq!(mismatches(&state(&stale, &[], false)).len(), 1);
        let current = manifest(PIN, HEAD);
        assert_eq!(mismatches(&state(&current, &[], true)).len(), 1);
        let mut dirty_build = manifest(PIN, HEAD);
        dirty_build.insert("inputs.wyrmroot_sdk_dirty".into(), "true".into());
        assert_eq!(mismatches(&state(&dirty_build, &[], false)).len(), 1);
        let mut no_record = manifest(PIN, HEAD);
        no_record.remove("inputs.deepwyrm_syscall");
        assert_eq!(mismatches(&state(&no_record, &[], false)).len(), 1);
    }

    #[test]
    fn a_changed_protocol_crate_is_refused() {
        let manifest = manifest(PIN, HEAD);
        let changed = ["crates/wyrmroot-fs-proto".to_owned()];
        let reasons = mismatches(&state(&manifest, &changed, false));
        assert_eq!(reasons.len(), 1);
        assert!(reasons[0].contains("crates/wyrmroot-fs-proto"));
    }

    #[test]
    fn the_compiled_in_wyrmroot_paths_are_read_from_the_manifest() {
        let cargo = r#"
deepwyrm-syscall = { git = "https://example.invalid/deepwyrm.git", rev = "abc" }
wyrmroot-startup-proto = { path = "../../wyrmroot/crates/wyrmroot-startup-proto" }
wyrmroot-fs-proto = { path = "../../wyrmroot/crates/wyrmroot-fs-proto" }
other = { path = "../local" }
"#;
        assert_eq!(
            wyrmroot_paths(cargo),
            ["crates/wyrmroot-startup-proto", "crates/wyrmroot-fs-proto"]
        );
    }
}
