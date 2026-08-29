// SPDX-License-Identifier: GPL-3.0-or-later

use std::path::{Path, PathBuf};
use std::process::Command;

fn repository() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("xtask must remain beneath the Wyrmroot repository")
        .to_path_buf()
}

fn rejected(arguments: &[&str], variable: Option<(&str, &str)>) -> String {
    let mut command = Command::new(repository().join("tools/pinned-cargo"));
    command.args(arguments).env_remove("CARGO_HOME");
    if let Some((name, value)) = variable {
        command.env(name, value);
    }
    let output = command.output().expect("run pinned Cargo launcher");
    assert!(!output.status.success(), "unsafe invocation was accepted");
    String::from_utf8(output.stderr).expect("launcher stderr must be UTF-8")
}

#[test]
fn launcher_owns_cargo_home() {
    let error = rejected(&["--version"], Some(("CARGO_HOME", "/tmp/not-owned")));
    assert!(error.contains("CARGO_HOME is launcher-owned"));
}

#[test]
fn launcher_rejects_implicit_host_binary_targets() {
    let error = rejected(&["build", "--workspace"], None);
    assert!(error.contains("rejects implicit build targets"));
}

#[test]
fn launcher_rejects_freestanding_target_selection() {
    let error = rejected(
        &["build", "--lib", "--target", "x86_64-unknown-wyrmroot"],
        None,
    );
    assert!(error.contains("rejects explicit guest/UEFI targets"));
}

#[test]
fn launcher_rejects_caller_selected_product_compiler() {
    let error = rejected(&["xtask", "--help"], Some(("WYRMROOT_RUSTC", "/tmp/rustc")));
    assert!(error.contains("WYRMROOT_RUSTC is product-build-owned"));
}

#[test]
fn launcher_rejects_transitive_firmware_feature_admission() {
    let error = rejected(
        &[
            "test",
            "--package",
            "wyrmroot-efi-loader",
            "--features",
            "firmware",
            "--no-run",
        ],
        None,
    );
    assert!(error.contains("rejects caller-selected features"));
}

#[test]
fn launcher_rejects_target_directory_bypass() {
    let error = rejected(&["test", "--target-dir", "/tmp/not-owned"], None);
    assert!(error.contains("target directory is launcher-owned"));
}

#[test]
fn launcher_accepts_the_registered_wyrmroot_lane_layout() {
    let target = std::env::temp_dir().join("wyrmroot-pinned-cargo-lane-contract");
    let output = Command::new(repository().join("tools/pinned-cargo"))
        .arg("--version")
        .env_remove("CARGO_HOME")
        .env_remove("CARGO")
        .env("WYRMROOT_PINNED_TARGET_DIR", target)
        .output()
        .expect("run pinned Cargo launcher from this checkout");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}
