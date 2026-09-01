// SPDX-License-Identifier: GPL-3.0-or-later

use std::process::Command;

fn command() -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_xtask"));
    for key in [
        "CARGO_TARGET_DIR",
        "DEEPWYRM_GUEST_TEST_SELECTOR",
        "DEEPWYRM_GUEST_TEST_ID",
        "DEEPWYRM_DW1E_EVIDENCE_NONCE",
    ] {
        command.env_remove(key);
    }
    command
}

#[test]
fn command_rejects_non_distinct_evidence_and_payload_nonces_before_creating_output() {
    let output = std::env::temp_dir().join(format!("dw1e3b-cli-invalid-{}", std::process::id()));
    assert!(!output.exists());
    let result = command()
        .args([
            "dw1-e3b-prepare",
            output.to_str().unwrap(),
            "/invalid/deepwyrm",
            &"1".repeat(40),
            "E300000000000001",
            "E300000000000002",
            "E300000000000002",
        ])
        .output()
        .expect("run xtask DW1-E3B producer");
    assert!(!result.status.success());
    assert!(
        String::from_utf8(result.stderr)
            .unwrap()
            .contains("DW1-E3B evidence and challenge nonces must be pairwise distinct")
    );
    assert!(!output.exists());
}

#[test]
fn help_names_the_three_nonce_e3b_producer_interface() {
    let result = command().arg("--help").output().expect("run xtask help");
    assert!(result.status.success());
    assert!(String::from_utf8(result.stdout).unwrap().contains(
        "dw1-e3b-prepare <fresh-directory> <deepwyrm-repository> <deepwyrm-revision> <16-hex-evidence-nonce> <16-hex-challenge-1-nonce> <16-hex-challenge-2-nonce>"
    ));
}
