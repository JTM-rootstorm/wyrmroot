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
fn command_dispatches_into_prepare_validation_without_creating_output() {
    let output = std::env::temp_dir().join(format!("dw1e3a-cli-invalid-{}", std::process::id()));
    assert!(!output.exists());
    let result = command()
        .args([
            "dw1-e3a-prepare",
            output.to_str().unwrap(),
            "/invalid/deepwyrm",
            "not-a-revision",
            "E300000000000001",
        ])
        .output()
        .expect("run xtask DW1-E3A producer");
    assert!(!result.status.success());
    assert!(
        String::from_utf8(result.stderr)
            .unwrap()
            .contains("Deepwyrm revision is not lowercase hexadecimal")
    );
    assert!(!output.exists());
}

#[test]
fn help_names_the_exact_producer_owned_positional_interface() {
    let result = command().arg("--help").output().expect("run xtask help");
    assert!(result.status.success());
    let stdout = String::from_utf8(result.stdout).unwrap();
    assert!(stdout.contains(
        "dw1-e3a-prepare <fresh-directory> <deepwyrm-repository> <deepwyrm-revision> <16-hex-nonce>"
    ));
}
