//! Source-text check of the hog's loop.

use std::{fs, path::PathBuf};

use deepwyrm_syscall as _;
use wyrmroot_dw1b_preemption as _;
use wyrmroot_loader as _;
use wyrmroot_runtime as _;

/// Source text: the loop never returns and runs only on the guest, so no host
/// test can observe that it makes no syscall.
#[test]
fn executed_hog_loop_is_syscall_yield_and_block_free() {
    let source =
        fs::read_to_string(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/lib.rs")).unwrap();
    let start = source.find("pub fn run_cpu_hog_body").unwrap();
    let function = &source[start..];
    let function = &function[..function.find("\n}\n").unwrap()];
    let executed_loop = &function[function.find("loop {").unwrap()..];
    assert!(executed_loop.contains("core::hint::spin_loop()"));
    for forbidden in ["syscall", "yield", "wait_", "receive_", "send_", "close_"] {
        assert!(!executed_loop.contains(forbidden), "found {forbidden}");
    }
}
