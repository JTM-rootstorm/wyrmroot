use std::fs;
use std::path::PathBuf;

use deepwyrm_syscall as _;
use wyrmroot_dw1b_preemption as _;
use wyrmroot_loader as _;
use wyrmroot_runtime as _;

fn repository() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_owned()
}

#[test]
fn executed_hog_loop_is_syscall_yield_and_block_free() {
    let source =
        fs::read_to_string(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/lib.rs")).unwrap();
    let start = source.find("pub fn run_cpu_hog").unwrap();
    let end = source[start..].find("pub fn run_progress").unwrap() + start;
    let function = &source[start..end];
    let loop_start = function.find("loop {").unwrap();
    let executed_loop = &function[loop_start..];
    assert!(executed_loop.contains("core::hint::spin_loop()"));
    for forbidden in ["syscall", "yield", "wait_", "receive_", "send_", "close_"] {
        assert!(!executed_loop.contains(forbidden), "found {forbidden}");
    }
}

#[test]
fn progress_attestation_is_after_all_eight_correlated_exchanges() {
    let source =
        fs::read_to_string(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/lib.rs")).unwrap();
    let start = source.find("pub fn run_progress").unwrap();
    let end = source[start..]
        .find("fn receive_hog_startup_and_ready")
        .unwrap()
        + start;
    let function = &source[start..end];
    let loop_pos = function.find("for round in 0..ROUND_COUNT").unwrap();
    let parse_pos = function.find("parse_challenge(&bytes, round)").unwrap();
    let reply_pos = function.find("encode_reply(round)").unwrap();
    let submit_pos = function
        .find("submit_dw1b_progress(CHALLENGE_DIGEST)")
        .unwrap();
    assert!(loop_pos < parse_pos && parse_pos < reply_pos && reply_pos < submit_pos);
    assert_eq!(
        source
            .matches("submit_dw1b_progress(CHALLENGE_DIGEST)")
            .count(),
        1
    );
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Event {
    HogCreateStart,
    HogReady,
    ProgressCreateStart,
    ProgressReady,
    Arm,
    Exchange(u8),
    ProgressExitQueryReap,
    HelloReadyExitCleanup,
    HogTerminateExitQueryReap,
    InitReadyExit,
}

#[test]
fn executable_mock_trace_proves_the_complete_selector_26_order() {
    let mut trace = vec![Event::HogCreateStart, Event::HogReady];
    trace.extend([Event::ProgressCreateStart, Event::ProgressReady, Event::Arm]);
    for round in 0..wyrmroot_dw1b_preemption::ROUND_COUNT {
        let request = wyrmroot_dw1b_preemption::encode_challenge(round);
        let reply = wyrmroot_dw1b_preemption::encode_reply(round);
        wyrmroot_dw1b_preemption::parse_challenge(&request, round).unwrap();
        wyrmroot_dw1b_preemption::parse_reply(&reply, round).unwrap();
        trace.push(Event::Exchange(round as u8));
    }
    trace.extend([
        Event::ProgressExitQueryReap,
        Event::HelloReadyExitCleanup,
        Event::HogTerminateExitQueryReap,
        Event::InitReadyExit,
    ]);
    let mut expected = vec![Event::HogCreateStart, Event::HogReady];
    expected.extend([Event::ProgressCreateStart, Event::ProgressReady, Event::Arm]);
    expected.extend((0..8).map(Event::Exchange));
    expected.extend([
        Event::ProgressExitQueryReap,
        Event::HelloReadyExitCleanup,
        Event::HogTerminateExitQueryReap,
        Event::InitReadyExit,
    ]);
    assert_eq!(trace, expected);

    let root = repository();
    let runtime =
        fs::read_to_string(root.join("crates/wyrmroot-runtime/src/capability_native.rs")).unwrap();
    assert!(runtime.contains("DwSyscallId(0xFFFF_FF1A)"));
    assert!(runtime.contains("[1, hog_process.0, progress_process.0, 8, 0, 0]"));
    assert!(runtime.contains("[2, 8, digest, 0, 0, 0]"));
}

#[test]
fn selector_25_and_27_identities_remain_distinct() {
    let root = repository();
    let wyr1 = fs::read_to_string(root.join("tools/xtask/src/wyr1.rs")).unwrap();
    let wyr1b = fs::read_to_string(root.join("tools/xtask/src/wyr1b.rs")).unwrap();
    let dw1b = fs::read_to_string(root.join("tools/xtask/src/dw1b.rs")).unwrap();
    assert!(wyr1.contains("pub const TEST_ID: u32 = 25;"));
    assert!(wyr1b.contains("pub const TEST_ID: u32 = 27;"));
    assert!(dw1b.contains("pub const TEST_ID: u32 = 26;"));
}
