use std::collections::BTreeSet;
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

/// Source text: the link arguments are `cargo:` directives a build script
/// prints for rustc; no host test or type can observe them, and the guest
/// link that consumes them runs only in the native product builds.
#[test]
fn all_native_payloads_use_the_canonical_linker_contract() {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let build = fs::read_to_string(manifest_dir.join("build.rs")).unwrap();
    let main = &build[build.find("fn main()").expect("build script entry")..];
    assert!(main.contains("manifest.join(\"../../toolchain/native-user.ld\")"));
    // Every `[[bin]]` the manifest declares, and only those, is linked by
    // the loop, and the loop gives each one both arguments.
    let manifest = fs::read_to_string(manifest_dir.join("Cargo.toml")).unwrap();
    let declared = manifest
        .split("[[bin]]")
        .skip(1)
        .map(|table| {
            table
                .lines()
                .find_map(|line| line.strip_prefix("name = \""))
                .and_then(|name| name.strip_suffix('"'))
                .expect("bin name")
                .to_owned()
        })
        .collect::<BTreeSet<_>>();
    let list = &main[main.find("for binary in [").expect("binary loop")..];
    let (list, body) = list.split_once("] {").expect("binary list");
    let linked = list
        .split('"')
        .skip(1)
        .step_by(2)
        .map(str::to_owned)
        .collect::<BTreeSet<_>>();
    assert_eq!(linked, declared);
    let body = &body[..body.find("\n    }").expect("loop body")];
    assert!(body.contains("cargo:rustc-link-arg-bin={binary}=-T{}"));
    assert!(body.contains("cargo:rustc-link-arg-bin={binary}=--build-id=none"));
}

#[test]
fn executed_hog_loop_is_syscall_yield_and_block_free() {
    let source =
        fs::read_to_string(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/lib.rs")).unwrap();
    let start = source.find("pub fn run_cpu_hog_body").unwrap();
    let end = source[start..].find("pub fn run_progress").unwrap() + start;
    let function = &source[start..end];
    let loop_start = function.find("loop {").unwrap();
    let executed_loop = &function[loop_start..];
    assert!(executed_loop.contains("core::hint::spin_loop()"));
    for forbidden in ["syscall", "yield", "wait_", "receive_", "send_", "close_"] {
        assert!(!executed_loop.contains(forbidden), "found {forbidden}");
    }
}

/// Source text: both entry points are guest-only `no_std`/`no_main` binaries
/// with no host build, and the shared body never returns, so no host test
/// can observe that an entry delegates to it.
#[test]
fn historical_and_job_v2_entries_share_the_only_hog_body() {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let source = fs::read_to_string(manifest.join("src/lib.rs")).unwrap();
    let job = fs::read_to_string(manifest.join("src/bin/job_cpu_hog.rs")).unwrap();
    let hog = fs::read_to_string(manifest.join("src/bin/cpu_hog.rs")).unwrap();
    let progress = fs::read_to_string(manifest.join("src/bin/progress.rs")).unwrap();
    let body = |text: &str, start: &str| {
        let from = text
            .find(start)
            .unwrap_or_else(|| panic!("missing {start}"));
        let rest = &text[from..];
        rest[..rest.find("\n}\n").expect("item end")].to_owned()
    };
    let at = |text: &str, needle: &str| {
        text.find(needle)
            .unwrap_or_else(|| panic!("missing {needle}"))
    };
    // The spin loop exists once in the whole crate, inside the shared body.
    for (file, text) in [
        ("cpu_hog", &hog),
        ("job_cpu_hog", &job),
        ("progress", &progress),
    ] {
        assert!(!text.contains("spin_loop"), "{file} spins on its own");
    }
    assert_eq!(source.matches("core::hint::spin_loop()").count(), 1);
    assert!(body(&source, "pub fn run_cpu_hog_body()").contains("core::hint::spin_loop()"));
    // The historical entry readies, then runs the shared body.
    let historical = body(&source, "pub fn run_cpu_hog(channel: DwHandle)");
    assert!(
        at(&historical, "receive_hog_startup_and_ready(channel)?;")
            < at(&historical, "run_cpu_hog_body()")
    );
    assert!(body(&hog, "fn payload_main(").contains("run_cpu_hog(startup.bootstrap_channel()"));
    // The JobV2 entry validates its startup, prepares, then runs the same body.
    let entry = body(&job, "fn job_cpu_hog_main(");
    let validate = at(&entry, "validate_job_cpu_hog_entry(");
    for argument in [
        "startup.version()",
        "startup.argc()",
        "startup.arg(0)",
        "startup.envc()",
    ] {
        assert!(validate < at(&entry, argument), "{argument}");
    }
    let prepare = at(&entry, "prepare_job_cpu_hog(&mut system");
    assert!(at(&entry, "startup.envc()") < prepare);
    assert!(prepare < at(&entry, "run_cpu_hog_body()"));
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
    let wait_pos = function.find("wait_one(").unwrap();
    let receive_pos = function.find("receive_channel(data_channel").unwrap();
    let parse_pos = function.find("parse_challenge(&bytes, round)").unwrap();
    let reply_pos = function.find("encode_reply(round)").unwrap();
    let submit_pos = function
        .find("submit_dw1b_progress(CHALLENGE_DIGEST)")
        .unwrap();
    assert!(function.contains("DW_SIGNAL_READABLE.0 | DW_SIGNAL_PEER_CLOSED.0"));
    assert!(function.contains("DW_DEADLINE_INFINITE"));
    assert!(function.contains("observed.observed.0 & DW_SIGNAL_READABLE.0 == 0"));
    assert!(
        loop_pos < wait_pos
            && wait_pos < receive_pos
            && receive_pos < parse_pos
            && parse_pos < reply_pos
            && reply_pos < submit_pos
    );
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
