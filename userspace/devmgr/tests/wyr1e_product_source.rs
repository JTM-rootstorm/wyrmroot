use wyrmroot_loader as _;
use wyrmroot_registry_proto as _;
use wyrmroot_runtime as _;
#[cfg(feature = "native-devmgr")]
use {wyrmroot_loader as _, wyrmroot_registry_proto as _, wyrmroot_runtime as _};

use {deepwyrm_syscall as _, wyrmroot_device_proto as _, wyrmroot_devmgr as _};

/// devmgr's role logic, in its original order: the binary's entry file, then
/// `role.rs`, which holds everything `main.rs` held before S2U step 3. Source
/// text because the role's decisions are not yet driven by host tests through
/// the platform seam; S3 converts these rows.
const NATIVE: &str = concat!(
    include_str!("../src/main.rs"),
    include_str!("../src/role.rs")
);

/// Source text until S3: the role runs over the platform seam, but no
/// RecordingPlatform script drives this path yet.
#[test]
fn e8_intentional_terminal_preserves_failure_validation_and_cleanup_state() {
    let driver_branch = &NATIVE[NATIVE.find("if Some(index) == driver_index").unwrap()
        ..NATIVE.find("if Some(index) != publication_index").unwrap()];
    let observe_call = driver_branch.find("observe_driver_failure(").unwrap();
    let observe_call = &driver_branch[observe_call..];
    let observe_call = &observe_call[..observe_call.find(")?;").unwrap()];
    assert!(observe_call.contains("e8_retire_requested"));

    let observe = &NATIVE[NATIVE.find("fn observe_driver_failure<").unwrap()
        ..NATIVE.find("fn retire_driver_publication<").unwrap()];
    let counts = observe.find("counts.bytes != bytes.len()").unwrap();
    let parse = observe.find("control::parse(&bytes)").unwrap();
    let exact_message = observe.find("if message != expected").unwrap();
    let terminal = observe.rfind("record_driver_terminal(").unwrap();
    assert!(counts < parse && parse < exact_message && exact_message < terminal);
    assert!(observe.contains("if peer_closed && counts.bytes == 0 && counts.handles == 0"));

    let terminal_helper = &observe[observe.find("fn record_driver_terminal(").unwrap()..];
    let intentional = terminal_helper
        .find("accept_intentional_driver_terminal(request)")
        .unwrap();
    let unexpected = terminal_helper
        .find("driver_failed(request.endpoint)")
        .unwrap();
    assert!(intentional < unexpected);

    let retired = driver_branch
        .find("send_driver_retired(platform, bootstrap, request)?")
        .unwrap();
    let clear = driver_branch.find("e8_retire_requested = false").unwrap();
    let rebind = driver_branch.find("let rebind_deadline =").unwrap();
    assert!(retired < clear && clear < rebind);
}
