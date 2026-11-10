#[cfg(feature = "native-devmgr")]
use {wyrmroot_loader as _, wyrmroot_registry_proto as _, wyrmroot_runtime as _};

use {deepwyrm_syscall as _, wyrmroot_device_proto as _, wyrmroot_devmgr as _};

const MANIFEST: &str = include_str!("../Cargo.toml");
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
fn e8_accepts_only_the_exact_current_driver_retire_request() {
    assert!(MANIFEST.contains("wyr1e8-production = [\"wyr1e-production\"]"));
    let controller = &NATIVE[NATIVE
        .find("let (replacement, action) = match input")
        .unwrap()..NATIVE.find("fn receive_controller<").unwrap()];
    let e8 = &controller[controller
        .find("#[cfg(feature = \"wyr1e8-production\")]\n                ControllerInput::D5(D5ControllerMessage::RequestRetire(identity))")
        .unwrap()..];
    let validate = e8.find("identity != current.d5_identity()").unwrap();
    let broker = e8.find("broker.current() != Some(current)").unwrap();
    let attach = e8
        .find("ConnectorSlot::Active { attach, .. } if attach.driver == current")
        .unwrap();
    let duplicate = e8.find("e8_retire_requested").unwrap();
    let retire = e8
        .find("send_driver_retire(platform, control, &mut resident)?")
        .unwrap();
    let one_shot = e8.find("e8_retire_requested = true").unwrap();
    assert!(validate < broker && broker < attach && attach < duplicate);
    assert!(duplicate < retire && retire < one_shot);
    assert!(e8.contains(
        "#[cfg(feature = \"wyr1e8-production\")]\n                ControllerInput::D5(_) => return Err(failure(313))"
    ));
}

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

