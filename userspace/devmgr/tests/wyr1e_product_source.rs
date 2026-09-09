use {deepwyrm_syscall as _, wyrmroot_device_proto as _, wyrmroot_devmgr as _};

const MANIFEST: &str = include_str!("../Cargo.toml");
const NATIVE: &str = include_str!("../src/main.rs");

#[test]
fn e6_feature_enables_the_neutral_staged_connector_without_selector32() {
    assert!(MANIFEST.contains("wyr1e-production = [\"wyr1d-production\", \"wyr1c6-production\"]"));
    assert!(
        NATIVE
            .contains("WYR1-E production and selector-only devmgr policies are mutually exclusive")
    );
    assert!(
        !MANIFEST
            .split("wyr1e-production = ")
            .nth(1)
            .unwrap()
            .lines()
            .next()
            .unwrap()
            .contains("wyr1d-selector32")
    );
}

#[test]
fn connector_broker_activation_is_shared_but_wdr5_remains_selector_only() {
    let activation = &NATIVE[NATIVE.find("fn selector32_driver_ready").unwrap()
        ..NATIVE.find("fn send_d5_controller").unwrap()];
    assert!(activation.contains("activate_connector_broker(resident, broker)"));
    assert!(activation.contains("D5ControllerMessage::DriverReady"));
    let neutral = &activation[activation.find("fn activate_connector_broker").unwrap()..];
    assert!(neutral.contains("ConnectorBroker::new"));
    assert!(!neutral.contains("D5ControllerMessage"));
    assert!(NATIVE.contains(
        "#[cfg(all(feature = \"wyr1e-production\", not(feature = \"wyr1d-selector32\")))]\n                activate_connector_broker"
    ));
}

#[test]
fn production_publication_receiver_uses_the_exact_v1_1_service_generation() {
    let imports = &NATIVE[..NATIVE.find("const FAILURE_BASE").unwrap()];
    assert!(imports.contains(
        "#[cfg(not(any(\n    feature = \"dw1e3-selector31\",\n    feature = \"wyr1d-selector32\",\n    feature = \"wyr1e-production\"\n)))]\nuse wyrmroot_device_proto::controller::INSTALL_BYTES;"
    ));
    assert!(imports.contains(
        "#[cfg(not(any(feature = \"wyr1d-selector32\", feature = \"wyr1e-production\")))]\nuse wyrmroot_device_proto::controller::parse as parse_controller;"
    ));
    assert!(imports.contains(
        "#[cfg(any(feature = \"wyr1d-selector32\", feature = \"wyr1e8-production\"))]\nuse wyrmroot_device_proto::d5_controller::{"
    ));

    let receive = &NATIVE[NATIVE.find("fn receive_controller(").unwrap()
        ..NATIVE.find("fn published_driver(").unwrap()];
    let selected = "#[cfg(any(feature = \"wyr1d-selector32\", feature = \"wyr1e-production\"))]";
    let legacy = "#[cfg(not(any(feature = \"wyr1d-selector32\", feature = \"wyr1e-production\")))]";
    let e7_buffer = receive
        .find(
            "#[cfg(all(\n        not(feature = \"dw1e3-selector31\"),\n        not(feature = \"wyr1d-selector32\"),\n        not(feature = \"wyr1e8-production\"),\n        feature = \"wyr1e-production\"\n    ))]\n    let mut bytes = [0u8; wyrmroot_device_proto::controller_v1_1::RECORD_BYTES];",
        )
        .unwrap();
    let legacy_buffer = receive
        .find(
            "#[cfg(not(any(\n        feature = \"dw1e3-selector31\",\n        feature = \"wyr1d-selector32\",\n        feature = \"wyr1e-production\"\n    )))]\n    let mut bytes = [0u8; INSTALL_BYTES];",
        )
        .unwrap();
    assert!(receive.contains(
        "#[cfg(feature = \"dw1e3-selector31\")]\n    let mut bytes = [0u8; D3_DEVICE_STAGE_BYTES];"
    ));
    assert!(receive.contains(
        "#[cfg(all(\n        not(feature = \"dw1e3-selector31\"),\n        any(feature = \"wyr1d-selector32\", feature = \"wyr1e8-production\")\n    ))]\n    let mut bytes = [0u8; D5_CONTROLLER_BYTES];"
    ));
    let parse = receive
        .find(&format!(
            "{selected}\n    let publication = match wyrmroot_device_proto::controller_v1_1::parse(&bytes[..counts.bytes])"
        ))
        .unwrap();
    assert!(e7_buffer < parse && legacy_buffer < parse);
    let message = receive
        .find(&format!(
            "{selected}\n    let message = publication.controller;"
        ))
        .unwrap();
    let accept = receive
        .find(&format!(
            "{selected}\n    let accepted = resident.accept_publication(publication, counts.handles as u32);"
        ))
        .unwrap();
    assert!(parse < message && message < accept);
    assert!(receive.contains(&format!(
        "{legacy}\n    let message = match parse_controller(&bytes[..counts.bytes])"
    )));
    assert!(receive.contains(&format!(
        "{legacy}\n    let accepted = resident.accept(message, counts.handles as u32);"
    )));

    let d5_gate = receive
        .find("#[cfg(any(feature = \"wyr1d-selector32\", feature = \"wyr1e8-production\"))]\n    if counts.bytes == D5_CONTROLLER_BYTES")
        .unwrap();
    let d5_parse = receive
        .find("parse_d5_controller(&bytes[..counts.bytes])")
        .unwrap();
    assert!(d5_gate < d5_parse && d5_parse < parse);

    let published = &NATIVE[NATIVE.find("fn published_driver(").unwrap()
        ..NATIVE.find("fn selector32_driver_ready(").unwrap()];
    assert!(published.contains("publication_service_generation()"));
    assert!(published.contains(".ok_or(failure(243))?"));
    assert!(!published.contains("active_binding"));
    assert!(!published.contains("endpoint.generation"));
}

#[test]
fn e8_accepts_only_the_exact_current_driver_retire_request() {
    assert!(MANIFEST.contains("wyr1e8-production = [\"wyr1e-production\"]"));
    let controller = &NATIVE[NATIVE
        .find("let (replacement, action) = match input")
        .unwrap()..NATIVE.find("fn receive_controller(").unwrap()];
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
        .find("send_driver_retire(control, &mut resident)?")
        .unwrap();
    let one_shot = e8.find("e8_retire_requested = true").unwrap();
    assert!(validate < broker && broker < attach && attach < duplicate);
    assert!(duplicate < retire && retire < one_shot);
    assert!(e8.contains(
        "#[cfg(feature = \"wyr1e8-production\")]\n                ControllerInput::D5(_) => return Err(failure(313))"
    ));
    assert!(NATIVE.contains(
        "#[cfg(feature = \"wyr1d-selector32\")]\n                ControllerInput::D5(D5ControllerMessage::RequestRetire(identity))"
    ));
}

#[test]
fn e8_intentional_terminal_preserves_failure_validation_and_cleanup_state() {
    let driver_branch = &NATIVE[NATIVE.find("if Some(index) == driver_index").unwrap()
        ..NATIVE.find("if Some(index) != publication_index").unwrap()];
    let observe_call = driver_branch.find("observe_driver_failure(").unwrap();
    let observe_call = &driver_branch[observe_call..];
    let observe_call = &observe_call[..observe_call.find(")?;").unwrap()];
    assert!(observe_call.contains("e8_retire_requested"));

    let observe = &NATIVE[NATIVE.find("fn observe_driver_failure(").unwrap()
        ..NATIVE.find("fn retire_driver_publication(").unwrap()];
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
        .find("send_driver_retired(bootstrap, request)?")
        .unwrap();
    let clear = driver_branch.find("e8_retire_requested = false").unwrap();
    let rebind = driver_branch.find("let rebind_deadline =").unwrap();
    assert!(retired < clear && clear < rebind);
}

#[test]
fn production_connector_services_offer_and_generic_detach_without_test_evidence() {
    assert!(NATIVE.contains("feature = \"wyr1e-production\""));
    let service = &NATIVE[NATIVE.find("fn service_production_driver_control").unwrap()
        ..NATIVE.find("fn service_selector31_driver_control").unwrap()];
    assert!(service.contains("parse_control_v1_1"));
    assert!(service.contains("broker.driver_detached(message)"));
    assert!(!service.contains("WDR5"));
    assert!(!service.contains("selector_report"));
    let offers = &NATIVE[NATIVE.rfind("fn service_connector_offer").unwrap()
        ..NATIVE.find("fn service_production_driver_control").unwrap()];
    assert!(offers.contains("RegistryMessage::ConnectOffer"));
    assert!(offers.contains("ConnectorMessage::ConnectStream"));
    assert!(offers.contains(".accept_stream_ready(ready)"));
    assert!(offers.contains(".client_endpoint_moved()"));
}
