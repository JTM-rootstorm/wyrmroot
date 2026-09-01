use wyrmroot_dw1e3_com2_test as _;

const PROBE: &str = include_str!("../src/main.rs");
const DEVMGR: &str = include_str!("../../devmgr/src/main.rs");
const SYSTEM_INIT: &str = include_str!("../../system-init/src/wyr1c_native.rs");

#[test]
fn evidence_probe_uses_canonical_registry_geometry() {
    assert!(PROBE.contains("let mut connected_bytes = [0; REGISTRY_HEADER_BYTES];"));
    assert!(!PROBE.contains("dw1e3_bind_probe"));
}

#[test]
fn controller_waits_for_generation_exact_devmgr_readiness_before_launching_the_probe() {
    let install = SYSTEM_INIT.split("fn install_publication").nth(1).unwrap();
    assert!(install.contains("let policy = SERIAL_CONSOLE_CONNECTOR_PUBLICATION_POLICY;"));

    let start = SYSTEM_INIT.split("fn start_e3a_probe").nth(1).unwrap();
    let config = start.find("encode_e3a_devmgr_config(").unwrap();
    let ready = start.find("parse_devmgr_ready(&devmgr_ready)").unwrap();
    let launch = start.find("launch_registry_client_actor(").unwrap();
    assert!(config < ready && ready < launch);
    let bind = start
        .find("dw1e3_bind_probe(probe.loaded.process, nonce)")
        .unwrap();
    let configure = start.find("encode_e3a_controller(configure").unwrap();
    assert!(launch < bind && bind < configure);

    let configure = DEVMGR
        .split("ControllerInput::Dw1e3(config) =>")
        .nth(1)
        .unwrap();
    let broker = configure.find("connector_broker = Some(").unwrap();
    let ready = configure.find("encode_devmgr_ready(ready").unwrap();
    let acknowledge = configure
        .find("send_channel(bootstrap, &ready_bytes, &[])")
        .unwrap();
    assert!(broker < ready && ready < acknowledge);
}

#[test]
fn selector31_finalize_is_the_exact_client_release_certificate_before_driver_reap() {
    let close = PROBE
        .find("close_handle(stream).map_err(|_| 41u32)?;")
        .unwrap();
    let peer_closed = PROBE.find("ControllerMessage::StreamPeerClosed").unwrap();
    assert!(close < peer_closed);

    let report = SYSTEM_INIT
        .find("Dw1e3ReportEvent::Driver1PeerClosed")
        .unwrap();
    let finalize = SYSTEM_INIT
        .find("send_e3a_finalize_retire(resident, system)")
        .unwrap();
    assert!(report < finalize);

    let command = DEVMGR
        .split("ControllerInput::Dw1e3DriverCommand(binding, message_type) =>")
        .nth(1)
        .unwrap();
    for required in [
        "selector_binding != Some(binding)",
        "!selector_binding_ready",
        "current.publication_generation != binding.publication_generation",
        "selector_finalize_client_release(current, binding.stream_generation)",
        "selector_retiring_driver = Some(current);",
    ] {
        assert!(command.contains(required), "missing {required}");
    }
    let release = command.find("selector_finalize_client_release").unwrap();
    let forward = command.find("encode_finalize_retire(binding").unwrap();
    assert!(release < forward);

    let reaped = DEVMGR
        .find("let reaped = selector_retiring_driver.take()")
        .unwrap();
    let broker_reaped = DEVMGR[reaped..]
        .find("driver_attempt_reaped(reaped)")
        .unwrap()
        + reaped;
    let empty = DEVMGR[broker_reaped..]
        .find("ConnectorSlot::Empty")
        .unwrap()
        + broker_reaped;
    let clear = DEVMGR[empty..].find("connector_broker = None;").unwrap() + empty;
    assert!(reaped < broker_reaped && broker_reaped < empty && empty < clear);
}

#[test]
fn selector31_binding_ready_and_broker_model_reject_early_or_duplicate_finalize() {
    let service = DEVMGR
        .split("fn service_selector31_driver_control")
        .nth(1)
        .unwrap();
    assert!(service.contains("binding != Some(ready) || *binding_ready"));
    assert!(service.contains("*binding_ready = true;"));

    let model = include_str!("../../devmgr/src/connector.rs");
    for required in [
        "fn selector_finalize_client_release",
        "let ConnectorSlot::Active { attach, .. } = self.slot",
        "self.current != Some(observed_driver)",
        "attach.stream_generation != observed_stream_generation",
        "selector_finalize_rejects_early_duplicate_and_mismatched_attach_without_mutation",
        "selector_reap_before_client_certificate_keeps_u2_blocked",
    ] {
        assert!(model.contains(required), "missing {required}");
    }
}
