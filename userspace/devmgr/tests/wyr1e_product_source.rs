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
