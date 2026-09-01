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
