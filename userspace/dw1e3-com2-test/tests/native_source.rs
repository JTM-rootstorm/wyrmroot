use wyrmroot_dw1e3_com2_test as _;

const PROBE: &str = include_str!("../src/main.rs");

#[test]
fn evidence_probe_binds_only_after_the_production_stream_is_attached() {
    let connected = PROBE
        .find("let stream = stream_handles[0].handle;")
        .unwrap();
    let bind = PROBE.find("dw1e3_bind_probe(nonce)").unwrap();
    let attached = PROBE.find("ControllerMessage::Attached {").unwrap();

    assert!(connected < bind && bind < attached);
}
