use deepwyrm_syscall as _;
use wyrmroot_device_proto as _;
use wyrmroot_devmgr as _;
use wyrmroot_stream_proto as _;
use wyrmroot_uart16550_core as _;
use wyrmroot_uart16550d as _;

const DRIVER: &str = include_str!("../src/main.rs");
const DEVMGR: &str = include_str!("../../devmgr/src/main.rs");
const DEVMGR_MANIFEST: &str = include_str!("../../devmgr/Cargo.toml");
const RETAINED_MANIFEST: &str = include_str!("../../wyr1-retained-stubs/Cargo.toml");

#[test]
fn native_loop_checks_control_and_pio_before_interrupt_ack() {
    let probe = DRIVER
        .find("let control_signals = match probe_control(control)")
        .unwrap();
    let interrupt = DRIVER.find("if observed.index == 1").unwrap();
    assert!(probe < interrupt);

    let peer_closed = DRIVER
        .find("signals.0 & DW_SIGNAL_PEER_CLOSED.0 != 0")
        .unwrap();
    let readable = DRIVER
        .find("signals.0 & DW_SIGNAL_READABLE.0 != 0")
        .unwrap();
    assert!(peer_closed < readable);

    let drain = DRIVER.find("driver.drain_interrupt()").unwrap();
    let ack = drain
        + DRIVER[drain..]
            .find("driver.acknowledge_interrupt")
            .unwrap();
    assert!(drain < ack);
    assert!(
        DRIVER[ack..].contains("driver.acknowledge_interrupt(drained, !pio_failed.get(), |handle|")
    );
}

#[test]
fn native_stream_and_teardown_paths_preserve_commit_and_close_order() {
    let prepare = DRIVER.find("driver.prepare_stream_send").unwrap();
    let send = DRIVER
        .find("send_channel(endpoint.handle, &bytes[..size], &[])")
        .unwrap();
    let commit = DRIVER.find("driver.commit_stream_send()").unwrap();
    assert!(prepare < send && send < commit);

    let disable = DRIVER
        .rfind("device_pio_write(driver.resource().handle, 1, 1, 0)")
        .unwrap();
    let stream = DRIVER.rfind("driver.detach_stream()").unwrap();
    let interrupt = DRIVER
        .rfind("close_handle(driver.interrupt().handle)")
        .unwrap();
    let resource = DRIVER
        .rfind("close_handle(driver.resource().handle)")
        .unwrap();
    let control = DRIVER.rfind("close_handle(control)").unwrap();
    assert!(disable < stream && stream < interrupt && interrupt < resource && resource < control);
}

#[test]
fn d3_product_gate_cannot_select_the_historical_selector29_actor() {
    assert!(DEVMGR_MANIFEST.contains("wyr1d-production = [\"wyr1c5-production\"]"));
    assert!(DEVMGR_MANIFEST.contains("wyr1c6-selector29 = [\"wyr1c6-production\"]"));
    assert!(!DEVMGR_MANIFEST.contains("wyr1c6-selector29 = [\"wyr1d-production\"]"));
    assert!(
        DEVMGR.contains("#[cfg(feature = \"wyr1d-production\")]\n    return launch_driver_staged")
    );
    assert!(DEVMGR.contains(
        "#[cfg(all(feature = \"wyr1c5-production\", not(feature = \"wyr1d-production\")))]\nfn launch_driver_with_historical_bundle"
    ));
    assert!(!RETAINED_MANIFEST.contains("wyr1d-production"));
}
