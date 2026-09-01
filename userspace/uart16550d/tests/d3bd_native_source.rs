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
fn selector31_allows_an_empty_coalesced_ack_epoch_after_the_challenge_drain() {
    let record = DRIVER.find("fn record(&mut self, bytes: &[u8])").unwrap();
    let body = &DRIVER[record..];
    let empty = body.find("if bytes.is_empty()").unwrap();
    let reported = body.find("if self.reported").unwrap();
    assert!(empty < reported);
}

#[test]
fn startup_and_stream_peer_close_precedence_is_explicit() {
    assert_eq!(DRIVER.matches("!startup_control_is_readable(").count(), 2);

    let pending = DRIVER.find("peer_close_drain.is_pending()").unwrap();
    let capacity = pending
        + DRIVER[pending..]
            .find("while driver.wants_stream_readable()")
            .unwrap();
    let drain = capacity
        + DRIVER[capacity..]
            .find("service_stream_read(driver, control, pio_failed)")
            .unwrap();
    let blocked = drain
        + DRIVER[drain..]
            .find("StreamReadOutcome::WouldBlock")
            .unwrap();
    let detach = blocked
        + DRIVER[blocked..]
            .find("isolate_stream(driver, control)")
            .unwrap();
    assert!(pending < capacity && capacity < drain && drain < blocked && blocked < detach);

    let suppress = DRIVER
        .find("peer_close_drain.include_stream_wait(receive_capacity)")
        .unwrap();
    assert!(suppress < pending);
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
