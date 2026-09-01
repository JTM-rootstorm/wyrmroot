use deepwyrm_syscall as _;
use wyrmroot_device_proto as _;
use wyrmroot_devmgr as _;
use wyrmroot_stream_proto as _;
use wyrmroot_uart16550_core as _;
use wyrmroot_uart16550d as _;

const DRIVER: &str = include_str!("../src/main.rs");
const DRIVER_POLICY: &str = include_str!("../src/lib.rs");
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
fn selector31_stage1_blocks_stale_finalize_and_post_ier_interrupt_drains() {
    let begin = DRIVER
        .find("Ok(ControlOutcome::BeginRetire(binding))")
        .unwrap();
    let retired = DRIVER[begin..].find("selector_retiring = true").unwrap() + begin;
    let finalize = DRIVER
        .find("Ok(ControlOutcome::FinalizeRetire(binding))")
        .unwrap();
    let exact = DRIVER[finalize..]
        .find("selector_retirement_binding != Some(binding)")
        .unwrap()
        + finalize;
    assert!(begin < retired && retired < finalize && finalize < exact);

    let wait_gate = DRIVER
        .find("let mut count = if selector_retiring { 1 } else { 2 };")
        .unwrap();
    let interrupt_gate = DRIVER[wait_gate..].find("if !selector_retiring").unwrap() + wait_gate;
    let interrupt_drain = DRIVER.find("if observed.index == 1").unwrap();
    assert!(wait_gate < interrupt_gate && interrupt_gate < interrupt_drain);

    let ier_readback = DRIVER[begin..]
        .find("!driver.selector_interrupts_disabled()")
        .unwrap()
        + begin;
    let stage1_ready = DRIVER[begin..].find("encode_retire_stage1_ready").unwrap() + begin;
    assert!(begin < ier_readback && ier_readback < stage1_ready);
}

#[test]
fn selector31_temt_wait_requires_the_timer_signal_and_checks_sticky_pio_after_lsr() {
    let prove = DRIVER.find("fn prove_transport_empty").unwrap();
    let body = &DRIVER[prove..];
    let waited = body.find("let waited = wait_one(").unwrap();
    let signaled = body[waited..]
        .find("waited.observed.0 & DW_SIGNAL_SIGNALED.0 == 0")
        .unwrap()
        + waited;
    let lsr = body
        .find("let temt = driver.uart_mut().transport_empty();")
        .unwrap();
    let sticky = body[lsr..].find("if pio_failed.get() {").unwrap() + lsr;
    assert!(waited < signaled && signaled < lsr && lsr < sticky);
}

#[test]
fn selector31_rechecks_stream_input_after_final_ack_before_temt() {
    let input_proof = DRIVER.find("fn selector_response_input_drained").unwrap();
    let post_ack = DRIVER
        .find("selector_response_input_drained(driver, control, pio_failed, &mut evidence)")
        .unwrap();
    let temt = DRIVER[post_ack..]
        .find("prove_transport_empty(driver, control, pio_failed, evidence)")
        .unwrap()
        + post_ack;
    assert!(post_ack < temt);
    let proof = &DRIVER[input_proof..];
    assert!(proof.contains("Ok(StreamReadOutcome::WouldBlock) => Ok(())"));
    assert!(proof.contains("StreamReadOutcome::Accepted | StreamReadOutcome::Detached"));
}

#[test]
fn selector31_zero_length_stream_data_is_a_noop_but_not_post_response_data() {
    assert!(DRIVER.contains("fn record_response"));
    let record = DRIVER.find("fn record_response").unwrap();
    let body = &DRIVER[record..];
    assert!(body.contains("if bytes.is_empty()"));
    assert!(body.contains("return Ok(());"));
    assert!(body.contains("self.response_bytes == expected.len()"));
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
fn send_side_peer_close_enters_receive_drain_before_detach() {
    let writer_start = DRIVER.find("fn service_stream_write").unwrap();
    let writer = &DRIVER[writer_start..];
    let send_peer_closed = writer
        .find("status_is(error, DW_STATUS_PEER_CLOSED)")
        .unwrap();
    let pending_result = writer[send_peer_closed..]
        .find("StreamSendResult::PeerClosed")
        .unwrap();
    let resolution = writer[send_peer_closed..]
        .find("driver.resolve_stream_send(peer_close_drain, result)")
        .unwrap();
    assert!(pending_result < resolution);

    let dispatch = DRIVER.find("service_stream_write(driver, control").unwrap();
    let suppression = DRIVER
        .find("!peer_close_drain.is_pending() && driver.wants_stream_writable()")
        .unwrap();
    assert!(suppression < dispatch && dispatch < writer_start);
}

#[test]
fn native_stream_and_teardown_paths_preserve_commit_and_close_order() {
    let prepare = DRIVER.find("driver.prepare_stream_send").unwrap();
    let send = DRIVER
        .find("send_channel(endpoint.handle, &bytes[..size], &[])")
        .unwrap();
    let resolve = DRIVER
        .find("driver.resolve_stream_send(peer_close_drain, result)")
        .unwrap();
    assert!(prepare < send && send < resolve);

    let sent = DRIVER_POLICY.find("StreamSendResult::Sent =>").unwrap();
    let commit = DRIVER_POLICY[sent..]
        .find("self.commit_stream_send()")
        .unwrap();
    assert!(commit != 0);

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
