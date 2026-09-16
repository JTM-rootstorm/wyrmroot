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
    // The probe is skipped once the driver is orphaned, so anchor on the call
    // rather than on the binding that used to wrap it.
    let probe = DRIVER.find("probe_control(control)").unwrap();
    let interrupt = DRIVER.find("if slot == 1").unwrap();
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
        .find("let mut items = [DwWaitItemV1::default(); 3];")
        .unwrap();
    let interrupt_gate = DRIVER[wait_gate..].find("if !selector_retiring {").unwrap() + wait_gate;
    let interrupt_drain = DRIVER.find("if slot == 1").unwrap();
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
    assert!(proof.contains("loop {"));
    assert!(proof.contains(
        "Ok(StreamReadOutcome::WouldBlock | StreamReadOutcome::PeerClosed) => return Ok(())"
    ));
    assert!(proof.contains("Ok(StreamReadOutcome::EmptyData) => continue"));
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
    let receive = DRIVER.find("fn service_stream_read").unwrap();
    let receive_body = &DRIVER[receive..];
    assert!(receive_body.contains("return Ok(StreamReadOutcome::EmptyData);"));
}

#[test]
fn selector31_queue_proof_drains_one_or_many_empty_records_but_rejects_nonempty_data() {
    let proof = DRIVER.find("fn selector_response_input_drained").unwrap();
    let body = &DRIVER[proof..];
    let empty = body
        .find("Ok(StreamReadOutcome::EmptyData) => continue")
        .unwrap();
    let clear = body
        .find("Ok(StreamReadOutcome::WouldBlock | StreamReadOutcome::PeerClosed) => return Ok(())")
        .unwrap();
    let reject = body
        .find("StreamReadOutcome::Accepted | StreamReadOutcome::Detached")
        .unwrap();
    // The clean observation is the only return-success arm; empty records
    // loop back into the same receive proof and nonempty records fail.
    assert!(clear < empty && empty < reject);
}

#[test]
fn startup_and_stream_peer_close_precedence_is_explicit() {
    assert_eq!(DRIVER.matches("!startup_control_is_readable(").count(), 2);

    let pending = DRIVER.find("peer_close_drain.is_pending()").unwrap();
    let capacity = pending
        + DRIVER[pending..]
            .find("while driver.wants_stream_readable()")
            .unwrap();
    let drain = capacity + DRIVER[capacity..].find("service_stream_read(").unwrap();
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
fn selector32_drain_is_post_ack_fresh_queue_and_hardware_proof() {
    let proof = DRIVER
        .split("fn service_d5_drain")
        .nth(1)
        .unwrap()
        .split("fn selector_response_input_drained")
        .next()
        .unwrap();
    let receive = proof
        .find("service_stream_read(driver, control, pio_failed, fence)")
        .unwrap();
    let empty = proof.find("channel_empty = true").unwrap();
    let software = proof.find("let software_empty").unwrap();
    let hardware = proof.find("driver.uart_mut().transport_empty()").unwrap();
    let send = proof.find("send_channel(control, &bytes, &[])").unwrap();
    let commit = proof.find("fence.sent(identity)").unwrap();
    assert!(
        receive < empty
            && empty < software
            && software < hardware
            && hardware < send
            && send < commit
    );
    assert!(proof.contains("fence.ready(channel_empty, software_empty, true).is_none()"));
    assert!(proof.contains("fence.ready(channel_empty, software_empty, temt)"));
    let ack = DRIVER.find("driver.acknowledge_interrupt(drained").unwrap();
    let recorded = DRIVER.find("d5.irq_acknowledged()").unwrap();
    assert!(ack < recorded);
    assert!(DEVMGR.contains("!selector32_drain.permits_retire(identity)"));
    let relay = DEVMGR
        .split("fn service_selector32_driver_control")
        .nth(1)
        .unwrap();
    assert!(
        relay
            .find(".validate_completion(identity, broker)")
            .unwrap()
            < relay.find("send_d5_controller").unwrap()
    );
    assert!(
        relay.find("send_d5_controller").unwrap() < relay.find(".forwarded(identity)").unwrap()
    );
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
    let suppression = DRIVER.find("!peer_close_drain.is_pending()").unwrap();
    assert!(DRIVER[..dispatch].contains("graceful_retire.is_none()"));
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
fn ordinary_retire_drains_raw_tx_and_temt_before_ier_zero_release() {
    let retire = DRIVER
        .find("Ok(ControlOutcome::Retire) => {")
        .expect("ordinary Retire branch");
    let start = DRIVER[retire..]
        .find("GracefulRetireDrain::new")
        .expect("bounded production drain")
        + retire;
    let service = DRIVER
        .find("fn service_graceful_retire_drain")
        .expect("production drain service");
    let receive = DRIVER[service..]
        .find("service_stream_read(")
        .expect("raw receive")
        + service;
    let fresh_empty = DRIVER[service..]
        .find("drain.observe_stream_empty()")
        .expect("fresh receive-side empty")
        + service;
    let software_empty = DRIVER[service..]
        .find("driver.tx_free() == wyrmroot_uart16550_core::RING_CAPACITY")
        .expect("software TX empty")
        + service;
    let temt = DRIVER[service..]
        .find("driver.uart_mut().transport_empty()")
        .expect("hardware transport empty")
        + service;
    let complete = DRIVER
        .find("fn complete_graceful_retire")
        .expect("drained retirement completion");
    let disable = DRIVER[complete..]
        .find("driver.begin_graceful_retire()")
        .expect("IER zero transition")
        + complete;
    let readback = DRIVER[complete..]
        .find("driver.graceful_retire_interrupts_disabled()")
        .expect("IER zero readback")
        + complete;
    let release = DRIVER[complete..]
        .find("release_driver(driver, control, 0)")
        .expect("release after readback")
        + complete;
    assert!(retire < start && start < service);
    assert!(service < receive && receive < fresh_empty);
    assert!(fresh_empty < software_empty && software_empty < temt);
    assert!(temt < complete && complete < disable && disable < readback && readback < release);

    let drain_body = &DRIVER[service..complete];
    assert!(drain_body.contains("temt_probe_due"));
    assert!(drain_body.contains("StreamReadOutcome::PeerClosed"));
    assert!(!drain_body.contains("isolate_stream(driver, control)"));
    assert!(!drain_body.contains("peer_close_drain"));

    let receive = DRIVER
        .split("fn service_stream_read")
        .nth(1)
        .expect("stream receive helper");
    assert!(receive.contains(
        "status_is(error, DW_STATUS_WOULD_BLOCK) => {\n            return Ok(StreamReadOutcome::WouldBlock)"
    ));
    assert!(receive.contains(
        "status_is(error, DW_STATUS_PEER_CLOSED) => {\n            return Ok(StreamReadOutcome::PeerClosed)"
    ));

    let dispatch = &DRIVER[..service];
    let pending = dispatch
        .rfind("if let Some(drain) = graceful_retire.as_mut()")
        .expect("pending Retire dispatch");
    let probe = dispatch[pending..]
        .find("probe_control(control)")
        .expect("control probe before drain")
        + pending;
    let queued = dispatch[pending..]
        .find("DW_SIGNAL_READABLE.0 != 0")
        .expect("queued control rejection")
        + pending;
    assert!(pending < probe && probe < queued && queued < service);
}

#[test]
fn native_stream_commit_consumes_uart_prefix_in_optimized_builds() {
    let commit = DRIVER_POLICY.find("pub fn commit_stream_send").unwrap();
    let body = &DRIVER_POLICY[commit
        ..DRIVER_POLICY[commit..]
            .find("pub const fn pending_stream_bytes")
            .unwrap()
            + commit];
    let discard = body
        .find("let discarded = self.uart.discard_rx(self.pending_rx_len)")
        .unwrap();
    let invariant = body
        .find("assert_eq!(\n                discarded, self.pending_rx_len")
        .unwrap();
    let clear = body.find("self.pending_rx_len = 0").unwrap();
    assert!(discard < invariant && invariant < clear);
    assert!(!body.contains("debug_assert_eq!"));
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

/// `DW1_WYR1_FINAL_CLOSURE_CONTRACT.md` §5.3 item 1. Losing the control peer
/// orphans the driver; it does not stop it. The DeviceResource, the Interrupt
/// and the established stream are all retained, and the exact `Retire`
/// handshake stays the only deliberate way to stop serving.
///
/// This is a source-contract test because the branch lives in the binary's
/// syscall loop, not in the testable policy library. It pins the structure the
/// behaviour depends on; the behaviour itself is a live obligation.
#[test]
fn a_lost_control_peer_orphans_the_driver_instead_of_shutting_it_down() {
    let loop_body = &DRIVER[DRIVER.find("let mut orphaned = false;").unwrap()..];

    // The peer-close branch inside the control arm orphans, and shuts down
    // only when a `Retire` was already admitted.
    let arm = loop_body.find("if slot == 0 || control_signals.0 != 0 {").unwrap();
    let peer_closed = loop_body[arm..]
        .find("if signals.0 & DW_SIGNAL_PEER_CLOSED.0 != 0 {")
        .unwrap()
        + arm;
    let post_retire = loop_body[peer_closed..]
        .find("if graceful_retire.is_some() {\n                    return graceful_shutdown(driver, control, 0);")
        .unwrap()
        + peer_closed;
    let orphan = loop_body[peer_closed..].find("orphaned = true;").unwrap() + peer_closed;
    assert!(peer_closed < post_retire && post_retire < orphan);

    // An orphaned driver neither waits on nor probes control again: a closed
    // peer keeps `PEER_CLOSED` asserted, and any reply `service_control` owes
    // would fail the driver.
    assert!(loop_body.contains("if !orphaned {\n            items[count] = DwWaitItemV1 {\n                handle: control,"));
    assert!(loop_body.contains("let control_signals = if orphaned {\n            DwSignals(0)\n        } else {"));

    // Dropping control shifts the wait set down by one; `slot` undoes that so
    // the Interrupt and stream branches stay positional.
    assert!(loop_body.contains("let slot = observed.index + usize::from(orphaned);"));

    // An orphan with neither an Interrupt nor a stream has no service to keep.
    assert!(loop_body.contains("if count == 0 {"));

    // The pre-existing post-`Retire` peer-close shutdown at the top of the
    // loop is untouched.
    let admitted = DRIVER
        .find("if let Some(drain) = graceful_retire.as_mut() {")
        .unwrap();
    assert!(
        DRIVER[admitted..]
            .find("return graceful_shutdown(driver, control, 0);")
            .unwrap()
            < DRIVER[admitted..].find("service_graceful_retire_drain(").unwrap()
    );
}
