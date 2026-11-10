use deepwyrm_syscall as _;
use wyrmroot_device_proto as _;
use wyrmroot_devmgr as _;
use wyrmroot_loader as _;
use wyrmroot_runtime as _;
use wyrmroot_stream_proto as _;
use wyrmroot_uart16550_core as _;
use wyrmroot_uart16550d as _;

/// The driver role, in its original order: the binary's entry file, then
/// `role.rs`, which holds everything this `main.rs` held before S2U step 3, so
/// every position and slice below keeps its meaning. Source text for the
/// reason each test below gives.
const DRIVER: &str = concat!(
    include_str!("../src/main.rs"),
    include_str!("../src/role.rs")
);
const DRIVER_POLICY: &str = include_str!("../src/lib.rs");
/// devmgr's role, in its original order: the binary's entry file, then
/// `role.rs`, which holds everything devmgr's `main.rs` held before S2U step 3.
/// Source text for the reason each test below gives.

/// Source text until S3: the role runs over the platform seam, but no
/// RecordingPlatform script drives this path yet.
#[test]
fn native_loop_checks_control_and_pio_before_interrupt_ack() {
    // The probe is skipped once the driver is orphaned, so anchor on the call
    // rather than on the binding that used to wrap it.
    let probe = DRIVER.find("probe_control(platform, control)").unwrap();
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

/// Source text until S3: the role runs over the platform seam, but no
/// RecordingPlatform script drives this path yet.
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
            .find("isolate_stream(platform, driver, control)")
            .unwrap();
    assert!(pending < capacity && capacity < drain && drain < blocked && blocked < detach);

    let suppress = DRIVER
        .find("peer_close_drain.include_stream_wait(receive_capacity)")
        .unwrap();
    assert!(suppress < pending);
}

/// Source text until S3: the role runs over the platform seam, but no
/// RecordingPlatform script drives this path yet.
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

    let dispatch = DRIVER
        .find("service_stream_write(platform, driver, control")
        .unwrap();
    let suppression = DRIVER.find("!peer_close_drain.is_pending()").unwrap();
    assert!(DRIVER[..dispatch].contains("graceful_retire.is_none()"));
    assert!(suppression < dispatch && dispatch < writer_start);
}

/// The body of the driver function `name`, up to its closing brace.
fn driver_function(name: &str) -> &'static str {
    let start = DRIVER
        .find(&format!("\nfn {name}<"))
        .unwrap_or_else(|| panic!("the driver role no longer defines {name}"));
    let end = DRIVER[start..]
        .find("\n}\n")
        .unwrap_or_else(|| panic!("{name} has no closing brace"));
    &DRIVER[start..start + end]
}

/// Source text until S3: the role runs over the platform seam, but no
/// RecordingPlatform script drives this path yet. That a sent record commits
/// is held by the host test
/// `send_peer_close_preserves_final_inbound_data_until_empty_queue_proof` in lib.rs.
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

    // Disable the device, then release in the one teardown order. Each
    // position is read inside its own function: a whole-file `rfind` lands on
    // the later failure paths' closes and cannot see this order change.
    let shutdown = driver_function("graceful_shutdown");
    let disable = shutdown
        .find("device_pio_write(driver.resource().handle, 1, 1, 0)")
        .expect("graceful shutdown no longer disables the device");
    let release = shutdown
        .find("release_driver(platform, driver, control, result)")
        .expect("graceful shutdown no longer releases the driver");
    assert!(disable < release);

    let release = driver_function("release_driver");
    let position = |needle: &str| {
        release
            .find(needle)
            .unwrap_or_else(|| panic!("release_driver no longer calls {needle}"))
    };
    let stream = position("driver.detach_stream()");
    let interrupt = position("close_handle(driver.interrupt().handle)");
    let resource = position("close_handle(driver.resource().handle)");
    let control = position("close_handle(control)");
    assert!(stream < interrupt && interrupt < resource && resource < control);
}

/// Source text until S3: the role runs over the platform seam, but no
/// RecordingPlatform script drives this path yet.
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
        .find("release_driver(platform, driver, control, 0)")
        .expect("release after readback")
        + complete;
    assert!(retire < start && start < service);
    assert!(service < receive && receive < fresh_empty);
    assert!(fresh_empty < software_empty && software_empty < temt);
    assert!(temt < complete && complete < disable && disable < readback && readback < release);

    let drain_body = &DRIVER[service..complete];
    assert!(drain_body.contains("temt_probe_due"));
    assert!(drain_body.contains("StreamReadOutcome::PeerClosed"));
    assert!(!drain_body.contains("isolate_stream(platform, driver, control)"));
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
        .find("probe_control(platform, control)")
        .expect("control probe before drain")
        + pending;
    let queued = dispatch[pending..]
        .find("DW_SIGNAL_READABLE.0 != 0")
        .expect("queued control rejection")
        + pending;
    assert!(pending < probe && probe < queued && queued < service);
}

/// Source text: the property holds only where debug assertions are compiled
/// out, and every host test runs with them on, so a host test cannot tell
/// `assert_eq!` from `debug_assert_eq!` here; clippy's
/// `debug_assert_with_mut_call` does not flag the discard moved inside one
/// (checked). The commit's effect in a debug build is host-tested by lib.rs
/// `send_peer_close_preserves_final_inbound_data_until_empty_queue_proof`.
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

/// `DW1_WYR1_FINAL_CLOSURE_CONTRACT.md` §5.3 item 1. Losing the control peer
/// orphans the driver; it does not stop it. The DeviceResource, the Interrupt
/// and the established stream are all retained, and the exact `Retire`
/// handshake stays the only deliberate way to stop serving.
///
/// Source text until S3: the branch lives in the role's syscall loop, which
/// now runs over the platform seam, but no RecordingPlatform script drives it
/// yet. It pins the structure the behaviour depends on; the behaviour itself
/// is a live obligation.
#[test]
fn a_lost_control_peer_orphans_the_driver_instead_of_shutting_it_down() {
    let loop_body = &DRIVER[DRIVER.find("let mut orphaned = false;").unwrap()..];

    // The peer-close branch inside the control arm orphans, and shuts down
    // only when a `Retire` was already admitted.
    let arm = loop_body
        .find("if slot == 0 || control_signals.0 != 0 {")
        .unwrap();
    let peer_closed = loop_body[arm..]
        .find("if signals.0 & DW_SIGNAL_PEER_CLOSED.0 != 0 {")
        .unwrap()
        + arm;
    let post_retire = loop_body[peer_closed..]
        .find("if graceful_retire.is_some() {\n                    return graceful_shutdown(platform, driver, control, 0);")
        .unwrap()
        + peer_closed;
    let orphan = loop_body[peer_closed..].find("orphaned = true;").unwrap() + peer_closed;
    assert!(peer_closed < post_retire && post_retire < orphan);

    // An orphaned driver neither waits on nor probes control again: a closed
    // peer keeps `PEER_CLOSED` asserted, and any reply `service_control` owes
    // would fail the driver.
    assert!(loop_body.contains("if !orphaned {\n            items[count] = DwWaitItemV1 {\n                handle: control,"));
    assert!(loop_body.contains(
        "let control_signals = if orphaned {\n            DwSignals(0)\n        } else {"
    ));

    // Dropping control shifts the wait set down by one; `slot` undoes that so
    // the Interrupt and stream branches stay positional.
    assert!(loop_body.contains("let slot = observed.index + u32::from(orphaned);"));

    // An orphan with no stream left has no service to keep: only devmgr can
    // attach another, and devmgr is gone.
    assert!(loop_body.contains(
        "if count == 0 || (orphaned && driver.stream_endpoint().is_none()) {\n            // Orphaned with no stream left"
    ));

    // A detach report to a closed control peer is dropped, not a driver
    // failure; any other send error still fails. Both detach paths use it.
    let report = DRIVER.split("fn report_detached<").nth(1).unwrap();
    let report = report.split("\n}\n").next().unwrap();
    assert!(
        report.contains("Err(Some(error)) if status_is(error, DW_STATUS_PEER_CLOSED) => Ok(()),")
    );
    assert!(report.contains("Err(_) => Err(()),"));
    let isolate = DRIVER.split("fn isolate_stream<").nth(1).unwrap();
    let isolate = isolate.split("\n}\n").next().unwrap();
    assert!(isolate.contains("report_detached(platform, control, detached)"));
    assert!(!isolate.contains("send_control("));
    let writer = DRIVER.split("fn service_stream_write<").nth(1).unwrap();
    let writer = writer.split("\n}\n").next().unwrap();
    assert!(writer.contains("report_detached(platform, control, detached)?;"));
    assert!(!writer.contains("send_control("));

    // The pre-existing post-`Retire` peer-close shutdown at the top of the
    // loop is untouched.
    let admitted = DRIVER
        .find("if let Some(drain) = graceful_retire.as_mut() {")
        .unwrap();
    assert!(
        DRIVER[admitted..]
            .find("return graceful_shutdown(platform, driver, control, 0);")
            .unwrap()
            < DRIVER[admitted..]
                .find("service_graceful_retire_drain(")
                .unwrap()
    );
}

/// `DIAGNOSTIC_CAUSE_CARRIAGE_CONTRACT.md` §3.2: the receive loop collapses
/// every detach cause onto one outcome, so each producer records its cause
/// before the collapse, and before isolation can fail and lose it.
///
/// Source text until S3: the role runs over the platform seam, but no
/// RecordingPlatform script drives this path yet.
#[test]
fn every_stream_detach_records_its_cause_before_isolating() {
    let receive = DRIVER.split("fn service_stream_read<").nth(1).unwrap();
    let receive = receive.split("\n}\n").next().unwrap();
    assert_eq!(
        receive
            .matches("detached(driver, StreamDetachCause::")
            .count(),
        4
    );
    assert!(!receive.contains("StreamReadOutcome::Detached"));
    // Each site's own block, from its opening brace to its return: the
    // record comes first and the block's only isolation follows it.
    for cause in ["Native(", "Overflow)", "Record(error)"] {
        let site = receive
            .find(&format!("detached(driver, StreamDetachCause::{cause}"))
            .unwrap();
        let open = receive[..site].rfind("{\n").unwrap();
        let close = site + receive[site..].find("return Ok(outcome);").unwrap();
        let block = &receive[open..close];
        assert_eq!(
            block
                .matches("isolate_stream(platform, driver, control)?;")
                .count(),
            1
        );
        assert!(
            site - open
                < block
                    .find("isolate_stream(platform, driver, control)?;")
                    .unwrap()
        );
    }
    let helper = DRIVER.split("fn detached<").nth(1).unwrap();
    assert!(
        helper.contains("driver.record_stream_detach(cause);\n    StreamReadOutcome::Detached")
    );
}
