use super::*;

/// F3A.7k. devmgr's death also withdraws its publication, and registryd
/// completes consoled's watch with generation 0. Both registry arms must
/// keep serving on a withdrawal and rebuild only on a real republication.
///
/// Still a text test: both arms are inside the role's event loop, which
/// moved to `role.rs` in S2U step 3 but which no host test drives yet.
/// `MAIN` is the binary's old text in its old order, `main.rs` then
/// `role.rs`, so every count and position below keeps its meaning.
#[test]
fn a_withdrawn_publication_keeps_the_session_serving() {
    const MAIN: &str = concat!(include_str!("main.rs"), include_str!("role.rs"));
    let main: std::string::String = MAIN.chars().filter(|c| !c.is_whitespace()).collect();
    assert!(main.contains(
        "constfnpublication_withdrawn(service_generation:u64)->bool{service_generation==0}"
    ));
    let guarded = "ifpublication_withdrawn(receive_publication_change(";
    assert_eq!(
        main.matches(guarded).count(),
        2,
        "both registry arms check for a withdrawal"
    );
    for (at, _) in main.match_indices(guarded) {
        let arm = &main[at..at + 300];
        let keep = arm
            .find("continue;")
            .expect("a withdrawal does not keep serving");
        let rebuild = arm
            .find("recover_serial(")
            .or_else(|| arm.find("LaunchWaitOutcome::SerialLost"))
            .expect("a republication no longer rebuilds the session");
        assert!(keep < rebuild);
    }
    // Exactly the withdrawal test, and exactly `continue` when it holds, in
    // both arms. (Both pass `serial` directly since the event loop's
    // needless `&mut` reborrow went; see the S2 integration commit. Both
    // pass the role's `platform` first since S2U step 3.) The two negative
    // checks below name the same spelling, or they would pass vacuously.
    assert_eq!(
        main.matches(
            "ifpublication_withdrawn(receive_publication_change(platform,authorities,serial)?){continue;}"
        )
        .count(),
        2,
        "a registry arm lost its exact withdrawal guard"
    );
    // No registry arm may rebuild without asking first.
    assert!(
        !main.contains("receive_publication_change(platform,authorities,serial)?;recover_serial(")
    );
    assert!(!main.contains(
        "receive_publication_change(platform,authorities,serial)?;returnOk(LaunchWaitOutcome::SerialLost)"
    ));
}

/// F3A.7k. A witness released while raw custody holds means devmgr is gone,
/// not the serial line, and closure contract §5.4 requires the console and
/// the live shell to keep serving. Both wait loops must drop the witness and
/// carry on; neither may tear the shell down or report the serial lost.
///
/// Still a text test: both wait loops are in the role, which no host test
/// drives yet. `MAIN` is `main.rs` then `role.rs`, the binary's old text in
/// its old order.
#[test]
fn an_orphaned_witness_is_dropped_and_the_session_keeps_serving() {
    const MAIN: &str = concat!(include_str!("main.rs"), include_str!("role.rs"));
    let squeeze = |text: &str| -> std::string::String {
        text.chars().filter(|c| !c.is_whitespace()).collect()
    };
    let main = squeeze(MAIN);
    let helper = main
        .find(
            "fndrop_orphaned_witness<P:ConsoledPlatform>(platform:&mutP,serial:&mutSerialSession,)",
        )
        .expect("the orphaned-witness helper is gone");
    let helper = &main[helper..helper + 300];
    assert!(helper.contains("serial.release_witness.take()"));
    assert!(helper.contains("close_handle(witness)"));

    let observed = "observe_release_witness(";
    let mut sites = 0;
    for (at, _) in main.match_indices("ifwitness_index==Some(") {
        let branch = &main[at..at + 400];
        let wyrmsh = branch.find("{").expect("a witness branch has no body");
        let arm = &branch[wyrmsh..];
        let arm = &arm[..arm.find("}").expect("the wyrmsh arm never closes")];
        let observe = arm
            .find(observed)
            .expect("the release is not validated first");
        let drop = arm
            .find("drop_orphaned_witness(")
            .expect("the witness is not dropped");
        assert!(observe < drop);
        assert!(arm[drop..].contains("continue;"));
        assert!(!arm.contains("recover_serial("));
        assert!(!arm.contains("SerialLost"));
        sites += 1;
    }
    assert_eq!(sites, 2, "both wait loops watch the witness");
    // A dropped witness must stop being waited on, not fail the next wait.
    assert_eq!(
        main.matches("serial.release_witness.map(|witness|").count(),
        2
    );
}

/// The supervision half of F3A.7g.
///
/// The property is a decision inside one role function, which no host
/// test drives yet, so it is read out of the source rather than left
/// unstated. `MAIN` is `main.rs` then `role.rs`, the binary's old text in
/// its old order; the slice below still ends at the next top-level `fn`,
/// and starts at `fn recover_terminal_child<` since the function now opens
/// with its platform parameter list.
///
/// Written against positions rather than presence: a guard that is
/// deleted, moved after the relaunch, or joined by a second relaunch all
/// fail. A substring test for `session_shutdown` alone would survive all
/// three.
#[test]
fn terminal_recovery_checks_for_a_session_shutdown_before_it_relaunches() {
    const MAIN: &str = concat!(include_str!("main.rs"), include_str!("role.rs"));
    const SIGNATURE: &str = "fn recover_terminal_child<";

    let start = MAIN
        .find(SIGNATURE)
        .expect("recover_terminal_child is gone");
    let body = &MAIN[start + SIGNATURE.len()..];
    let end = body
        .find("\nfn ")
        .expect("recover_terminal_child never ends");
    let body = &body[..end];

    let guard = body
        .find("if child.session_shutdown {")
        .expect("terminal recovery no longer asks whether the session ended");
    let ended = body
        .find("return Ok(TerminalOutcome::SessionEnded);")
        .expect("the shutdown guard no longer ends the session");
    let relaunch = body
        .find("*child = launch_child(")
        .expect("terminal recovery no longer relaunches at all");

    assert!(
        guard < ended && ended < relaunch,
        "the session-shutdown guard must decide before the relaunch: \
         guard {guard}, end {ended}, relaunch {relaunch}"
    );
    assert_eq!(
        body.matches("launch_child(").count(),
        1,
        "a second relaunch in this function would bypass the guard"
    );
}

#[test]
fn direct_release_witness_is_message_free_and_raw_closes_first() {
    assert_eq!(
        classify_release_witness(false, true),
        ReleaseWitnessEvent::Released
    );
    for (readable, peer_closed) in [(false, false), (true, false), (true, true)] {
        assert_eq!(
            classify_release_witness(readable, peer_closed),
            ReleaseWitnessEvent::Malformed
        );
    }

    let mut order = [0u64; 2];
    let mut count = 0;
    assert!(release_raw_then_witness(41, Some(42), |handle| {
        order[count] = handle;
        count += 1;
        true
    }));
    assert_eq!(order, [41, 42]);

    count = 0;
    assert!(release_raw_then_witness(43, None, |handle| {
        order[count] = handle;
        count += 1;
        true
    }));
    assert_eq!(count, 1);
    assert_eq!(order[0], 43);

    count = 0;
    assert!(!release_raw_then_witness(51, Some(52), |handle| {
        order[count] = handle;
        count += 1;
        handle != 51
    }));
    assert_eq!(order, [51, 52]);
}

#[test]
fn fatal_event_loop_cleanup_orders_serial_before_watch_and_child() {
    let log = std::cell::Cell::new(0u16);
    let mut serial = ();
    let mut child = ();
    let cleaned = cleanup_after_event_loop_failure(
        &mut (),
        &mut serial,
        &mut child,
        |_, _| {
            log.set(log.get() * 10 + 1);
            false
        },
        |_, _| {
            log.set(log.get() * 10 + 2);
            true
        },
        |_, _| {
            log.set(log.get() * 10 + 3);
            true
        },
    );
    assert!(!cleaned);
    assert_eq!(log.get(), 123);
}

fn correlation(value: u64) -> SerialCorrelation {
    SerialCorrelation {
        registry_generation: 1,
        registry_endpoint_id: 1,
        registry_endpoint_generation: 1,
        publication_generation: value,
        connector_client_transaction: value,
        device_role: 1,
        device_bundle: value,
        driver_attempt: value,
        driver_control_endpoint_id: value,
        driver_control_endpoint_generation: value,
        attach_transaction: value,
        stream_generation: value,
    }
}
fn connect(model: &mut ConsoleModel, value: u64, now: u64) {
    let serial = correlation(value);
    model
        .begin_connect(ConnectRequest {
            registry_generation: serial.registry_generation,
            registry_endpoint_id: serial.registry_endpoint_id,
            registry_endpoint_generation: serial.registry_endpoint_generation,
            requested_publication_generation: serial.publication_generation,
            connector_client_transaction: serial.connector_client_transaction,
        })
        .unwrap();
    model.attach_connected(serial, now).unwrap();
}
fn close_serial(model: &mut ConsoleModel, now: u64) -> RecoveryAction {
    let snapshot = model.snapshot();
    model
        .serial_peer_closed(
            snapshot.serial.unwrap(),
            snapshot.console_generation.unwrap(),
            now,
        )
        .unwrap()
}
const fn cleanup_evidence() -> LaunchCleanupEvidence {
    LaunchCleanupEvidence {
        consoled_peers_closed: [true; 3],
        unmoved_child_peers_closed: [true; 3],
        moved_child_peers_revoked: [true; 3],
    }
}
fn launch(model: &mut ConsoleModel) -> EventGeneration {
    let mut tx = model.begin_child_launch(100).unwrap();
    for kind in [StreamKind::Stdin, StreamKind::Stdout, StreamKind::Stderr] {
        tx.move_child_peer(kind).unwrap();
    }
    model.commit_child_launch(&mut tx, 200).unwrap().ids.into()
}
fn live() -> (ConsoleModel, EventGeneration) {
    let mut model = ConsoleModel::new();
    connect(&mut model, 1, 0);
    let event = launch(&mut model);
    (model, event)
}

#[test]
fn quiescence_stages_native_output_and_waits_for_serial_commit() {
    let (mut model, event) = live();
    let mut polls = 0;
    assert_eq!(
        model.poll_output_quiescence(event, |source, output| {
            polls += 1;
            let bytes: &[u8] = match source {
                OutputSource::Stdout => b"redraw\n",
                OutputSource::Stderr => b"diagnostic\n",
            };
            output[..bytes.len()].copy_from_slice(bytes);
            Ok(Some(bytes.len()))
        }),
        Ok(false)
    );
    assert_eq!(polls, 2);
    assert_eq!(
        model.poll_output_quiescence(event, |_, _| panic!("queued output must drain first")),
        Ok(false)
    );
    let mut bytes = [0u8; FAIR_SOURCE_BYTES_PER_TURN];
    let mut committed = std::vec::Vec::new();
    while let Some(reservation) = model.reserve_serial_tx(&mut bytes).unwrap() {
        let original = bytes[..reservation.length].to_vec();
        model.release_serial_tx(reservation).unwrap();
        let retry = model.reserve_serial_tx(&mut bytes).unwrap().unwrap();
        assert_eq!(&bytes[..retry.length], original.as_slice());
        committed.extend_from_slice(&bytes[..retry.length]);
        model.commit_serial_tx(retry).unwrap();
    }
    assert_eq!(committed, b"redraw\r\ndiagnostic\r\n");
    assert_eq!(
        model.poll_output_quiescence(event, |_, _| {
            polls += 1;
            Ok(None)
        }),
        Ok(true)
    );
    assert_eq!(
        polls, 4,
        "both live streams must freshly report WOULD_BLOCK"
    );
}

#[test]
fn quiescence_rejects_peer_loss_and_invalid_read_counts() {
    for bad in [
        Ok(Some(0)),
        Ok(Some(FAIR_SOURCE_BYTES_PER_TURN + 1)),
        Err(ModelError::ChildDisconnected),
    ] {
        let (mut model, event) = live();
        assert!(model.poll_output_quiescence(event, |_, _| bad).is_err());
        assert_eq!(model.snapshot().stdout_queued, 0);
        assert_eq!(model.snapshot().stderr_queued, 0);
    }
}

#[test]
fn selected_child_policy_preserves_historical_default() {
    assert_eq!(
        (ChildPolicy::selected(), ChildPolicy::selected().path()),
        (ChildPolicy::Wyrmsh, "system/wyrmsh")
    );
}

#[test]
fn status_snapshot_maps_exact_local_state_without_authority_ids() {
    use wyrmroot_console_proto::{
        FLAG_CHILD_PRESENT, FLAG_PENDING_LAUNCH, FLAG_SERIAL_PRESENT, State,
    };

    let (model, event) = live();
    let snapshot = model.status_snapshot().unwrap();
    assert_eq!(snapshot.state, State::Active);
    assert_eq!(
        snapshot.flags & (FLAG_SERIAL_PRESENT | FLAG_CHILD_PRESENT),
        FLAG_SERIAL_PRESENT | FLAG_CHILD_PRESENT
    );
    assert_eq!(snapshot.flags & FLAG_PENDING_LAUNCH, 0);
    assert_eq!(
        snapshot.serial_registry_generation,
        event.serial.registry_generation
    );
    assert_eq!(
        snapshot.publication_generation,
        event.serial.publication_generation
    );
    assert_eq!(snapshot.device_bundle, event.serial.device_bundle);
    assert_eq!(snapshot.driver_attempt, event.serial.driver_attempt);
    assert_eq!(
        snapshot.raw_stream_generation,
        event.serial.stream_generation
    );
    assert_eq!(snapshot.child_generation, event.child_generation);
    assert_eq!(snapshot.outer_job, event.child_job);
    assert_eq!(snapshot.outer_launch_transaction, event.child_launch);
    assert_eq!(snapshot.live_peer_mask, 0b111);
}

#[test]
fn pending_launch_snapshot_has_no_child_identity() {
    use wyrmroot_console_proto::{FLAG_CHILD_PRESENT, FLAG_PENDING_LAUNCH, FLAG_SERIAL_PRESENT};

    let mut model = ConsoleModel::new();
    connect(&mut model, 1, 0);
    let launch = model.begin_child_launch(91).unwrap();
    let snapshot = model.status_snapshot().unwrap();
    assert_eq!(snapshot.flags & FLAG_SERIAL_PRESENT, FLAG_SERIAL_PRESENT);
    assert_eq!(snapshot.flags & FLAG_PENDING_LAUNCH, FLAG_PENDING_LAUNCH);
    assert_eq!(snapshot.flags & FLAG_CHILD_PRESENT, 0);
    assert_eq!(snapshot.child_generation, 0);
    assert_eq!(snapshot.outer_job, 0);
    assert_eq!(snapshot.outer_launch_transaction, 0);
    assert_eq!(snapshot.live_peer_mask, 0);
    let token = model.abort_child_launch(launch).unwrap();
    model
        .complete_abort_child_launch(&token, cleanup_evidence())
        .unwrap();
}

#[test]
fn status_codec_session_and_console_model_form_one_read_only_transport() {
    use wyrmroot_console_proto::{
        FLAG_CHILD_PRESENT, Header, Message, Relationship, SNAPSHOT_BYTES, StatusSession, decode,
        encode_query, encode_snapshot,
    };

    let mut model = ConsoleModel::new();
    connect(&mut model, 1, 0);
    let mut launch = model.begin_child_launch(91).unwrap();
    let relationship = Relationship {
        console_generation: launch.console_generation(),
        status_generation: 77,
        child_generation: launch.child_generation(),
        outer_launch_transaction: launch.outer_launch_transaction(),
    };
    let mut session = StatusSession::new(relationship).unwrap();
    let mut wire = [0u8; SNAPSHOT_BYTES];

    for (transaction_id, child_present) in [(1, false), (2, true)] {
        if child_present {
            for kind in [StreamKind::Stdin, StreamKind::Stdout, StreamKind::Stderr] {
                launch.move_child_peer(kind).unwrap();
            }
            model.commit_child_launch(&mut launch, 92).unwrap();
        }
        let header = Header {
            transaction_id,
            console_generation: relationship.console_generation,
            status_generation: relationship.status_generation,
        };
        let query_size = encode_query(header, &mut wire).unwrap();
        assert_eq!(decode(&wire[..query_size], 0), Ok(Message::Query(header)));
        let ticket = session.admit(header).unwrap();
        let snapshot = model.status_snapshot().unwrap();
        assert_eq!(snapshot.flags & FLAG_CHILD_PRESENT != 0, child_present);
        if child_present {
            assert_eq!(snapshot.child_generation, relationship.child_generation);
            assert_eq!(
                snapshot.outer_launch_transaction,
                relationship.outer_launch_transaction
            );
        }
        let response_size = encode_snapshot(header, snapshot, &mut wire).unwrap();
        assert_eq!(
            decode(&wire[..response_size], 0),
            Ok(Message::Snapshot(header, snapshot))
        );
        session.complete(ticket).unwrap();
    }
}

#[test]
fn status_peer_close_is_current_child_fatal_and_generation_bound() {
    let (mut model, event) = live();
    let stale = EventGeneration {
        child_generation: event.child_generation + 1,
        ..event
    };
    assert_eq!(
        model.status_peer_closed(stale, 1),
        Err(ModelError::StaleCorrelation)
    );
    assert!(matches!(
        model.status_peer_closed(event, 2),
        Ok(RecoveryAction::TerminateChild(job)) if job == event.child_job
    ));
    assert_eq!(
        model.snapshot().last_failure,
        Some(ModelError::ChildDisconnected)
    );
}

#[test]
fn cross_record_input_and_independent_output_transform() {
    let (mut model, event) = live();
    model.stage_serial_input(event, b"a\r").unwrap();
    model.stage_serial_input(event, b"\nb\rc").unwrap();
    let mut input = [0; 8];
    let r = model.reserve_child_stdin(&mut input).unwrap().unwrap();
    assert_eq!(&input[..r.length()], b"a\nb\nc");
    model.commit_child_stdin(r).unwrap();
    model
        .stage_child_output(event, OutputSource::Stdout, b"o\r")
        .unwrap();
    model
        .stage_child_output(event, OutputSource::Stderr, b"e\n")
        .unwrap();
    model
        .stage_child_output(event, OutputSource::Stdout, b"\n")
        .unwrap();
    let mut output = [0; 8];
    let r = model.reserve_serial_tx(&mut output).unwrap().unwrap();
    assert_eq!(&output[..r.length()], b"o\r\n");
    model.commit_serial_tx(r).unwrap();
    let r = model.reserve_serial_tx(&mut output).unwrap().unwrap();
    assert_eq!(&output[..r.length()], b"e\r\n");
}

#[test]
fn terminal_precursor_preserves_lf_until_commit_before_replacement_prompt() {
    let (mut model, event) = live();
    model
        .stage_child_output(event, OutputSource::Stdout, b"\n")
        .unwrap();
    let staged = model.snapshot();
    assert_eq!(
        model.child_terminal_precursor(event, 1),
        Ok(RecoveryAction::None)
    );
    assert_eq!(model.snapshot(), staged);

    let mut serial = std::vec::Vec::new();
    let mut bytes = [0u8; 8];
    let committed = model.reserve_serial_tx(&mut bytes).unwrap().unwrap();
    assert_eq!(&bytes[..committed.length()], b"\r\n");
    serial.extend_from_slice(&bytes[..committed.length()]);
    model.commit_serial_tx(committed).unwrap();
    assert_eq!(model.snapshot().stdout_queued, 0);
    assert!(matches!(
        model.child_terminal(event, 2),
        Ok(RecoveryAction::ReapChild(job)) if job == event.child_job
    ));
    model.child_streams_closed(event, 2).unwrap();
    assert_eq!(
        model.child_reaped(event, 2),
        Ok(RecoveryAction::ReplaceChild)
    );

    let mut launch = model.begin_child_launch(200).unwrap();
    for kind in [StreamKind::Stdin, StreamKind::Stdout, StreamKind::Stderr] {
        launch.move_child_peer(kind).unwrap();
    }
    let replacement = model.commit_child_launch(&mut launch, 201).unwrap();
    model
        .stage_child_output(
            EventGeneration::from(replacement.ids),
            OutputSource::Stdout,
            b"\r\x1b[2K",
        )
        .unwrap();
    let prompt = model.reserve_serial_tx(&mut bytes).unwrap().unwrap();
    serial.extend_from_slice(&bytes[..prompt.length()]);
    assert_eq!(&serial[..2], b"\r\n");
    assert_eq!(&serial[2..], b"\r\x1b[2K");
}
#[test]
fn launch_binds_caller_supplied_transaction_and_accepted_job() {
    let mut model = ConsoleModel::new();
    connect(&mut model, 1, 0);
    let mut transaction = model.begin_child_launch(91).unwrap();
    for kind in [StreamKind::Stdin, StreamKind::Stdout, StreamKind::Stderr] {
        transaction.move_child_peer(kind).unwrap();
    }
    let child = model.commit_child_launch(&mut transaction, 92).unwrap();
    assert_eq!(child.ids.child_launch, 91);
    assert_eq!(child.ids.child_job, 92);
}

#[test]
fn input_crlf_state_survives_child_replacement_and_aborted_launch() {
    for (terminal, abort) in [(false, false), (false, true), (true, false), (true, true)] {
        let (mut model, old) = live();
        model.stage_serial_input(old, b"exit\r").unwrap();
        let mut bytes = [0; 32];
        let input = model.reserve_child_stdin(&mut bytes).unwrap().unwrap();
        assert_eq!(&bytes[..input.length()], b"exit\n");
        model.commit_child_stdin(input).unwrap();
        model
            .stage_child_output(old, OutputSource::Stdout, b"\r")
            .unwrap();
        if terminal {
            model.child_terminal(old, 1).unwrap();
        } else {
            model.child_peer_closed(old, StreamKind::Stdout, 1).unwrap();
            model.child_terminated(old, 1).unwrap();
        }
        model.child_streams_closed(old, 2).unwrap();
        assert_eq!(model.child_reaped(old, 3), Ok(RecoveryAction::ReplaceChild));
        if abort {
            let transaction = model.begin_child_launch(101).unwrap();
            let token = model.abort_child_launch(transaction).unwrap();
            model
                .complete_abort_child_launch(&token, cleanup_evidence())
                .unwrap();
        }
        let replacement = launch(&mut model);
        assert_eq!(replacement.serial, old.serial);
        model.stage_serial_input(replacement, b"\n").unwrap();
        assert_eq!(model.reserve_child_stdin(&mut bytes), Ok(None));
        model.stage_serial_input(replacement, b"ping\r\n").unwrap();
        let input = model.reserve_child_stdin(&mut bytes).unwrap().unwrap();
        assert_eq!(&bytes[..input.length()], b"ping\n");
        model
            .stage_child_output(replacement, OutputSource::Stdout, b"\n")
            .unwrap();
        let output = model.reserve_serial_tx(&mut bytes).unwrap().unwrap();
        assert_eq!(&bytes[..output.length()], b"\r\n");
    }
}

#[test]
fn serial_replacement_resets_input_crlf_state() {
    let (mut model, old) = live();
    model.stage_serial_input(old, b"exit\r").unwrap();
    let snapshot = model.snapshot();
    close_serial(&mut model, 1);
    model.child_terminated(old, 2).unwrap();
    model.child_streams_closed(old, 3).unwrap();
    model.child_reaped(old, 4).unwrap();
    model
        .complete_serial_cleanup(
            snapshot.serial.unwrap(),
            snapshot.console_generation.unwrap(),
            5,
        )
        .unwrap();
    connect(&mut model, 2, 30);
    let replacement = launch(&mut model);
    model.stage_serial_input(replacement, b"\n").unwrap();
    let mut bytes = [0; 8];
    let input = model.reserve_child_stdin(&mut bytes).unwrap().unwrap();
    assert_eq!(&bytes[..input.length()], b"\n");
}
#[test]
fn exact_preflight_admits_normalized_one_byte_when_one_slot_remains() {
    let (mut model, event) = live();
    model.input.push(&[b'x'; STAGING_CAPACITY - 1]);
    model.stage_serial_input(event, b"\r").unwrap();
    assert_eq!(model.input.len(), STAGING_CAPACITY);
    model.input.clear();
    model.stdout.push(&[b'x'; STAGING_CAPACITY - 1]);
    model
        .stage_child_output(event, OutputSource::Stdout, b"x")
        .unwrap();
    assert_eq!(model.stdout.len(), STAGING_CAPACITY);
}
#[test]
fn backpressure_never_partially_transforms() {
    let (mut model, event) = live();
    model.stdout.push(&[b'x'; STAGING_CAPACITY - 1]);
    let before = model.stdout.len();
    assert_eq!(
        model.stage_child_output(event, OutputSource::Stdout, b"\n"),
        Err(ModelError::Backpressure)
    );
    assert_eq!(model.stdout.len(), before);
    assert_eq!(
        model.stage_serial_input(event, &[b'x'; 1025]),
        Err(ModelError::TooLarge)
    );
}
#[test]
fn would_block_reservations_preserve_bytes_and_fair_turn() {
    let (mut model, event) = live();
    model.stage_serial_input(event, b"in").unwrap();
    let mut bytes = [0; 8];
    let stdin = model.reserve_child_stdin(&mut bytes).unwrap().unwrap();
    model.release_child_stdin(stdin).unwrap();
    let again = model.reserve_child_stdin(&mut bytes).unwrap().unwrap();
    assert_eq!(&bytes[..again.length()], b"in");
    model.commit_child_stdin(again).unwrap();
    model
        .stage_child_output(event, OutputSource::Stdout, b"out")
        .unwrap();
    model
        .stage_child_output(event, OutputSource::Stderr, b"err")
        .unwrap();
    let tx = model.reserve_serial_tx(&mut bytes).unwrap().unwrap();
    assert_eq!(tx.output_source(), Some(OutputSource::Stdout));
    model.release_serial_tx(tx).unwrap();
    let same = model.reserve_serial_tx(&mut bytes).unwrap().unwrap();
    assert_eq!(same.output_source(), Some(OutputSource::Stdout));
    model.commit_serial_tx(same).unwrap();
    assert_eq!(
        model
            .reserve_serial_tx(&mut bytes)
            .unwrap()
            .unwrap()
            .output_source(),
        Some(OutputSource::Stderr)
    );
}
#[test]
fn partial_move_cleanup_accounts_for_exactly_six_unique_endpoints() {
    let mut model = ConsoleModel::new();
    connect(&mut model, 1, 0);
    let mut tx = model.begin_child_launch(101).unwrap();
    tx.move_child_peer(StreamKind::Stdin).unwrap();
    let token = model.abort_child_launch(tx).unwrap();
    let cleanup = token.cleanup();
    let mut index = 0;
    while index < 6 {
        let mut other = index + 1;
        while other < 6 {
            assert_ne!(
                cleanup.entries[index].endpoint,
                cleanup.entries[other].endpoint
            );
            other += 1;
        }
        index += 1;
    }
    assert_eq!(
        cleanup.entries[3].disposition,
        CleanupDisposition::RevokeMovedChildPeerFromLaunch
    );
    assert_eq!(
        cleanup.entries[4].disposition,
        CleanupDisposition::CloseUnmovedChildPeer
    );
    assert_eq!(
        model.begin_child_launch(102),
        Err(ModelError::WrongConnectionState)
    );
    let _cleanup = model
        .complete_abort_child_launch(&token, cleanup_evidence())
        .unwrap();
    let retry = model.begin_child_launch(102).unwrap();
    let token = model.abort_child_launch(retry).unwrap();
    assert!(
        model
            .complete_abort_child_launch(&token, cleanup_evidence())
            .is_ok()
    );
}
#[test]
fn launch_correlation_rejects_drift_before_commit() {
    let mut model = ConsoleModel::new();
    connect(&mut model, 1, 0);
    let mut tx = model.begin_child_launch(102).unwrap();
    for kind in [StreamKind::Stdin, StreamKind::Stdout, StreamKind::Stderr] {
        tx.move_child_peer(kind).unwrap();
    }
    close_serial(&mut model, 1);
    assert_eq!(
        model.commit_child_launch(&mut tx, 202),
        Err(ModelError::StaleCorrelation)
    );
    let token = model.abort_child_launch(tx).unwrap();
    assert!(
        model
            .complete_abort_child_launch(&token, cleanup_evidence())
            .is_ok()
    );
}
#[test]
fn individual_peer_close_requires_termination_reap_and_all_peer_cleanup() {
    let (mut model, event) = live();
    let job = model.child.unwrap().ids.child_job;
    assert_eq!(
        model.child_peer_closed(event, StreamKind::Stdout, 1),
        Ok(RecoveryAction::TerminateChild(job))
    );
    assert_eq!(
        model.child_terminated(event, 1),
        Ok(RecoveryAction::ReapChild(job))
    );
    assert_eq!(
        model.child_reaped(event, 1),
        Err(ModelError::IncompleteCleanup)
    );
    model.child_streams_closed(event, 1).unwrap();
    assert_eq!(
        model.child_reaped(event, 1),
        Ok(RecoveryAction::ReplaceChild)
    );
    assert_eq!(model.state(), ConnectionState::Active);
}
#[test]
fn wrong_direction_data_is_a_child_failure() {
    let (mut model, event) = live();
    assert!(matches!(
        model.wrong_direction_data(event, 1),
        Ok(RecoveryAction::TerminateChild(_))
    ));
    assert_eq!(
        model.snapshot().last_failure,
        Some(ModelError::WrongDirection)
    );
}
#[test]
fn raw_loss_requires_complete_reap_before_fresh_attach_and_does_not_count() {
    let (mut model, event) = live();
    let serial = model.snapshot().serial.unwrap();
    let console = model.snapshot().console_generation.unwrap();
    close_serial(&mut model, 1);
    model.child_terminated(event, 1).unwrap();
    model.child_streams_closed(event, 1).unwrap();
    model.child_reaped(event, 1).unwrap();
    assert_eq!(model.state(), ConnectionState::AwaitingReap);
    assert_eq!(
        model.attach_connected(correlation(2), 1),
        Err(ModelError::WrongConnectionState)
    );
    assert_eq!(
        model.complete_serial_cleanup(serial, console, 1),
        Ok(RecoveryAction::RetrySerialAt(26))
    );
    assert_eq!(model.snapshot().serial_failures, 0);
    connect(&mut model, 2, 2);
}
#[test]
fn reconnect_failure_budget_exhausts_and_blocks_fifth_attach_or_launch() {
    let mut model = ConsoleModel::new();
    for now in 0..4 {
        let expected = if now == 3 {
            RecoveryAction::Escalate
        } else {
            RecoveryAction::RetrySerialAt(now + 25)
        };
        assert_eq!(model.serial_reconnect_failed(now), Ok(expected));
    }
    assert_eq!(model.state(), ConnectionState::Exhausted);
    assert_eq!(
        model.attach_connected(correlation(1), 5),
        Err(ModelError::RestartExhausted)
    );
    assert_eq!(
        model.begin_child_launch(103),
        Err(ModelError::RestartExhausted)
    );
}
#[test]
fn correlation_is_full_monotonic_and_rejects_a_b_a() {
    let mut model = ConsoleModel::new();
    connect(&mut model, 1, 0);
    close_serial(&mut model, 1);
    connect(&mut model, 2, 2);
    close_serial(&mut model, 3);
    assert_eq!(
        model.attach_connected(correlation(1), 4),
        Err(ModelError::StaleCorrelation)
    );
}
#[test]
fn fresh_endpoint_can_start_at_same_object_generation_in_retained_bundle() {
    let old = correlation(1);
    let new = SerialCorrelation {
        device_bundle: old.device_bundle,
        driver_control_endpoint_generation: old.driver_control_endpoint_generation,
        ..correlation(2)
    };
    assert!(new.valid_transition_from(old));
    assert!(
        !SerialCorrelation {
            driver_control_endpoint_id: old.driver_control_endpoint_id,
            ..new
        }
        .valid_transition_from(old)
    );
    assert!(
        !SerialCorrelation {
            attach_transaction: old.attach_transaction,
            ..new
        }
        .valid_transition_from(old)
    );
}
#[test]
fn exact_ready_token_only_clears_child_window_after_sixty_seconds() {
    let (mut model, event) = live();
    model
        .child_peer_closed(event, StreamKind::Stdin, 1)
        .unwrap();
    model.child_terminated(event, 1).unwrap();
    model.child_streams_closed(event, 1).unwrap();
    model.child_reaped(event, 1).unwrap();
    let event = launch(&mut model);
    let token = model.observe_child_ready(event, 2).unwrap();
    assert!(!model.observe_ready(60_001, token).unwrap());
    assert!(model.observe_ready(60_002, token).unwrap());
    model
        .child_peer_closed(event, StreamKind::Stdin, 60_003)
        .unwrap();
    assert_eq!(
        model.observe_ready(60_004, token),
        Err(ModelError::StaleCorrelation)
    );
}
#[test]
fn global_time_regression_fails_closed_before_state_mutation() {
    let (mut model, event) = live();
    model.stage_serial_input(event, b"x").unwrap();
    model
        .child_peer_closed(event, StreamKind::Stdin, 10)
        .unwrap();
    let before = model.snapshot();
    assert_eq!(
        model.child_terminated(event, 9),
        Err(ModelError::MonotonicRegression)
    );
    assert_eq!(model.state(), ConnectionState::FailClosed);
    assert_eq!(model.snapshot().input_queued, before.input_queued);
}
#[test]
fn empty_transport_buffers_do_not_reserve_or_rotate_fairness() {
    let (mut model, event) = live();
    model
        .stage_child_output(event, OutputSource::Stdout, b"a")
        .unwrap();
    model
        .stage_child_output(event, OutputSource::Stderr, b"b")
        .unwrap();
    assert_eq!(model.reserve_serial_tx(&mut []), Ok(None));
    let mut bytes = [0; 8];
    assert_eq!(
        model
            .reserve_serial_tx(&mut bytes)
            .unwrap()
            .unwrap()
            .output_source(),
        Some(OutputSource::Stdout)
    );
    assert_eq!(model.reserve_child_stdin(&mut []), Ok(None));
}
#[test]
fn failed_connect_attempt_releases_pending_request_for_retry() {
    let mut model = ConsoleModel::new();
    let request = ConnectRequest {
        registry_generation: 1,
        registry_endpoint_id: 1,
        registry_endpoint_generation: 1,
        requested_publication_generation: 1,
        connector_client_transaction: 1,
    };
    model.begin_connect(request).unwrap();
    assert_eq!(
        model.serial_reconnect_failed(0),
        Ok(RecoveryAction::RetrySerialAt(25))
    );
    let retry = ConnectRequest {
        connector_client_transaction: 2,
        ..request
    };
    model.begin_connect(retry).unwrap();
    model.abort_connect(retry).unwrap();
}
#[test]
fn ready_requires_exact_ready_event_and_stale_ready_preserves_new_proof() {
    let (mut model, event) = live();
    assert_eq!(model.ready_token(), None);
    let token = model.observe_child_ready(event, 1).unwrap();
    assert_eq!(
        model.observe_child_ready(
            EventGeneration {
                child_generation: event.child_generation + 1,
                ..event
            },
            2
        ),
        Err(ModelError::StaleCorrelation)
    );
    assert!(!model.observe_ready(2, token).unwrap());
}
#[test]
fn duplicate_ready_preserves_original_stable_since() {
    let (mut model, event) = live();
    let token = model.observe_child_ready(event, 10).unwrap();
    assert_eq!(model.observe_child_ready(event, 59_999), Ok(token));
    assert!(model.observe_ready(60_010, token).unwrap());
}
#[test]
fn active_terminal_starts_reap_without_peer_close() {
    let (mut model, event) = live();
    assert!(matches!(
        model.child_terminal(event, 1),
        Ok(RecoveryAction::ReapChild(_))
    ));
    assert_eq!(model.state(), ConnectionState::AwaitingReap);
}
#[test]
fn pending_launch_serial_loss_matrix_requires_exact_cleanup_before_b() {
    let kinds = [StreamKind::Stdin, StreamKind::Stdout, StreamKind::Stderr];
    for moved_count in 0usize..=3 {
        let mut model = ConsoleModel::new();
        connect(&mut model, 1, 0);
        let mut launch_a = model.begin_child_launch(100 + moved_count as u64).unwrap();
        for kind in kinds.iter().take(moved_count) {
            launch_a.move_child_peer(*kind).unwrap();
        }
        let snapshot = model.snapshot();
        model
            .serial_peer_closed(
                snapshot.serial.unwrap(),
                snapshot.console_generation.unwrap(),
                1,
            )
            .unwrap();
        assert!(model.snapshot().serial_invalidated);
        let token = model.abort_child_launch(launch_a).unwrap();
        let mut evidence = LaunchCleanupEvidence {
            consoled_peers_closed: [true; 3],
            unmoved_child_peers_closed: [false; 3],
            moved_child_peers_revoked: [false; 3],
        };
        for index in 0..3 {
            if index < moved_count {
                evidence.moved_child_peers_revoked[index] = true;
            } else {
                evidence.unmoved_child_peers_closed[index] = true;
            }
        }
        let mut incomplete = evidence;
        incomplete.consoled_peers_closed[0] = false;
        assert_eq!(
            model.complete_abort_child_launch(&token, incomplete),
            Err(ModelError::IncompleteCleanup)
        );
        // The rejected completion retains the token obligation, so prepare
        // a fresh equivalent transaction is intentionally still blocked.
        assert_eq!(
            model.begin_child_launch(999),
            Err(ModelError::WrongConnectionState)
        );
        assert!(model.complete_abort_child_launch(&token, evidence).is_ok());
        assert_eq!(
            model.take_recovery_action(),
            Some(RecoveryAction::RetrySerialAt(26))
        );
        connect(&mut model, 2, 2);
        let launch_b = model.begin_child_launch(200 + moved_count as u64).unwrap();
        assert!(model.abort_child_launch(launch_b).is_ok());
        assert!(model.validate_invariants());
    }
}

#[test]
fn serial_loss_dominates_both_child_retirement_orderings() {
    for serial_after_termination in [false, true] {
        let (mut model, event) = live();
        let snapshot = model.snapshot();
        assert!(matches!(
            model.child_peer_closed(event, StreamKind::Stdout, 1),
            Ok(RecoveryAction::TerminateChild(_))
        ));
        if serial_after_termination {
            assert!(matches!(
                model.child_terminated(event, 2),
                Ok(RecoveryAction::ReapChild(_))
            ));
        }
        assert_eq!(
            model.serial_peer_closed(
                snapshot.serial.unwrap(),
                snapshot.console_generation.unwrap(),
                3,
            ),
            Ok(RecoveryAction::None)
        );
        if !serial_after_termination {
            assert!(matches!(
                model.child_terminated(event, 4),
                Ok(RecoveryAction::ReapChild(_))
            ));
        }
        model.child_streams_closed(event, 5).unwrap();
        assert_eq!(model.child_reaped(event, 6), Ok(RecoveryAction::None));
        assert_eq!(
            model.complete_serial_cleanup(
                snapshot.serial.unwrap(),
                snapshot.console_generation.unwrap(),
                7,
            ),
            Ok(RecoveryAction::RetrySerialAt(32))
        );
        assert_eq!(model.state(), ConnectionState::Reconnecting);
        let retired = model.snapshot();
        assert_eq!(retired.child_failures, 0);
        assert_eq!(retired.last_failure, Some(ModelError::SerialDisconnected));
        assert_eq!(model.child_failure_at, None);
        assert!(model.validate_invariants());
    }
}

#[test]
fn serial_dominant_retirement_cannot_age_a_replacement_child_failure() {
    let (mut model, old_event) = live();
    let old_serial = model.snapshot();
    model
        .child_peer_closed(old_event, StreamKind::Stdout, 1)
        .unwrap();
    model
        .serial_peer_closed(
            old_serial.serial.unwrap(),
            old_serial.console_generation.unwrap(),
            2,
        )
        .unwrap();
    model.child_terminated(old_event, 3).unwrap();
    model.child_streams_closed(old_event, 3).unwrap();
    model.child_reaped(old_event, 3).unwrap();
    model
        .complete_serial_cleanup(
            old_serial.serial.unwrap(),
            old_serial.console_generation.unwrap(),
            4,
        )
        .unwrap();
    connect(&mut model, 2, 5);

    let replacement = launch(&mut model);
    model
        .child_peer_closed(replacement, StreamKind::Stdin, 70_000)
        .unwrap();
    assert_eq!(
        model.snapshot().last_failure,
        Some(ModelError::ChildDisconnected)
    );
    model.child_terminated(replacement, 70_000).unwrap();
    model.child_streams_closed(replacement, 70_000).unwrap();
    assert_eq!(
        model.child_reaped(replacement, 70_000),
        Ok(RecoveryAction::ReplaceChild)
    );

    let next = launch(&mut model);
    model
        .child_peer_closed(next, StreamKind::Stdin, 70_001)
        .unwrap();
    model.child_terminated(next, 70_001).unwrap();
    model.child_streams_closed(next, 70_001).unwrap();
    assert_eq!(
        model.child_reaped(next, 70_001),
        Ok(RecoveryAction::ReplaceChild)
    );
    assert_eq!(model.snapshot().child_failures, 2);
}

#[test]
fn child_exhaustion_survives_serial_replacement_and_blocks_a_fifth_child() {
    let mut model = ConsoleModel::new();
    connect(&mut model, 1, 0);
    for failure in 0u64..4 {
        let event = launch(&mut model);
        let now = failure + 1;
        model
            .child_peer_closed(event, StreamKind::Stdin, now)
            .unwrap();
        model.child_terminated(event, now).unwrap();
        model.child_streams_closed(event, now).unwrap();
        let expected = if failure == 3 {
            RecoveryAction::Escalate
        } else {
            RecoveryAction::ReplaceChild
        };
        assert_eq!(model.child_reaped(event, now), Ok(expected));
    }
    let exhausted = model.snapshot();
    assert!(exhausted.child_restart_exhausted);
    assert!(!exhausted.serial_restart_exhausted);
    assert_eq!(
        model.serial_peer_closed(
            exhausted.serial.unwrap(),
            exhausted.console_generation.unwrap(),
            5,
        ),
        Ok(RecoveryAction::RetrySerialAt(30))
    );
    connect(&mut model, 2, 6);
    assert_eq!(
        model.begin_child_launch(999),
        Err(ModelError::RestartExhausted)
    );
    assert!(model.validate_invariants());
}

#[test]
fn exact_restart_window_boundary_expires_the_old_failure() {
    let mut model = ConsoleModel::new();
    connect(&mut model, 1, 0);
    for now in [0, RESTART_WINDOW_MILLIS] {
        let event = launch(&mut model);
        model
            .child_peer_closed(event, StreamKind::Stdin, now)
            .unwrap();
        model.child_terminated(event, now).unwrap();
        model.child_streams_closed(event, now).unwrap();
        assert_eq!(
            model.child_reaped(event, now),
            Ok(RecoveryAction::ReplaceChild)
        );
    }
    assert_eq!(model.snapshot().child_failures, 1);
}

#[test]
fn stale_ready_from_replaced_child_cannot_change_new_stability() {
    let (mut model, old_event) = live();
    let old_token = model.observe_child_ready(old_event, 1).unwrap();
    model
        .child_peer_closed(old_event, StreamKind::Stdin, 2)
        .unwrap();
    model.child_terminated(old_event, 2).unwrap();
    model.child_streams_closed(old_event, 2).unwrap();
    model.child_reaped(old_event, 2).unwrap();
    let new_event = launch(&mut model);
    let new_token = model.observe_child_ready(new_event, 3).unwrap();
    assert_eq!(
        model.observe_ready(4, old_token),
        Err(ModelError::StaleCorrelation)
    );
    assert!(
        model
            .observe_ready(3 + STABLE_RUN_MILLIS, new_token)
            .unwrap()
    );
}

#[test]
fn three_retired_shell_epochs_cannot_mutate_the_current_ready_or_stream_state() {
    let (mut model, mut current) = live();
    let mut now = 1;
    for _ in 0..3 {
        let retired = current;
        model.child_terminal(retired, now).unwrap();
        model.child_streams_closed(retired, now).unwrap();
        assert_eq!(
            model.child_reaped(retired, now),
            Ok(RecoveryAction::ReplaceChild)
        );
        current = launch(&mut model);
        let current_token = model.observe_child_ready(current, now + 1).unwrap();
        let before = model.snapshot();

        assert_eq!(
            model.observe_child_ready(retired, now + 2),
            Err(ModelError::StaleCorrelation)
        );
        assert_eq!(
            model.stage_child_output(retired, OutputSource::Stdout, b"old"),
            Err(ModelError::StaleCorrelation)
        );
        assert_eq!(
            model.child_peer_closed(retired, StreamKind::Stdout, now + 2),
            Err(ModelError::StaleCorrelation)
        );
        let mut expected = before;
        expected.last_failure = Some(ModelError::StaleCorrelation);
        assert_eq!(model.snapshot(), expected);
        assert_eq!(model.ready_token(), Some(current_token));
        now += 3;
    }
}

#[test]
fn fail_closed_launch_still_exposes_and_completes_endpoint_cleanup() {
    let mut model = ConsoleModel::new();
    connect(&mut model, 1, 10);
    let mut launch = model.begin_child_launch(101).unwrap();
    launch.move_child_peer(StreamKind::Stdin).unwrap();
    let snapshot = model.snapshot();
    assert_eq!(
        model.serial_peer_closed(
            snapshot.serial.unwrap(),
            snapshot.console_generation.unwrap(),
            9,
        ),
        Err(ModelError::MonotonicRegression)
    );
    let pending = model.snapshot();
    assert_eq!(pending.state, ConnectionState::FailClosed);
    assert!(pending.pending_launch);
    let token = model.abort_child_launch(launch).unwrap();
    let evidence = LaunchCleanupEvidence {
        consoled_peers_closed: [true; 3],
        unmoved_child_peers_closed: [false, true, true],
        moved_child_peers_revoked: [true, false, false],
    };
    model.complete_abort_child_launch(&token, evidence).unwrap();
    let cleaned = model.snapshot();
    assert!(!cleaned.pending_launch);
    assert!(!cleaned.pending_launch_cleanup);
    assert!(model.validate_invariants());
}
