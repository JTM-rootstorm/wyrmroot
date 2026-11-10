use super::*;
use deepwyrm_syscall::DwStatus;
use wyrmroot_loader::launch::LaunchError;

#[test]
fn local_job_table_reserves_before_publish_and_never_evicts() {
    let mut table = JobTable::new();
    let first = table.reserve().unwrap();
    assert!(table.publish(first, 91));
    assert_eq!(table.state(91), Some(JobState::Active));
    assert!(table.set_state(91, JobState::Terminating));
    assert_eq!(table.state(91), Some(JobState::Terminating));
    for id in 1..MAX_VISIBLE_JOBS as u64 {
        let slot = table.reserve().unwrap();
        assert!(table.publish(slot, 100 + id));
    }
    assert!(table.reserve().is_none());
    assert!(table.remove(91));
    let replacement = table.reserve().unwrap();
    table.abort(replacement);
    assert!(table.reserve().is_some());
}

#[test]
fn duplicate_and_zero_publish_cannot_corrupt_reservation() {
    let mut table = JobTable::new();
    let first = table.reserve().unwrap();
    assert!(table.publish(first, 7));
    let second = table.reserve().unwrap();
    assert!(!table.publish(second, 0));
    assert!(!table.publish(second, 7));
    table.abort(second);
    assert_eq!(table.state(7), Some(JobState::Active));
}

// F3A.6n / DIAGNOSTIC_CAUSE_CARRIAGE_CONTRACT.md §3.2: before this
// amendment, `ForegroundError::Stream` was payload-less and every one of
// these causes reached the reader as the same literal
// "run stream=failed\n". These tests assert the instance now survives to
// `foreground_stream_cause_name`/`stream_error_name` distinctly, which is
// what `write_stderr`s the `run stream=<name>\n` line in `run`'s match on
// `ForegroundError`.

#[test]
fn write_and_read_exhaustion_are_distinct_causes() {
    // Before F3A.6n both `Ok(0)` sites in `drain_foreground` (the
    // pending-output write and the stdin read) produced the identical
    // bare `ForegroundError::Stream`. A zero-length write and a
    // zero-length read are different instances and must not collapse
    // back onto one name.
    assert_ne!(
        foreground_stream_cause_name(&ForegroundStreamCause::WriteExhausted),
        foreground_stream_cause_name(&ForegroundStreamCause::ReadExhausted),
    );
}

#[test]
fn stream_error_name_is_exhaustive_and_distinct() {
    // Every `StreamError` variant the stdin read side can produce
    // (`Err(_)` used to erase all of these into one bare disposition)
    // must now name a distinct static string. `stream_error_name` is
    // matched exhaustively (no wildcard arm), so a new `StreamError`
    // variant added later fails to compile here rather than silently
    // inheriting a default name, per §3.4.
    let samples: [(&str, StreamError); 8] = [
        (
            "native",
            StreamError::Native(NativeError::Status(DwStatus(-1))),
        ),
        ("would_block", StreamError::WouldBlock),
        ("eof", StreamError::Eof),
        ("broken", StreamError::Broken),
        ("protocol", StreamError::Protocol),
        ("received_handles", StreamError::ReceivedHandles),
        ("failed", StreamError::Failed),
        ("launch", StreamError::Launch(LaunchError::BadMagic)),
    ];
    for (label_a, a) in &samples {
        for (label_b, b) in &samples {
            let name_a = stream_error_name(a);
            let name_b = stream_error_name(b);
            if label_a == label_b {
                assert_eq!(name_a, name_b, "{label_a} should name itself consistently");
            } else {
                assert_ne!(
                    name_a, name_b,
                    "{label_a} and {label_b} must not collapse onto the same name"
                );
            }
        }
    }
}

#[test]
fn read_stream_cause_forwards_the_underlying_stream_error_name() {
    // `ForegroundStreamCause::Read` must not re-collapse the
    // `StreamError` it carries — its name has to match what
    // `stream_error_name` would say directly, so the "run stream=<name>"
    // line names the same cause a caller inspecting the `StreamError`
    // itself would see.
    let cause = ForegroundStreamCause::Read(StreamError::Broken);
    assert_eq!(
        foreground_stream_cause_name(&cause),
        stream_error_name(&StreamError::Broken)
    );
}
