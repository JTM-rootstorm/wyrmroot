use wyrmroot_consoled as _;
use {
    deepwyrm_syscall as _, wyrmroot_bootfs as _, wyrmroot_device_proto as _, wyrmroot_devmgr as _,
    wyrmroot_launch_proto as _, wyrmroot_loader as _, wyrmroot_registry_proto as _,
    wyrmroot_registryd as _, wyrmroot_rrc_manifest as _, wyrmroot_runtime as _,
    wyrmroot_system_init as _, wyrmroot_uart16550d as _, wyrmroot_wyr1b_gate_proto as _,
};

const NATIVE: &str = include_str!("../src/wyr1b_native.rs");

/// The text of the item that starts at `start`, up to its closing brace at
/// `indent`.
fn item<'a>(source: &'a str, start: &str, indent: &str) -> &'a str {
    let from = source
        .find(start)
        .unwrap_or_else(|| panic!("missing {start}"));
    let close = format!("\n{indent}}}\n");
    let to = source[from..].find(&close).unwrap() + from;
    &source[from..to]
}

/// The selector-27 gate records its relational joins in contract order.
///
/// Source text because `run_registry_gate` and `run_job_gate` are reached
/// only from `activate_resident` and the resident `control_tick`, which no
/// host fake drives. Each span runs between two named fns.
#[test]
fn controller_records_all_relational_joins_in_contract_order() {
    let registry_start = NATIVE.find("fn run_registry_gate").unwrap();
    let registry_end = NATIVE[registry_start..]
        .find("fn launch_registry_replacement_with_gate")
        .map(|offset| registry_start + offset)
        .unwrap();
    let registry = &NATIVE[registry_start..registry_end];
    let mut cursor = 0;
    for event in [
        "GateEvent::RegistryReady",
        "GateEvent::PublisherReady",
        "GateEvent::ClientReady",
        "GateEvent::Published",
        "GateEvent::Connected",
        "GateEvent::DirectExchange",
        "GateEvent::Retired",
        "GateEvent::StaleRejected",
    ] {
        let relative = registry[cursor..]
            .find(event)
            .unwrap_or_else(|| panic!("missing or reordered registry evidence join {event}"));
        cursor += relative + event.len();
    }

    let job_start = NATIVE.find("fn run_job_gate").unwrap();
    let job_end = NATIVE[job_start..]
        .find("fn run_registry_gate")
        .map(|offset| job_start + offset)
        .unwrap();
    let job = &NATIVE[job_start..job_end];
    cursor = 0;
    for event in [
        "GateEvent::JobAccepted",
        "record_owner_job_reap(&mut *evidence, owner.grant, job_id, owner_result)?",
        "GateEvent::ForeignRejected",
        "GateEvent::OrphanReaped",
        ".finish()",
    ] {
        let relative = job[cursor..]
            .find(event)
            .unwrap_or_else(|| panic!("missing or reordered job evidence join {event}"));
        cursor += relative + event.len();
    }
    assert_eq!(job.matches("record_owner_job_reap(").count(), 1);

    let reap_start = NATIVE.find("fn record_owner_job_reap").unwrap();
    let reap_end = NATIVE[reap_start..]
        .find("fn run_job_gate")
        .map(|offset| reap_start + offset)
        .unwrap();
    let reap = &NATIVE[reap_start..reap_end];
    cursor = 0;
    for join in [
        "result.classification != TerminationClassification::NormalExit.as_u32()",
        "result.application_code != 0",
        "result.cleanup_result != 0",
        "GateEvent::JobExitZero",
        "GateEvent::JobReaped",
    ] {
        let relative = reap[cursor..]
            .find(join)
            .unwrap_or_else(|| panic!("missing or reordered clean-reap evidence join {join}"));
        cursor += relative + join.len();
    }
    // The job gate's own closing checks, not another fn's.
    assert!(job.contains("orphan_result.cleanup_result != 0"));
    assert!(job.contains("jobs.jobs.live_jobs() != 0"));
    assert!(job.contains("jobs.jobs.orphan_jobs() != 0"));
}

/// Reset card R6D, for the two clients a model test cannot reach: registry
/// supervision and service control.
///
/// Those live in `control_tick`, which supervises the active roles and then
/// polls the launch dispatcher. The claim is about wall time, and what decides
/// it is the deadline every wait in the tick is given: `DwDeadline(now_ns)`,
/// the tick's own instant, which is already in the past by the time the
/// syscall runs and therefore cannot wait.
///
/// The dispatcher's waits (the session poll and R6C's parked-child poll) are
/// host-tested by `every_dispatcher_tick_wait_is_a_poll_of_the_ticks_own_instant`
/// in wyr1b_native.rs. The one wait on the dispatcher path that is *not* a
/// poll, inside `observe_prepared_ready`, is bounded by R6C's gate, asserted by
/// `the_parked_child_poll_asks_only_for_signals_it_can_act_on_at_once`.
///
/// Source text for `control_tick`'s own role-supervision poll, because no
/// host fake drives the selector-27 `control_tick`. Scoped to its body.
#[test]
fn every_wait_on_the_resident_tick_path_is_a_poll_of_the_ticks_own_instant() {
    let control = item(NATIVE, "pub(crate) fn control_tick<", "");
    let calls = control.matches(".wait_many(").count();
    assert!(
        calls > 0,
        "control_tick no longer waits at all; re-read this test"
    );
    assert_eq!(
        calls,
        control.matches("DwDeadline(now_ns)").count(),
        "control_tick has a wait whose deadline is not the tick's own instant"
    );
}
