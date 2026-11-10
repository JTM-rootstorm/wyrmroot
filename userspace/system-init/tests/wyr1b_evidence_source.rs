use {
    deepwyrm_syscall as _, wyrmroot_bootfs as _, wyrmroot_device_proto as _, wyrmroot_devmgr as _,
    wyrmroot_launch_proto as _, wyrmroot_loader as _, wyrmroot_registry_proto as _,
    wyrmroot_registryd as _, wyrmroot_rrc_manifest as _, wyrmroot_runtime as _,
    wyrmroot_system_init as _, wyrmroot_uart16550d as _, wyrmroot_wyr1b_gate_proto as _,
};

const MAIN: &str = include_str!("../src/main.rs");
const LOOP: &str = include_str!("../src/resident_loop.rs");
const LIB: &str = include_str!("../src/lib.rs");
const WYR1B_MODEL: &str = include_str!("../src/wyr1b.rs");
const NATIVE: &str = include_str!("../src/wyr1b_native.rs");
const MANIFEST: &str = include_str!("../Cargo.toml");

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

#[test]
fn native_product_activation_constructs_and_continues_one_resident_in_place() {
    assert!(LIB.contains("pub fn continue_system_init_product"));
    assert!(LIB.contains("let mut slot = MaybeUninit::uninit()"));
    assert!(LIB.contains("slot.write(ResidentSystemInit"));
    assert!(NATIVE.contains("slot.write(ResidentSystemInit"));
    assert!(!LIB.contains("enum ProductActivation"));
    assert!(!NATIVE.contains("struct Activation"));
    assert!(!LIB.contains("pub fn run_system_init_product"));
    assert!(MAIN.contains("continue_system_init_product("));
    assert!(MAIN.contains("resident_loop::continue_resident,"));
    assert!(!MAIN.contains("let mut resident = match"));
}

/// Selector 27's resident tick borrows its large state where it lives, and
/// the replacement gate keeps its frame out of the tick.
///
/// Source text because the property is the target build's stack frame: a
/// moved or inlined copy behaves identically on the host, and selector 27's
/// shape is only `check`ed by the gate. Scoped to `control_tick`'s body and
/// to the named items' own declarations.
#[test]
fn selector_27_resident_control_borrows_large_state_in_place() {
    let control = item(NATIVE, "pub(crate) fn control_tick<", "");
    assert!(control.contains("let ResidentSystemInit {"));
    assert!(control.contains("let state = wyr1b.as_mut()"));
    // Through the destructured binding as well as through `resident`.
    assert!(!control.contains("wyr1b.take()"));
    assert!(NATIVE.contains("#[inline(never)]\nfn run_registry_replacement_gate"));
    assert!(NATIVE.contains("enum ReplacementGateOutcome"));
    assert!(NATIVE.contains(") -> Result<Option<RegistryNativeAttempt>, InitError>"));
}

/// The selector-27 dispatcher family holds one protocol-sized payload buffer
/// and one stream set, and its large helpers are inlined into one frame.
///
/// Source text because both are properties of the target build's stack
/// frame, which no host test observes, and selector 27's shape is only
/// `check`ed by the gate. Scoped to the dispatch family, from
/// `dispatch_one_job_request` to `poll_job_dispatcher`.
#[test]
fn selector_27_dispatcher_keeps_one_protocol_sized_payload_and_stream_set() {
    let dispatch_start = NATIVE.find("fn dispatch_one_job_request").unwrap();
    let dispatch_end = NATIVE[dispatch_start..]
        .find("fn poll_job_dispatcher")
        .map(|offset| dispatch_start + offset)
        .unwrap();
    let dispatch = &NATIVE[dispatch_start..dispatch_end];
    assert_eq!(
        dispatch
            .matches("wyrmroot_launch_proto::MAX_LAUNCH_MESSAGE_BYTES")
            .count(),
        1
    );
    assert_eq!(
        dispatch
            .matches("wyrmroot_launch_proto::STREAM_COUNT")
            .count(),
        1
    );
    assert!(!dispatch.contains("MAX_STRING_BYTES + 2048"));
    assert!(NATIVE.contains("#[inline(always)]\nfn accept_reserved_launch"));
    assert!(NATIVE.contains("#[inline(always)]\npub(crate) fn poll_job_dispatcher"));
    assert!(WYR1B_MODEL.contains("#[inline(always)]\npub(crate) fn prepare_reserved_job"));
    assert!(LIB.contains("#[inline(always)]\n    pub fn control_tick_product"));
}

/// Each post-startup bootfs mapping names its own site.
///
/// Source text for the reason the startup check above gives: the site is
/// carried only in selector 27's shape, which the gate only `check`s. The
/// per-file call counts bound each assertion to the one call it names.
#[test]
fn selector_27_ordinary_mapping_diagnostic_names_each_remaining_site() {
    // Exclude the test module, not a test-only branch inside production code.
    let production_lib = LIB.split("\n#[cfg(test)]\nmod ").next().unwrap();
    assert!(LIB.contains("low five bits carry the claim-bearing ordinal"));
    assert!(LIB.contains("mapping_failure_ordinal(0, diagnostic.error"));
    assert!(LIB.contains("ordinary_mapping_error(MappingDiagnosticSite::RoleRemap, error, size)"));
    assert!(
        NATIVE
            .contains("ordinary_mapping_error(MappingDiagnosticSite::JobDispatcher, error, size)")
    );
    assert!(NATIVE.contains(
        "ordinary_mapping_error(MappingDiagnosticSite::RegistryReplacement, error, size)"
    ));
    assert_eq!(production_lib.matches("ordinary_mapping_error(").count(), 2);
    assert_eq!(NATIVE.matches("ordinary_mapping_error(").count(), 2);
    assert!(!LIB.contains(".map_err(InitError::Mapping)?"));
    assert!(!NATIVE.contains(".map_err(InitError::Mapping)?"));
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
