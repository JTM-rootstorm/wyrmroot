use {
    deepwyrm_syscall as _, wyrmroot_bootfs as _, wyrmroot_device_proto as _,
    wyrmroot_launch_proto as _, wyrmroot_loader as _, wyrmroot_registry_proto as _,
    wyrmroot_rrc_manifest as _, wyrmroot_runtime as _, wyrmroot_system_init as _,
    wyrmroot_wyr1b_gate_proto as _,
};

const MAIN: &str = include_str!("../src/main.rs");
const LIB: &str = include_str!("../src/lib.rs");
const WYR1B_MODEL: &str = include_str!("../src/wyr1b.rs");
const NATIVE: &str = include_str!("../src/wyr1b_native.rs");
const MANIFEST: &str = include_str!("../Cargo.toml");

#[test]
fn selector_27_submission_feature_is_separate_from_selector_25() {
    assert!(MANIFEST.contains(
        "wyr1-test-evidence = [\"native-init\", \"wyrmroot-runtime/wyr1-test-evidence\"]"
    ));
    assert!(MANIFEST.contains(
        "wyr1b-test-evidence = [\"native-init\", \"wyrmroot-runtime/wyr1b-test-evidence\"]"
    ));
    assert!(MAIN.contains("#[cfg(feature = \"wyr1b-test-evidence\")]"));
    assert!(MAIN.contains("resident.wyr1b_evidence_record(index)"));
    assert!(MAIN.contains("wyrmroot_runtime::submit_wyr1b_evidence(record)"));
    assert!(MAIN.contains("#[cfg(feature = \"wyr1-test-evidence\")]"));
    assert!(MAIN.contains("wyrmroot_runtime::submit_wyr1_evidence(record)"));
    assert!(LIB.contains("wyr1b_evidence: None"));
    assert!(NATIVE.contains("*wyr1b_evidence = Some(evidence)"));
}

#[test]
fn selector_27_startup_mapping_diagnostic_is_bound_to_the_initial_mapping_only() {
    let product_start = LIB.find("fn activate_received_product_in_place").unwrap();
    let product_end = LIB[product_start..]
        .find("fn receive_and_activate<S, T>")
        .map(|offset| product_start + offset)
        .unwrap();
    let product = &LIB[product_start..product_end];
    assert_eq!(
        product
            .matches(".map_err(|error| startup_mapping_error(error, size))?")
            .count(),
        1
    );
    assert!(LIB.contains("fn startup_mapping_error(error: MappingPlanError, size: u64)"));
    assert!(LIB.contains("InitError::StartupMapping(StartupMappingDiagnostic"));
    assert!(MAIN.contains("return wyr1b_test_failure_application_status(&error);"));
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
    assert!(MAIN.contains("continue_resident,"));
    assert!(!MAIN.contains("let mut resident = match"));
}

#[test]
fn selector_27_resident_control_borrows_large_state_in_place() {
    let control_start = NATIVE.find("pub(crate) fn control_tick").unwrap();
    let control_end = NATIVE[control_start..]
        .find("#[cfg(test)]")
        .map(|offset| control_start + offset)
        .unwrap();
    let control = &NATIVE[control_start..control_end];
    assert!(control.contains("let ResidentSystemInit {"));
    assert!(control.contains("let state = wyr1b.as_mut()"));
    assert!(!control.contains(".wyr1b.take()"));
    assert!(NATIVE.contains("#[inline(never)]\nfn run_registry_replacement_gate"));
    assert!(NATIVE.contains("enum ReplacementGateOutcome"));
    assert!(NATIVE.contains(") -> Result<Option<RegistryNativeAttempt>, InitError>"));
}

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
    assert!(NATIVE.contains("#[inline(always)]\nfn poll_job_dispatcher"));
    assert!(WYR1B_MODEL.contains("#[inline(always)]\npub(crate) fn prepare_reserved_job"));
    assert!(LIB.contains("#[inline(always)]\n    pub fn control_tick_product"));
    assert!(MAIN.contains(
        "#[cfg_attr(feature = \"wyr1b-test-evidence\", inline(always))]\n    fn with_bootfs_bytes"
    ));
}

#[test]
fn selector_27_ordinary_mapping_diagnostic_names_each_remaining_site() {
    let production_lib = LIB.split("#[cfg(test)]").next().unwrap();
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
    assert!(NATIVE.contains("orphan_result.cleanup_result != 0"));
    assert!(NATIVE.contains("jobs.jobs.live_jobs() != 0"));
    assert!(NATIVE.contains("jobs.jobs.orphan_jobs() != 0"));
}
