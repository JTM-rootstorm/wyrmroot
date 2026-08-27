use {
    deepwyrm_syscall as _, wyrmroot_bootfs as _, wyrmroot_launch_proto as _, wyrmroot_loader as _,
    wyrmroot_registry_proto as _, wyrmroot_rrc_manifest as _, wyrmroot_runtime as _,
    wyrmroot_system_init as _, wyrmroot_wyr1b_gate_proto as _,
};

const MAIN: &str = include_str!("../src/main.rs");
const LIB: &str = include_str!("../src/lib.rs");
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
    assert!(LIB.contains("wyr1b_evidence: activation.evidence"));
}

#[test]
fn selector_27_startup_mapping_diagnostic_is_bound_to_the_initial_mapping_only() {
    assert_eq!(
        LIB.matches(".map_err(|error| startup_mapping_error(error, size))?")
            .count(),
        1
    );
    assert!(LIB.contains("fn startup_mapping_error(error: MappingPlanError, size: u64)"));
    assert!(LIB.contains("InitError::StartupMapping(StartupMappingDiagnostic"));
    assert!(MAIN.contains("return wyr1b_test_failure_application_status(&error);"));
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
