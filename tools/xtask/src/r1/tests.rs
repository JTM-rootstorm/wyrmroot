use super::*;

#[test]
fn the_nonce_shape_matches_what_the_kernel_and_probe_require() {
    // The stack gate supplies this value for the selector.
    assert!(validate_nonce("8100000000000001").is_ok());
    assert!(validate_nonce("FFFFFFFFFFFFFFFF").is_ok());
    // A zero nonce compiles and then refuses every record, so it is refused here
    // rather than after nine payload builds.
    assert!(validate_nonce("0000000000000000").is_err());
    for malformed in [
        "",
        "81",
        "810000000000000",
        "81000000000000001",
        // Lowercase is the kernel's own rejection, mirrored so a product cannot
        // be built with a nonce the collector will not accept.
        "8100000000000abc",
        "8100000000000O01",
        "8100000000000 01",
    ] {
        assert!(
            validate_nonce(malformed).is_err(),
            "{malformed:?} must not parse"
        );
    }
}

#[test]
fn the_payload_set_is_exactly_the_cards_nine_and_names_no_excluded_actor() {
    assert_eq!(NATIVE_SPECS.len(), 9);
    let labels = NATIVE_SPECS.map(|spec| spec.label);
    for required in [
        "system-init",
        "registryd",
        "devmgr",
        "uart16550d",
        "consoled",
        "wyrmsh",
        "r1-probe",
        "cpu-hog",
        "hello",
    ] {
        assert!(labels.contains(&required), "{required} is missing");
    }
    // §8.1 excludes these outright, so they must not even be built.
    for excluded in [
        "recovery-trigger",
        "stdout-pressure",
        "console-echo",
        "com2-probe",
    ] {
        assert!(!labels.contains(&excluded), "{excluded} must not be built");
    }
    // Init is built for its own selector, not the historical native-init.
    let init = NATIVE_SPECS
        .iter()
        .find(|spec| spec.label == "system-init")
        .unwrap();
    assert_eq!(init.features, "r1-selector34");
    // devmgr must be the resource-domain coordinator the RRC graph assigns it.
    // Bare native-devmgr selects the older non-resource path and does not build.
    let devmgr = NATIVE_SPECS
        .iter()
        .find(|spec| spec.label == "devmgr")
        .unwrap();
    assert_eq!(devmgr.features, "wyr1c5-production");
    // The three excluded roles are the retained stubs, not the real drivers:
    // their images exist because the graph says the roles do.
    for retained in ["uart16550d", "consoled", "wyrmsh"] {
        let spec = NATIVE_SPECS
            .iter()
            .find(|spec| spec.label == retained)
            .unwrap();
        assert_eq!(spec.package, "wyrmroot-wyr1-retained-stubs");
        assert_eq!(spec.features, "native-retained");
    }
}

#[test]
fn hello_is_the_job_payload_because_the_probe_launches_without_streams() {
    // The stream variant would refuse a streams: false launch, and the policy
    // admits both payloads zero-stream only. Shipping the wrong hello would
    // surface as ProgressRejected and read like a scheduler result.
    let hello = NATIVE_SPECS
        .iter()
        .find(|spec| spec.label == "hello")
        .unwrap();
    assert_eq!(hello.binary, "wyrmroot-job-hello");
    assert_eq!(hello.features, "native-job-hello");
    let hog = NATIVE_SPECS
        .iter()
        .find(|spec| spec.label == "cpu-hog")
        .unwrap();
    assert_eq!(hog.binary, "wyrmroot-job-cpu-hog");
    assert_eq!(hog.package, "wyrmroot-dw1b-preemption");
}

#[test]
fn only_the_nonce_bound_payloads_are_compiled_against_it() {
    // Every other payload must build byte-identically whatever the nonce is, so
    // a nonce change cannot silently alter the retained stubs or registryd.
    assert_eq!(NONCE_BOUND_LABELS.len(), 2);
    assert!(NONCE_BOUND_LABELS.contains(&"r1-probe"));
    assert!(NONCE_BOUND_LABELS.contains(&"system-init"));
    for label in NONCE_BOUND_LABELS {
        assert!(NATIVE_SPECS.iter().any(|spec| spec.label == label));
    }
}

#[test]
fn the_profiles_are_exactly_the_two_accepted_topologies() {
    assert_eq!(PROFILES.len(), 2);
    for (name, hog_count, online_cpus) in PROFILES {
        assert!(
            ACCEPTED_TOPOLOGIES
                .iter()
                .any(|(hogs, cpus)| *hogs == hog_count && *cpus == online_cpus),
            "{name} is not an accepted topology"
        );
    }
    // Named as §5.1's command lines spell them, since the operator passes the
    // directory name directly to the GDB harness.
    assert_eq!(PROFILES[0].0, "smp");
    assert_eq!(PROFILES[1].0, "control");
    assert_eq!((PROFILES[0].1, PROFILES[0].2), (6, 4));
    assert_eq!((PROFILES[1].1, PROFILES[1].2), (3, 1));
}

#[test]
fn the_boot_generation_separates_this_card_from_c1_and_from_another_nonce() {
    // Same material, different domain separator or nonce, different generation:
    // otherwise two products could claim one identity.
    let material = |tag: &[u8], nonce: &str| {
        let mut bytes = Vec::from(tag);
        bytes.extend_from_slice(b"revision");
        bytes.extend_from_slice(nonce.as_bytes());
        sha256::bytes_digest_array(&bytes)
    };
    let r1 = material(b"wyrmroot-r1-host-product-v1\0", "8100000000000001");
    let c1 = material(b"wyrmroot-wyr1-c1-host-product-v1\0", "8100000000000001");
    let other_nonce = material(b"wyrmroot-r1-host-product-v1\0", "8100000000000002");
    assert_ne!(r1, c1);
    assert_ne!(r1, other_nonce);
}
