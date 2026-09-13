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

mod domain {
    use super::*;
    use std::path::PathBuf;

    fn render(vcpus: u8, port: u16) -> (String, PathBuf) {
        let root = PathBuf::from("/home/mike/Documents/Programming/OS-Project");
        let product = root.join("artifacts/r1-260912");
        let output = product.join(if vcpus == 1 { "control" } else { "smp" });
        let xml = domain_xml(
            vcpus,
            port,
            &product.join("artifacts/OVMF_CODE.fd"),
            &product.join("artifacts/r1-esp.img"),
            &output.join("OVMF_VARS.fd"),
        );
        (xml, output)
    }

    /// Every check `tools/run-active-gdb-vm.sh` performs on the XML it is handed,
    /// asserted here so the harness cannot refuse a generated domain at run time —
    /// which under the lease would waste an accepted request.
    #[test]
    fn the_domain_satisfies_every_check_the_gdb_harness_makes() {
        let (xml, output) = render(4, 1240);
        assert!(xml.contains("<name>OS-Project</name>"));
        assert!(xml.contains(&format!("<uuid>{DOMAIN_UUID}</uuid>")));
        assert!(xml.contains("<qemu:arg value=\"-S\"/>"));
        assert!(xml.contains("<qemu:arg value=\"tcp:127.0.0.1:1240\"/>"));
        assert!(xml.contains(&format!(
            "<source file=\"{}\"",
            output.join("OVMF_VARS.fd").display()
        )));
        // The harness rejects any file containing one. C6's domain carries them
        // on nvram and disk because its runner owns those descriptors.
        assert!(
            !xml.contains(" fdgroup="),
            "the GDB harness refuses runner-owned fdgroup annotations"
        );
    }

    #[test]
    fn the_gdbstub_port_is_the_one_the_operator_passes() {
        // The port is baked into the XML and also passed to the harness
        // separately. If they disagreed, the attach would hang until the timeout
        // and the run would look like a guest stall.
        for port in [1240_u16, 1236, 65535] {
            let (xml, _) = render(4, port);
            assert!(xml.contains(&format!("<qemu:arg value=\"tcp:127.0.0.1:{port}\"/>")));
            assert_eq!(
                xml.matches("tcp:127.0.0.1:").count(),
                1,
                "exactly one gdbstub endpoint"
            );
        }
    }

    #[test]
    fn each_profile_declares_its_own_exact_width() {
        // §4 rejects a run at a different width outright: A27's diagnosis depends
        // on the exact topology, so the domain must state it rather than inherit
        // whatever the domain was last defined with.
        let (smp, _) = render(4, 1240);
        let (control, _) = render(1, 1240);
        assert!(smp.contains("<vcpu placement=\"static\">4</vcpu>"));
        assert!(control.contains("<vcpu placement=\"static\">1</vcpu>"));
        assert_ne!(smp, control);
    }

    #[test]
    fn the_selector_and_test_id_reach_the_guest_by_firmware_config() {
        let (xml, _) = render(4, 1240);
        assert!(xml.contains(
            "<entry name=\"opt/org.deepwyrm.test.selector\">dynamic-launch-saturation</entry>"
        ));
        assert!(xml.contains("<entry name=\"opt/org.deepwyrm.test.test_id\">34</entry>"));
        assert_eq!(TEST_ID, 34);
        assert_eq!(SELECTOR, "dynamic-launch-saturation");
    }

    #[test]
    fn com2_is_null_and_the_transcript_leaves_over_com1() {
        let (xml, _) = render(4, 1240);
        // §8.1 excludes COM2 conversation from this card. A socket here would
        // create a second channel the card has no protocol for.
        assert!(xml.contains("<serial type=\"null\"><target type=\"isa-serial\" port=\"1\"/>"));
        assert!(!xml.contains("com2"));
        assert!(!xml.contains("type=\"unix\""));
        assert!(xml.contains("<serial type=\"pty\"><target type=\"isa-serial\" port=\"0\"/>"));
        // isa-debug-exit is how the kernel completes a run.
        assert!(xml.contains("isa-debug-exit,iobase=0xf4,iosize=0x04"));
    }

    #[test]
    fn the_nvram_path_is_the_per_run_copy_the_harness_makes() {
        // The harness refuses to start if <output>/OVMF_VARS.fd already exists,
        // and makes the copy itself. So prepare must reference that path and must
        // not create the file. Both profiles must point at their own copy, or one
        // run would inherit the other's variables.
        let (smp, smp_output) = render(4, 1240);
        let (control, control_output) = render(1, 1240);
        assert!(smp.contains(&smp_output.join("OVMF_VARS.fd").display().to_string()));
        assert!(control.contains(&control_output.join("OVMF_VARS.fd").display().to_string()));
        assert!(!smp.contains(&control_output.join("OVMF_VARS.fd").display().to_string()));
        assert_ne!(smp_output, control_output);
    }
}

mod media {
    use super::*;

    #[test]
    fn the_kernel_environment_is_exactly_the_selector_and_the_nonce() {
        let environment = kernel_environment("8100000000000001");
        assert_eq!(
            environment,
            [
                (
                    "DEEPWYRM_GUEST_TEST_SELECTOR",
                    "dynamic-launch-saturation".to_owned()
                ),
                ("DEEPWYRM_R1_EVIDENCE_NONCE", "8100000000000001".to_owned()),
            ]
        );
        // The nonce must be the same value the probe was compiled against. If it
        // were not, the collector would refuse every record and a working run
        // would report nothing at all — the failure mode hardest to tell from a
        // scheduler stall, which is what this card exists to distinguish.
        assert_eq!(environment[1].0, R1_EVIDENCE_VARIABLE);
        assert!(NONCE_BOUND_LABELS.contains(&"r1-probe"));
    }

    #[test]
    fn the_media_set_names_no_per_profile_artifact() {
        // bootfs.img and the ESP are per-profile, because the two handoffs differ
        // precisely in the WRR1 configuration their archive carries. Staging
        // either as shared media would silently give both profiles one topology.
        assert_eq!(MEDIA_ARTIFACTS.len(), 13);
        for shared in ["loader.efi", "deepwyrm.elf", "OVMF_CODE.fd", "OVMF_VARS.fd"] {
            assert!(MEDIA_ARTIFACTS.contains(&shared), "{shared} is missing");
        }
        for per_profile in ["bootfs.img", "r1-esp.img", "r1-gate-v1.bin", "domain.xml"] {
            assert!(
                !MEDIA_ARTIFACTS.contains(&per_profile),
                "{per_profile} is per-profile and must not be shared media"
            );
        }
    }

    #[test]
    fn the_symbols_and_kernel_are_the_same_image() {
        // The release profile keeps full DWARF, which is what lets the GDB harness
        // read §8.2's carrier facts. Stripping one of the two would silently
        // remove the only way this card obtains its evidence.
        assert!(MEDIA_ARTIFACTS.contains(&"deepwyrm.elf"));
        assert!(MEDIA_ARTIFACTS.contains(&"deepwyrm.symbols.elf"));
    }

    #[test]
    fn the_excluded_roles_are_staged_as_images_but_launch_nothing() {
        // Their presence is the RRC graph, which requires all five roles to exist;
        // their exclusion is the launch policy, which admits neither.
        for retained in ["uart16550d.elf", "consoled.elf", "wyrmsh.elf"] {
            assert!(MEDIA_ARTIFACTS.contains(&retained));
        }
        let entries = wyrmroot_bootfs::r1::launch_policy_entries([0x11; 32], [0x22; 32]);
        for path in ["system/wyrmsh", "system/consoled", "system/uart16550d"] {
            assert!(!entries.iter().any(|entry| entry.path == path));
        }
    }
}
