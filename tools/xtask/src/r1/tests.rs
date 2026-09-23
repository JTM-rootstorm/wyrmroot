use super::*;

/// S1.1: every combination the R1 product builds is in the host gate table.
#[test]
fn every_r1_native_spec_combination_is_in_the_host_gate_table() {
    for spec in NATIVE_SPECS {
        assert!(
            crate::tasks::is_listed_combination(spec.package, spec.features),
            "{} builds {} with {}, which FEATURE_COMBINATIONS omits",
            spec.label,
            spec.package,
            spec.features
        );
    }
}

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

    /// The handoff card R1's third run failed on, asserted where the two halves
    /// are chosen rather than discovered by booting.
    ///
    /// The bootstrap decides how it launches permanent init; the init spec
    /// decides how init receives. Those are picked in two different files, and
    /// nothing related them: a bootstrap built with a `wyr1c*-production`
    /// feature launches `SupervisorResourceDomain` (four handles,
    /// `SUPERVISOR_BYTES + 8`), while an init without one receives as
    /// `Supervisor` (three handles, `SUPERVISOR_BYTES`). The kernel refuses that
    /// with `BUFFER_TOO_SMALL`.
    #[test]
    fn the_init_features_match_the_bootstrap_that_launches_it() {
        const C6: &str = include_str!("../wyr1c6.rs");
        let bootstrap_is_resource_product = C6.contains("\"wyr1c6-production\"")
            || C6.contains("\"wyr1c5-production\"")
            || C6.contains("\"wyr1c4-production\"");
        assert!(
            bootstrap_is_resource_product,
            "card R1 builds its bootstrap through wyr1c6; if that stopped being \
             a production bootstrap, re-derive the handoff shape below"
        );
        let init = NATIVE_SPECS
            .iter()
            .find(|spec| spec.label == "system-init")
            .expect("card R1 stages permanent init");
        // The spec names one feature and Cargo resolves the rest, so the receive
        // shape is decided in the manifest. Read it there rather than in the
        // spec string, which is what an earlier version of this check got wrong.
        const INIT_MANIFEST: &str = include_str!("../../../../userspace/system-init/Cargo.toml");
        let selected = INIT_MANIFEST
            .split(&format!("\n{} = [", init.features))
            .nth(1)
            .and_then(|rest| rest.split(']').next())
            .unwrap_or_else(|| panic!("system-init declares no {} feature list", init.features));
        assert!(
            selected.contains("wyr1c5-production") || selected.contains("wyr1c4-production"),
            "the bootstrap launches init as SupervisorResourceDomain but {} \
             selects the plain Supervisor receive shape, so the handoff fails \
             with BUFFER_TOO_SMALL: the feature list was {selected:?}",
            init.features
        );
    }

    fn archives(sizes: &[(&str, usize)]) -> BTreeMap<String, Vec<u8>> {
        sizes
            .iter()
            .map(|(name, bytes)| ((*name).to_owned(), vec![0_u8; *bytes]))
            .collect()
    }

    #[test]
    fn the_page_bound_is_measured_from_the_largest_archive_that_will_be_mapped() {
        // One kernel serves both profiles, so the smaller archive must not set
        // the bound: the journal has to fit whichever archive is mapped.
        assert_eq!(
            bootfs_page_ceiling(&archives(&[("smp", 593_328), ("control", 4_096)])).unwrap(),
            145
        );
        assert_eq!(
            bootfs_page_ceiling(&archives(&[("smp", 4_096), ("control", 593_328)])).unwrap(),
            145
        );
        // A partial trailing page still needs a whole mapped page.
        assert_eq!(
            bootfs_page_ceiling(&archives(&[("smp", 4_097)])).unwrap(),
            2
        );
        assert_eq!(
            bootfs_page_ceiling(&archives(&[("smp", 4_096)])).unwrap(),
            1
        );
    }

    #[test]
    fn the_page_bound_refuses_what_deepwyrm_cannot_compile() {
        // Deepwyrm's parser asserts 1..=8192, so an out-of-range count must fail
        // here rather than at kernel build time with a const-eval panic.
        assert!(bootfs_page_ceiling(&archives(&[("smp", 8_192 * 4_096)])).is_ok());
        assert!(bootfs_page_ceiling(&archives(&[("smp", 8_192 * 4_096 + 1)])).is_err());
        // An empty archive would compile a zero ceiling, which the kernel rejects.
        assert!(bootfs_page_ceiling(&archives(&[("smp", 0)])).is_err());
        // No profile at all is a producer defect, not a zero bound.
        assert!(bootfs_page_ceiling(&BTreeMap::new()).is_err());
    }

    #[test]
    fn the_kernel_environment_is_exactly_the_selector_the_nonce_and_the_page_bound() {
        let environment = kernel_environment("8100000000000001", 145);
        assert_eq!(
            environment,
            [
                (
                    "DEEPWYRM_GUEST_TEST_SELECTOR",
                    "dynamic-launch-saturation".to_owned()
                ),
                ("DEEPWYRM_R1_EVIDENCE_NONCE", "8100000000000001".to_owned()),
                ("DEEPWYRM_R1_BOOTFS_MAX_PAGES", "145".to_owned()),
            ]
        );
        // The page bound is not decoration: Deepwyrm sizes its primordial
        // mapping journal from it, and selector 34 inherited a 17-page default
        // before this variable existed, which made the bootstrap's bootfs
        // mapping fail with NO_RESOURCES on a 145-page archive.
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

mod request {
    use super::*;

    #[test]
    fn the_host_timeout_exceeds_every_bound_the_probe_can_legitimately_use() {
        // This ordering is the card's whole premise. A27 produced no evidence
        // because the host's 30 s bound expired before anything in the guest
        // reported; the probe now bounds its own waits so it reports a
        // classification first, and the host bound exists only to stop a wedged
        // guest holding the lease.
        const {
            assert!(REQUEST_TIMEOUT_SECONDS > PROBE_WORST_CASE_SECONDS);
            // A27's own bound, which this must not regress to.
            assert!(REQUEST_TIMEOUT_SECONDS > 30);
        }
        // Derived from the probe's own constants rather than guessed: per hog an
        // accept, a progress accept and a progress result, then bounded cleanup.
        let per_hog = 3 + 3 + 8;
        let per_cleanup = 8 + 8;
        let smp_hogs = u32::from(PROFILES[0].1);
        assert_eq!(smp_hogs * (per_hog + per_cleanup), PROBE_WORST_CASE_SECONDS);
        assert_eq!(REQUEST_TIMEOUT_SECONDS, 300);
    }

    #[test]
    fn a_prepared_request_carries_its_own_card_and_not_another_cards_question() {
        let mut digests = BTreeMap::new();
        digests.insert("smp/r1-esp.img".to_owned(), "aa".repeat(32));
        let render = |card| {
            render_request(
                Path::new("/home/mike/Documents/Programming/OS-Project/artifacts/r1-260912"),
                card,
                "a7ce03706f85b186b2810c3ac38377f0ccac7238",
                "12d75ae405e5aa66960246ad459ec5e9f18127de",
                "085b184c32ae1fa3d5ec322c86957dd5d036595c",
                "a9b067107ec38e2be44630f4dce428dab0f48de8",
                "8100000000000001",
                1240,
                145,
                &digests,
            )
            .unwrap()
        };

        let r1c = render(RequestCard::R1C);
        assert!(r1c.contains("card = \"R1C\""));
        assert!(r1c.contains("reproduce the present failure family"));

        let r4e = render(RequestCard::R4E);
        assert!(r4e.contains("card = \"R4E\""));
        assert!(r4e.contains("more hogs than CPUs are launched on exactly four vCPUs"));
        // The point of the flag: R4E must not inherit the question or the
        // wants-a-failure framing of the card that ran before it.
        assert!(!r4e.contains("reproduce the present failure family"));
        assert!(!r4e.contains("A failing run is a valid result if it identifies"));
        assert!(r4e.contains("cannot discriminate R4B/R4C from their absence"));
        // Both still require the gdbstub, for opposite reasons.
        assert!(r1c.contains("gdb_required = true"));
        assert!(r4e.contains("gdb_required = true"));
        assert!(r4e.contains("The hook reads nothing on a passing run."));
    }

    #[test]
    fn the_request_states_every_element_section_10_requires() {
        let mut digests = BTreeMap::new();
        digests.insert("smp/r1-esp.img".to_owned(), "aa".repeat(32));
        let request = render_request(
            Path::new("/home/mike/Documents/Programming/OS-Project/artifacts/r1-260912"),
            RequestCard::R1C,
            "a7ce03706f85b186b2810c3ac38377f0ccac7238",
            "12d75ae405e5aa66960246ad459ec5e9f18127de",
            "085b184c32ae1fa3d5ec322c86957dd5d036595c",
            "a9b067107ec38e2be44630f4dce428dab0f48de8",
            "8100000000000001",
            1240,
            145,
            &digests,
        )
        .unwrap();

        // §10: project/gate, revisions with dirty qualification, artifact and
        // media identity, effective profile, selector/commands/expected signals,
        // timeout/logs, and destructive storage/configuration/cleanup needs.
        for required in [
            "[gate]",
            "card = \"R1C\"",
            "deepwyrm_dirty = \"clean\"",
            "wyrmroot_dirty = \"clean\"",
            "generated_abi_tree =",
            "[digest]",
            "[profile.smp]",
            "[profile.control]",
            "selector = \"dynamic-launch-saturation\"",
            "[expected_signals]",
            "timeout_seconds = 300",
            "logs =",
            "destructive_needs = \"none\"",
            "primary_qcow2_host_side_mutation = \"not-requested\"",
            "cleanup =",
            "configuration_delta =",
            "baseline_xml_sha256 =",
            "lease = \"/tmp/os-project-vm.lock\"",
            "connection = \"qemu:///system\"",
        ] {
            assert!(request.contains(required), "request omits {required}");
        }
        // It must not claim anything it cannot establish.
        assert!(request.contains("acceptance_identity = \"none-minted\""));
        assert!(request.contains("advances_e8 = false"));
        assert!(request.contains("physical_io = \"not-performed\""));
        // And it must say plainly that the verifier does not consume it, so no
        // operator goes looking for a schema that does not exist.
        assert!(request.contains("not"));
        assert!(request.contains("verify-vm-request.py"));
    }

    #[test]
    fn each_profile_carries_the_exact_command_for_its_own_leg() {
        let output = Path::new("/home/mike/Documents/Programming/OS-Project/artifacts/r1-260912");
        let request = render_request(
            output,
            RequestCard::R1C,
            "a7ce037",
            "12d75ae",
            "085b184",
            "a9b0671",
            "8100000000000001",
            1240,
            145,
            &BTreeMap::new(),
        )
        .unwrap();
        // Each command must name its own domain and output directory. Passing one
        // profile's domain with the other's output directory would put the nvram
        // copy where the domain does not expect it and fail at start.
        for (profile, _, _) in PROFILES {
            let directory = output.join(profile);
            assert!(request.contains(&format!("{} ", directory.join("domain.xml").display())));
            assert!(request.contains(&format!("{} 1240 300", directory.display())));
        }
        assert!(request.contains("run-active-gdb-vm.sh"));
        assert!(request.contains("ACTIVE_GDB_EXTRA_HOOKS=tools/gdb/r1-liveness.gdb"));
        assert!(request.contains("diagnostic-only"));
        assert!(request.contains("vcpus = 4"));
        assert!(request.contains("vcpus = 1"));
    }
}
