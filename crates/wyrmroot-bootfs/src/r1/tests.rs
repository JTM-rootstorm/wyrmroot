use super::*;

const PROBE: [u8; 32] = [0x5A; 32];
#[cfg(feature = "builder")]
const HOG: [u8; 32] = [0x11; 32];
#[cfg(feature = "builder")]
const HELLO: [u8; 32] = [0x22; 32];

#[cfg(feature = "builder")]
#[test]
fn the_policy_admits_exactly_the_two_payloads_the_card_launches() {
    let entries = launch_policy_entries(HOG, HELLO);
    assert_eq!(entries.len(), R1_POLICY_ENTRY_COUNT);
    assert_eq!(entries[0].path, "bin/cpu-hog");
    assert_eq!(entries[1].path, "bin/hello");
    for entry in entries {
        assert_eq!(entry.profile_id, JOB_V2_PROFILE_ID);
        assert_eq!(entry.startup_abi, R1_STARTUP_ABI);
    }
    // §8.1's exclusions, asserted rather than assumed: no shell, no recovery
    // trigger, no stdout-pressure actor, and no console payload may be
    // launchable in this product.
    for excluded in [
        crate::launch_policy::WYRMSH_PATH,
        crate::wyr1::E8_RECOVERY_TRIGGER_PATH,
        crate::wyr1::E8_STDOUT_PRESSURE_PATH,
        crate::wyr1::CONSOLE_ECHO_PATH,
    ] {
        assert!(
            !entries.iter().any(|entry| entry.path == excluded),
            "{excluded} must not be launchable under card R1"
        );
    }
}

#[cfg(feature = "builder")]
#[test]
fn the_hog_is_admitted_zero_stream_and_the_progress_child_is_not() {
    let entries = launch_policy_entries(HOG, HELLO);
    // The hog must never hold stdio: it is a no-yield spinner, the geometry
    // ledger sizes its handles as Process and TaskGroup only, and a saturation
    // payload with output would change what the run measures.
    assert!(entries[0].allow_no_streams);
    assert!(!entries[0].allow_three_streams);
    // The progress child keeps the shape every other product gives it.
    assert!(!entries[1].allow_no_streams);
    assert!(entries[1].allow_three_streams);
    assert_eq!(entries[0].content_sha256, HOG);
    assert_eq!(entries[1].content_sha256, HELLO);
}

#[cfg(feature = "builder")]
#[test]
fn the_probe_image_is_not_itself_launchable_through_the_policy() {
    // The probe is a resident image the supervisor launches with the
    // LaunchClient profile. Admitting it to the JobV2 policy as well would let
    // anything holding a launch session start a second probe.
    let entries = launch_policy_entries(HOG, HELLO);
    assert!(!entries.iter().any(|entry| entry.path == R1_PROBE_PATH));
    assert_ne!(R1_PROBE_PATH, "bin/cpu-hog");
    assert_ne!(R1_PROBE_PATH, "bin/hello");
}

#[test]
fn the_gate_round_trips_both_profile_topologies() {
    // The two handoffs differ only here, which is what makes them one product.
    for (hog_count, online_cpus) in [(6_u16, 4_u16), (3, 1)] {
        let configuration = ProbeConfiguration {
            hog_count,
            online_cpus,
            probe_identity: PROBE,
        };
        let mut bytes = [0_u8; R1_GATE_BYTES];
        assert_eq!(encode_gate(configuration, &mut bytes), Ok(R1_GATE_BYTES));
        assert_eq!(parse_gate(&bytes), Ok(configuration));
    }
    // And the two encodings differ, so a run cannot be handed the wrong one and
    // still validate.
    let mut smp = [0_u8; R1_GATE_BYTES];
    let mut control = [0_u8; R1_GATE_BYTES];
    encode_gate(
        ProbeConfiguration {
            hog_count: 6,
            online_cpus: 4,
            probe_identity: PROBE,
        },
        &mut smp,
    )
    .unwrap();
    encode_gate(
        ProbeConfiguration {
            hog_count: 3,
            online_cpus: 1,
            probe_identity: PROBE,
        },
        &mut control,
    )
    .unwrap();
    assert_ne!(smp, control);
}

#[test]
fn the_gate_refuses_a_configuration_that_would_prove_nothing() {
    let mut bytes = [0_u8; R1_GATE_BYTES];
    for bad in [(0_u16, 4_u16), (6, 0), (0, 0)] {
        assert_eq!(
            encode_gate(
                ProbeConfiguration {
                    hog_count: bad.0,
                    online_cpus: bad.1,
                    probe_identity: PROBE,
                },
                &mut bytes
            ),
            Err(GateError::ZeroTopology)
        );
    }
    assert_eq!(
        encode_gate(
            ProbeConfiguration {
                hog_count: 6,
                online_cpus: 4,
                probe_identity: [0; 32],
            },
            &mut bytes
        ),
        Err(GateError::ZeroIdentity)
    );
    let mut short = [0_u8; R1_GATE_BYTES - 1];
    assert_eq!(
        encode_gate(
            ProbeConfiguration {
                hog_count: 6,
                online_cpus: 4,
                probe_identity: PROBE,
            },
            &mut short
        ),
        Err(GateError::WrongSize)
    );
}

#[test]
fn the_gate_parser_refuses_every_malformed_shape() {
    let configuration = ProbeConfiguration {
        hog_count: 6,
        online_cpus: 4,
        probe_identity: PROBE,
    };
    let mut good = [0_u8; R1_GATE_BYTES];
    encode_gate(configuration, &mut good).unwrap();

    assert_eq!(
        parse_gate(&good[..R1_GATE_BYTES - 1]),
        Err(GateError::WrongSize)
    );
    assert_eq!(parse_gate(&[]), Err(GateError::WrongSize));

    let mut magic = good;
    magic[1] = b'X';
    assert_eq!(parse_gate(&magic), Err(GateError::WrongMagic));

    let mut version = good;
    version[4] = 2;
    assert_eq!(parse_gate(&version), Err(GateError::UnsupportedVersion));

    let mut size = good;
    size[12] = 32;
    assert_eq!(parse_gate(&size), Err(GateError::WrongSize));

    // Undeclared trailing content is refused rather than ignored: a supervisor
    // that skipped it would accept a file carrying instructions it never read.
    let mut reserved = good;
    reserved[R1_GATE_BYTES - 1] = 1;
    assert_eq!(parse_gate(&reserved), Err(GateError::NonzeroReserved));

    let mut topology = good;
    topology[8..10].copy_from_slice(&0_u16.to_le_bytes());
    assert_eq!(parse_gate(&topology), Err(GateError::ZeroTopology));

    let mut identity = good;
    identity[16..48].fill(0);
    assert_eq!(parse_gate(&identity), Err(GateError::ZeroIdentity));
}

#[cfg(feature = "builder")]
mod archive {
    use super::*;
    use crate::archive::Archive;
    use crate::builder::BuildError;
    use crate::launch_policy::encode as encode_policy;
    use crate::wyr1::{
        CONSOLED_PATH, DEVMGR_PATH, INIT_PATH, LAUNCH_POLICY_PATH, REGISTRYD_PATH, UART16550D_PATH,
        WYR1_C1_MARKER, WYRMSH_PATH,
        tests::{UART_IDENTITY, c1_product, canonical_wrdm},
    };

    const GENERATION: [u8; 32] = [0x77; 32];

    fn policy_bytes(hog: [u8; 32], hello: [u8; 32]) -> alloc::vec::Vec<u8> {
        let mut bytes = [0_u8; 1024];
        let size = encode_policy(GENERATION, &launch_policy_entries(hog, hello), &mut bytes)
            .expect("policy encodes");
        bytes[..size].to_vec()
    }

    fn gate_bytes(hog_count: u16, online_cpus: u16, probe: [u8; 32]) -> [u8; R1_GATE_BYTES] {
        let mut bytes = [0_u8; R1_GATE_BYTES];
        encode_gate(
            ProbeConfiguration {
                hog_count,
                online_cpus,
                probe_identity: probe,
            },
            &mut bytes,
        )
        .expect("gate encodes");
        bytes
    }

    fn product<'a>(
        device_manifest: &'a [u8],
        launch_policy: &'a [u8],
        gate_config: &'a [u8],
    ) -> ProductR1<'a> {
        ProductR1 {
            c1: c1_product(WYR1_C1_MARKER, device_manifest, UART_IDENTITY),
            launch_policy,
            gate_config,
            probe: b"probe",
            cpu_hog: b"hog",
            hello: b"hello",
            expected_probe_identity: PROBE,
            expected_cpu_hog_identity: HOG,
            expected_hello_identity: HELLO,
        }
    }

    #[test]
    fn the_archive_is_deterministic_and_carries_the_exact_entry_set() {
        let wrdm = canonical_wrdm(UART_IDENTITY);
        let policy = policy_bytes(HOG, HELLO);
        let gate = gate_bytes(6, 4, PROBE);
        let bytes = build_r1(product(&wrdm, &policy, &gate)).unwrap();
        assert_eq!(bytes, build_r1(product(&wrdm, &policy, &gate)).unwrap());

        let archive = Archive::new(&bytes).unwrap();
        for path in [
            INIT_PATH,
            REGISTRYD_PATH,
            DEVMGR_PATH,
            LAUNCH_POLICY_PATH,
            R1_GATE_PATH,
            R1_PROBE_PATH,
            "bin/cpu-hog",
            "bin/hello",
        ] {
            assert!(archive.lookup(path.as_bytes()).is_ok(), "{path} is missing");
        }
        // The three excluded roles are present as images because the RRC graph
        // says the roles exist, and non-launchable because the policy admits
        // neither. Their presence is the graph; their exclusion is the policy.
        for retained in [UART16550D_PATH, CONSOLED_PATH, WYRMSH_PATH] {
            assert!(archive.lookup(retained.as_bytes()).is_ok());
            assert!(
                !launch_policy_entries(HOG, HELLO)
                    .iter()
                    .any(|entry| entry.path == retained)
            );
        }
        assert!(
            archive
                .lookup(R1_PROBE_PATH.as_bytes())
                .unwrap()
                .is_executable()
        );
        assert!(
            !archive
                .lookup(R1_GATE_PATH.as_bytes())
                .unwrap()
                .is_executable()
        );
        assert!(
            !archive
                .lookup(LAUNCH_POLICY_PATH.as_bytes())
                .unwrap()
                .is_executable()
        );
    }

    #[test]
    fn a_policy_naming_different_bytes_than_the_payloads_is_refused() {
        // The failure this prevents: an image whose policy admits a digest the
        // archive does not contain would boot and then refuse every launch,
        // which reads as the probe failing rather than as a build defect.
        let wrdm = canonical_wrdm(UART_IDENTITY);
        let gate = gate_bytes(6, 4, PROBE);
        let substituted = policy_bytes([0x99; 32], HELLO);
        assert_eq!(
            build_r1(product(&wrdm, &substituted, &gate)),
            Err(BuildError::R1PolicyIdentityMismatch)
        );
        let substituted_hello = policy_bytes(HOG, [0x98; 32]);
        assert_eq!(
            build_r1(product(&wrdm, &substituted_hello, &gate)),
            Err(BuildError::R1PolicyIdentityMismatch)
        );
    }

    #[test]
    fn a_policy_with_the_wrong_stream_shape_or_extra_entry_is_refused() {
        let wrdm = canonical_wrdm(UART_IDENTITY);
        let gate = gate_bytes(6, 4, PROBE);

        // Giving the hog stdio is structurally valid and semantically wrong: a
        // saturation payload with output changes what the run measures.
        let mut entries = launch_policy_entries(HOG, HELLO);
        entries[0].allow_no_streams = false;
        entries[0].allow_three_streams = true;
        let mut bytes = [0_u8; 1024];
        let size = encode_policy(GENERATION, &entries, &mut bytes).unwrap();
        assert_eq!(
            build_r1(product(&wrdm, &bytes[..size], &gate)),
            Err(BuildError::InvalidR1LaunchPolicy)
        );

        // One admitted payload too many is refused even when both expected
        // entries are present and correct.
        let widened = [
            entries[0],
            entries[1],
            crate::launch_policy::LaunchPolicyEntry {
                path: crate::launch_policy::WYRMSH_PATH,
                content_sha256: [0x33; 32],
                startup_abi: R1_STARTUP_ABI,
                profile_id: JOB_V2_PROFILE_ID,
                allow_no_streams: false,
                allow_three_streams: true,
            },
        ];
        let mut wide = [0_u8; 1024];
        let size = encode_policy(GENERATION, &widened, &mut wide).unwrap();
        assert_eq!(
            build_r1(product(&wrdm, &wide[..size], &gate)),
            Err(BuildError::InvalidR1LaunchPolicy)
        );
    }

    #[test]
    fn a_gate_naming_another_probe_or_topology_is_refused() {
        let wrdm = canonical_wrdm(UART_IDENTITY);
        let policy = policy_bytes(HOG, HELLO);

        let foreign = gate_bytes(6, 4, [0x5B; 32]);
        assert_eq!(
            build_r1(product(&wrdm, &policy, &foreign)),
            Err(BuildError::R1ProbeIdentityMismatch)
        );

        // A topology no profile handoff provides. Both halves are individually
        // plausible, which is why the pairing is what gets checked.
        let unaccepted = gate_bytes(6, 1, PROBE);
        assert_eq!(
            build_r1(product(&wrdm, &policy, &unaccepted)),
            Err(BuildError::R1UnacceptedTopology)
        );
        let malformed = [0_u8; R1_GATE_BYTES];
        assert_eq!(
            build_r1(product(&wrdm, &policy, &malformed)),
            Err(BuildError::InvalidR1GateConfiguration)
        );
    }

    #[test]
    fn both_profile_handoffs_build_and_differ_only_in_the_gate() {
        let wrdm = canonical_wrdm(UART_IDENTITY);
        let policy = policy_bytes(HOG, HELLO);
        let smp = build_r1(product(&wrdm, &policy, &gate_bytes(6, 4, PROBE))).unwrap();
        let control = build_r1(product(&wrdm, &policy, &gate_bytes(3, 1, PROBE))).unwrap();
        assert_ne!(smp, control);
        // Same entry set, same payload bytes: the two runs are one product with
        // two configurations, which is what lets their results be compared.
        assert_eq!(smp.len(), control.len());
        let smp_archive = Archive::new(&smp).unwrap();
        let control_archive = Archive::new(&control).unwrap();
        for path in [
            R1_PROBE_PATH,
            "bin/cpu-hog",
            "bin/hello",
            LAUNCH_POLICY_PATH,
        ] {
            assert_eq!(
                smp_archive.lookup(path.as_bytes()).unwrap().data(),
                control_archive.lookup(path.as_bytes()).unwrap().data()
            );
        }
        assert_ne!(
            smp_archive.lookup(R1_GATE_PATH.as_bytes()).unwrap().data(),
            control_archive
                .lookup(R1_GATE_PATH.as_bytes())
                .unwrap()
                .data()
        );
    }

    #[test]
    fn c1s_own_validation_still_applies() {
        // R1 does not get a weaker base: a malformed device manifest or a wrong
        // marker is refused here exactly as build_c1 refuses it.
        let policy = policy_bytes(HOG, HELLO);
        let gate = gate_bytes(6, 4, PROBE);
        let wrong_driver = canonical_wrdm([0xa2; 32]);
        assert_eq!(
            build_r1(product(&wrong_driver, &policy, &gate)),
            Err(BuildError::C1DriverIdentityMismatch)
        );
        let wrdm = canonical_wrdm(UART_IDENTITY);
        let mut wrong_marker = product(&wrdm, &policy, &gate);
        wrong_marker.c1.marker = b"WYR1-B";
        assert_eq!(build_r1(wrong_marker), Err(BuildError::WrongC1Marker));
    }
}
