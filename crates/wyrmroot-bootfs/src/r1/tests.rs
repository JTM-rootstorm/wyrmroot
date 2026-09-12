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
