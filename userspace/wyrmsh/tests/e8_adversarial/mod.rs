// SPDX-License-Identifier: GPL-3.0-or-later

use super::*;

fn contains(bytes: &[u8], needle: &[u8]) -> bool {
    bytes.windows(needle.len()).any(|window| window == needle)
}

#[test]
fn old_whole_status_tuple_produces_no_current_snapshot_output() {
    let mut bytes = [0; wyrmroot_console_proto::SNAPSHOT_BYTES];
    let size = encode_snapshot(
        StatusHeader {
            transaction_id: 0x701,
            console_generation: 0x702,
            status_generation: 0x703,
        },
        status_snapshot(),
        &mut bytes,
    )
    .unwrap();
    let mut fixture = Fixture::new(&[b"status\n"]);
    fixture.queue_control(STATUS, &bytes[..size]);

    assert_eq!(
        run_v2(&mut fixture, "system/wyrmsh", &[]),
        Err(ShellError::InspectionProtocol)
    );
    let stdout = fixture.output(STDOUT);
    assert!(!contains(&stdout, b"status state="));
    assert!(!contains(&stdout, b"shell-generation="));
}

#[test]
fn every_truncated_wyrmsh_init_closes_all_roles_without_partial_ready() {
    for cut in 0..WYRMSH_BYTES {
        let mut fixture = Fixture::new(&[]);
        fixture.receive_counts.bytes = cut;
        assert_eq!(
            run_v2(&mut fixture, "system/wyrmsh", &[]),
            Err(ShellError::ReceiveCounts(fixture.receive_counts))
        );
        assert!(fixture.ready.is_empty(), "partial READY at cut {cut}");
        assert_eq!(
            fixture.closed.len(),
            6,
            "incomplete role cleanup at cut {cut}"
        );
        for handle in [STDIN, STDOUT, STDERR, STATUS, REGISTRY, SHELL_JOBS] {
            assert_eq!(
                fixture
                    .closed
                    .iter()
                    .filter(|closed| **closed == handle)
                    .count(),
                1
            );
        }
    }
}

#[test]
fn cross_registry_generation_continuation_commits_no_partial_enumeration() {
    let version = ProtocolVersion { major: 1, minor: 0 };
    let mut fixture = Fixture::new(&[b"services\n"]);
    fixture.queue_control(
        REGISTRY,
        &registry_reply(
            2,
            0,
            2,
            3,
            &[
                service(b"alpha", 11, 12, &[version]),
                service(b"middle", 21, 22, &[version]),
            ],
        ),
    );

    let mut bytes = [0; 416];
    let size = encode_service_list(
        RegistryHeader {
            message_type: RegistryMessageType::ServiceList,
            registry_generation: 0x801,
            endpoint_id: 0x802,
            endpoint_generation: 0x803,
            transaction_id: 2,
        },
        1,
        2,
        3,
        &[service(b"zeta", 31, 32, &[version])],
        &mut bytes,
    )
    .unwrap();
    fixture.queue_control(REGISTRY, &bytes[..size]);

    assert_eq!(
        run_v2(&mut fixture, "system/wyrmsh", &[]),
        Err(ShellError::InspectionProtocol)
    );
    let stdout = fixture.output(STDOUT);
    assert!(!contains(&stdout, b"service name="));
    assert!(!contains(&stdout, b"alpha"));
    assert!(!contains(&stdout, b"middle"));
    assert!(!contains(&stdout, b"zeta"));
}

#[test]
fn old_whole_job_list_tuple_produces_no_guessed_job_or_close() {
    let mut bytes = [0; 312];
    let size = encode_job_list(
        Reservation {
            connection_id: 0x901,
            generation: 0x902,
            transaction_id: 0x903,
        },
        &[0x904, 0x905],
        &mut bytes,
    )
    .unwrap();
    let mut fixture = Fixture::new(&[b"tasks\n"]);
    fixture.queue_control(SHELL_JOBS, &bytes[..size]);

    assert_eq!(
        run_v2(&mut fixture, "system/wyrmsh", &[]),
        Err(ShellError::InspectionProtocol)
    );
    assert!(!contains(&fixture.output(STDOUT), b"task job="));
    assert_eq!(
        fixture
            .trace
            .iter()
            .filter(|event| matches!(event, Trace::JobSend(_)))
            .copied()
            .collect::<Vec<_>>(),
        [Trace::JobSend(LaunchMessageType::ListJobs)]
    );
}

#[test]
fn malformed_wrst_frame_cannot_become_command_input() {
    let mut malformed = wire(b"help\n");
    malformed[0] ^= 1;
    let mut fixture = Fixture::new(&[]);
    fixture.incoming.push_back(malformed);

    assert_eq!(
        run_v2(&mut fixture, "system/wyrmsh", &[]),
        Err(ShellError::Stream(wyrmroot_runtime::StreamError::Protocol))
    );
    let stdout = fixture.output(STDOUT);
    assert!(!contains(&stdout, b"help - show"));
    assert!(fixture.control_requests.is_empty());
}

#[test]
fn every_wrst_fragment_boundary_preserves_control_input_semantics() {
    let input = b"echo boundary\x1b[D!\nexit\n";
    for split in 0..=input.len() {
        let mut fixture = Fixture::new(&[&input[..split], &input[split..]]);
        assert_eq!(
            run_v2(&mut fixture, "system/wyrmsh", &[]),
            Ok(()),
            "split {split}"
        );
        let stdout = fixture.output(STDOUT);
        assert!(contains(&stdout, b"boundar!y\n"), "split {split}");
        assert!(fixture.control_requests.is_empty(), "split {split}");
    }
}
