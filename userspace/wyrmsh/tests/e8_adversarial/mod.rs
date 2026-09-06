// SPDX-License-Identifier: GPL-3.0-or-later

use super::*;

fn contains(bytes: &[u8], needle: &[u8]) -> bool {
    bytes.windows(needle.len()).any(|window| window == needle)
}

#[derive(Clone, Copy)]
struct RetiredEpoch {
    label: &'static str,
    base: u64,
}

impl RetiredEpoch {
    fn status_header(self) -> StatusHeader {
        StatusHeader {
            transaction_id: self.base + 1,
            console_generation: self.base + 2,
            status_generation: self.base + 3,
        }
    }

    fn status_snapshot(self) -> Snapshot {
        Snapshot {
            serial_registry_generation: self.base + 4,
            publication_generation: self.base + 5,
            device_bundle: self.base + 6,
            driver_attempt: self.base + 7,
            raw_stream_generation: self.base + 8,
            child_generation: self.base + 9,
            outer_job: self.base + 10,
            outer_launch_transaction: self.base + 11,
            ..status_snapshot()
        }
    }

    fn registry_header(self) -> RegistryHeader {
        RegistryHeader {
            message_type: RegistryMessageType::ServiceList,
            registry_generation: self.base + 4,
            endpoint_id: self.base + 12,
            endpoint_generation: self.base + 13,
            transaction_id: self.base + 14,
        }
    }

    fn jobs_reservation(self) -> Reservation {
        Reservation {
            connection_id: self.base + 15,
            generation: self.base + 16,
            transaction_id: self.base + 17,
        }
    }

    fn job_id(self) -> u64 {
        self.base + 18
    }
}

const RETIRED_EPOCHS: [RetiredEpoch; 3] = [
    RetiredEpoch {
        label: "S1",
        base: 0x700,
    },
    RetiredEpoch {
        label: "S2",
        base: 0x800,
    },
    RetiredEpoch {
        label: "S3",
        base: 0x900,
    },
];

fn assert_current_endpoint_reject_has_no_partial_committed_effects(fixture: &Fixture, label: &str) {
    let before = fixture
        .control_delivery_effects
        .last()
        .expect("stale control reply must reach the actual receiver");
    assert_eq!(
        &fixture.committed_effects(),
        before,
        "{label} committed partial effects before fatal rejection"
    );
    assert_eq!(fixture.closed.len(), 7, "{label} cleanup cardinality");
    for handle in [
        BOOTSTRAP, STDIN, STDOUT, STDERR, STATUS, REGISTRY, SHELL_JOBS,
    ] {
        assert_eq!(
            fixture
                .closed
                .iter()
                .filter(|closed| **closed == handle)
                .count(),
            1,
            "{label} cleanup for {handle:?}"
        );
    }
}

#[test]
fn each_old_status_tuple_on_the_current_endpoint_is_fatal_without_partial_committed_effects() {
    let mut cases = 0;
    for retired in RETIRED_EPOCHS {
        let mut bytes = [0; wyrmroot_console_proto::SNAPSHOT_BYTES];
        let size = encode_snapshot(
            retired.status_header(),
            retired.status_snapshot(),
            &mut bytes,
        )
        .unwrap();
        let mut fixture = Fixture::new(&[b"status\n"]);
        fixture.queue_control(STATUS, &bytes[..size]);

        assert_eq!(
            run_v2(&mut fixture, "system/wyrmsh", &[]),
            Err(ShellError::InspectionProtocol),
            "{}",
            retired.label
        );
        let stdout = fixture.output(STDOUT);
        assert!(!contains(&stdout, b"status state="), "{}", retired.label);
        assert!(
            !contains(&stdout, b"shell-generation="),
            "{}",
            retired.label
        );
        assert_current_endpoint_reject_has_no_partial_committed_effects(&fixture, retired.label);
        cases += 1;
    }
    assert_eq!(cases, 3);
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
fn each_old_registry_continuation_on_the_current_endpoint_commits_no_partial_enumeration() {
    let version = ProtocolVersion { major: 1, minor: 0 };
    let mut cases = 0;
    for retired in RETIRED_EPOCHS {
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
            retired.registry_header(),
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
            Err(ShellError::InspectionProtocol),
            "{}",
            retired.label
        );
        let stdout = fixture.output(STDOUT);
        for forbidden in [
            b"service name=".as_slice(),
            b"alpha".as_slice(),
            b"middle".as_slice(),
            b"zeta".as_slice(),
        ] {
            assert!(!contains(&stdout, forbidden), "{}", retired.label);
        }
        assert_current_endpoint_reject_has_no_partial_committed_effects(&fixture, retired.label);
        cases += 1;
    }
    assert_eq!(cases, 3);
}

#[test]
fn each_old_job_list_on_the_current_endpoint_produces_no_guessed_job_or_close() {
    let mut cases = 0;
    for retired in RETIRED_EPOCHS {
        let mut bytes = [0; 312];
        let size = encode_job_list(
            retired.jobs_reservation(),
            &[retired.job_id(), retired.job_id() + 1],
            &mut bytes,
        )
        .unwrap();
        let mut fixture = Fixture::new(&[b"tasks\n"]);
        fixture.queue_control(SHELL_JOBS, &bytes[..size]);

        assert_eq!(
            run_v2(&mut fixture, "system/wyrmsh", &[]),
            Err(ShellError::InspectionProtocol),
            "{}",
            retired.label
        );
        assert!(
            !contains(&fixture.output(STDOUT), b"task job="),
            "{}",
            retired.label
        );
        assert_eq!(
            fixture
                .trace
                .iter()
                .filter(|event| matches!(event, Trace::JobSend(_)))
                .copied()
                .collect::<Vec<_>>(),
            [Trace::JobSend(LaunchMessageType::ListJobs)],
            "{}",
            retired.label
        );
        assert_current_endpoint_reject_has_no_partial_committed_effects(&fixture, retired.label);
        cases += 1;
    }
    assert_eq!(cases, 3);
}

#[test]
fn each_old_job_result_on_the_current_endpoint_produces_no_result_or_close() {
    let mut cases = 0;
    for retired in RETIRED_EPOCHS {
        let mut bytes = [0; 88];
        let size = encode_job_result(
            retired.jobs_reservation(),
            retired.job_id(),
            TerminationResult {
                classification: TerminationClassification::UnhandledException,
                application_code: retired.base as u32 + 19,
                exception_class: retired.base as u32 + 20,
                exception_detail: retired.base as u32 + 21,
                exception_address: retired.base + 22,
                cleanup_result: wyrmroot_launch_proto::CLEANUP_RESULT_MASK,
            },
            &mut bytes,
        )
        .unwrap();
        let mut fixture = Fixture::new(&[b"spawn bin/cpu-hog\nwait 91\n"]);
        fixture.queue_control(
            SHELL_JOBS,
            &job_reply(1, LaunchMessageType::LaunchAccepted, 91),
        );
        fixture.queue_control(SHELL_JOBS, &bytes[..size]);

        assert_eq!(
            run_v2(&mut fixture, "system/wyrmsh", &[]),
            Err(ShellError::InspectionProtocol),
            "{}",
            retired.label
        );
        let stdout = fixture.output(STDOUT);
        assert!(!contains(&stdout, b"job result job="), "{}", retired.label);
        assert!(!contains(&stdout, b"application="), "{}", retired.label);
        assert!(
            !fixture
                .trace
                .contains(&Trace::JobSend(LaunchMessageType::CloseJob)),
            "{}",
            retired.label
        );
        assert_current_endpoint_reject_has_no_partial_committed_effects(&fixture, retired.label);
        cases += 1;
    }
    assert_eq!(cases, 3);
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
