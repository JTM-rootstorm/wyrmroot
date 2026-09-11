use super::*;

/// Drives a probe through a fully successful run, returning the observed order.
fn run_to_completion(plan: ProbePlan) -> (SaturationProbe, usize) {
    let mut probe = SaturationProbe::new(plan).expect("valid plan");
    let mut job = 100_u64;
    let mut guard = 0;
    while probe.outcome().is_none() {
        guard += 1;
        assert!(guard < 1000, "probe failed to terminate");
        match probe.next_step().expect("open run offers a step") {
            ProbeStep::LaunchHog { index } => assert!(probe.observe_hog_submitted(index)),
            ProbeStep::AwaitHogAccepted { index } => {
                job += 1;
                assert!(probe.observe_hog_accepted(index, job));
            }
            ProbeStep::LaunchProgress { after_hog } => {
                job += 1;
                assert!(probe.observe_progress_accepted(after_hog, job));
            }
            ProbeStep::AwaitProgressResult { after_hog } => {
                assert!(probe.observe_progress_result(after_hog, job, 0));
            }
            ProbeStep::TerminateHog { index } => assert!(probe.observe_hog_terminated(index)),
            ProbeStep::AwaitHogResult { index } => {
                let expected = 101 + (index as u64) * 2;
                assert!(probe.observe_hog_result(index, expected, 0));
            }
            ProbeStep::Complete => unreachable!("Complete implies a terminal outcome"),
        }
    }
    (probe, guard)
}

#[test]
fn canonical_smp_plan_matches_the_plan_section_8_1_topology() {
    const {
        assert!(ProbePlan::SMP.online_cpus == 4);
        // "at least online_cpu_count + 2".
        assert!(ProbePlan::SMP.hog_count >= ProbePlan::SMP.online_cpus + 2);
        assert!(ProbePlan::SMP.is_valid());
        assert!(ProbePlan::CONTROL.is_valid());
        assert!(ProbePlan::CONTROL.online_cpus == 1);
    }
}

#[test]
fn an_invalid_plan_is_refused_rather_than_clamped() {
    assert!(
        SaturationProbe::new(ProbePlan {
            hog_count: 0,
            online_cpus: 4
        })
        .is_none()
    );
    assert!(
        SaturationProbe::new(ProbePlan {
            hog_count: MAX_HOGS + 1,
            online_cpus: 4
        })
        .is_none()
    );
    assert!(
        SaturationProbe::new(ProbePlan {
            hog_count: 4,
            online_cpus: 0
        })
        .is_none()
    );
}

#[test]
fn a_clean_smp_run_passes_and_proves_progress_after_every_hog() {
    let (probe, _) = run_to_completion(ProbePlan::SMP);
    assert_eq!(probe.outcome(), Some(ProbeOutcome::Passed));
    assert_eq!(probe.steps_observed(), ProbePlan::SMP.step_budget());
    assert_eq!(probe.admitted_hogs(), 0, "cleanup releases every hog job");
}

#[test]
fn the_one_vcpu_control_runs_the_same_sequence() {
    let (probe, _) = run_to_completion(ProbePlan::CONTROL);
    assert_eq!(probe.outcome(), Some(ProbeOutcome::Passed));
    assert_eq!(probe.steps_observed(), ProbePlan::CONTROL.step_budget());
}

#[test]
fn progress_is_required_after_the_first_hog_not_only_near_saturation() {
    // A27 failed with exactly one hog running, so the very first cycle must
    // already demand independent progress.
    let mut probe = SaturationProbe::new(ProbePlan::SMP).expect("valid plan");
    assert!(probe.observe_hog_submitted(0));
    assert!(probe.observe_hog_accepted(0, 12));
    assert_eq!(
        probe.next_step(),
        Some(ProbeStep::LaunchProgress { after_hog: 0 })
    );
}

#[test]
fn the_a27_shape_is_reported_as_an_accept_timeout_at_the_exact_hog() {
    let mut probe = SaturationProbe::new(ProbePlan::SMP).expect("valid plan");
    assert!(probe.observe_hog_submitted(0));
    assert!(probe.observe_hog_accepted(0, 12));
    assert!(probe.observe_progress_accepted(0, 13));
    assert!(probe.observe_progress_result(0, 13, 0));
    // Second hog submitted, no reply: exactly s4-spawn-hog-1-submit.
    assert!(probe.observe_hog_submitted(1));
    probe.observe_hog_accept_timeout(1);
    assert_eq!(
        probe.outcome(),
        Some(ProbeOutcome::Failed(ProbeFailure::HogAcceptTimeout {
            index: 1
        }))
    );
    assert_eq!(probe.admitted_hogs(), 1, "one hog was running at the stall");
    assert_eq!(probe.next_step(), None);
}

#[test]
fn a_rejection_is_never_reported_as_a_stall() {
    let mut probe = SaturationProbe::new(ProbePlan::SMP).expect("valid plan");
    assert!(probe.observe_hog_submitted(0));
    probe.observe_hog_rejected(0, 0x2A);
    assert_eq!(
        probe.outcome(),
        Some(ProbeOutcome::Failed(ProbeFailure::HogRejected {
            index: 0,
            status: 0x2A
        }))
    );
}

#[test]
fn launch_that_still_works_while_execution_does_not_is_a_distinct_failure() {
    let mut probe = SaturationProbe::new(ProbePlan::SMP).expect("valid plan");
    assert!(probe.observe_hog_submitted(0));
    assert!(probe.observe_hog_accepted(0, 12));
    assert!(probe.observe_progress_accepted(0, 13));
    probe.observe_progress_result_timeout(0);
    assert_eq!(
        probe.outcome(),
        Some(ProbeOutcome::Failed(ProbeFailure::ProgressResultTimeout {
            after_hog: 0
        }))
    );
}

#[test]
fn a_nonzero_progress_exit_stops_the_run() {
    let mut probe = SaturationProbe::new(ProbePlan::SMP).expect("valid plan");
    assert!(probe.observe_hog_submitted(0));
    assert!(probe.observe_hog_accepted(0, 12));
    assert!(probe.observe_progress_accepted(0, 13));
    assert!(!probe.observe_progress_result(0, 13, 7));
    assert_eq!(
        probe.outcome(),
        Some(ProbeOutcome::Failed(ProbeFailure::ProgressNotNormalZero {
            after_hog: 0,
            code: 7
        }))
    );
}

#[test]
fn an_uncorrelated_reply_fails_closed_instead_of_advancing() {
    let mut probe = SaturationProbe::new(ProbePlan::SMP).expect("valid plan");
    assert!(probe.observe_hog_submitted(0));
    assert!(probe.observe_hog_accepted(0, 12));
    assert!(probe.observe_progress_accepted(0, 13));
    assert!(!probe.observe_progress_result(0, 999, 0));
    assert_eq!(
        probe.outcome(),
        Some(ProbeOutcome::Failed(ProbeFailure::Uncorrelated {
            expected: 13,
            observed: 999
        }))
    );
}

#[test]
fn incomplete_cleanup_is_not_a_pass() {
    let mut probe = SaturationProbe::new(ProbePlan::CONTROL).expect("valid plan");
    let mut job = 100;
    for index in 0..ProbePlan::CONTROL.hog_count {
        assert!(probe.observe_hog_submitted(index));
        job += 1;
        assert!(probe.observe_hog_accepted(index, job));
        job += 1;
        assert!(probe.observe_progress_accepted(index, job));
        assert!(probe.observe_progress_result(index, job, 0));
    }
    assert!(probe.observe_hog_terminated(0));
    assert!(!probe.observe_hog_result(0, 101, 0x5A));
    assert_eq!(
        probe.outcome(),
        Some(ProbeOutcome::Failed(ProbeFailure::CleanupIncomplete {
            index: 0
        }))
    );
}

#[test]
fn observations_out_of_order_are_rejected_without_advancing() {
    let mut probe = SaturationProbe::new(ProbePlan::SMP).expect("valid plan");
    // Accept before submit, wrong index, and zero job id all fail closed.
    assert!(!probe.observe_hog_accepted(0, 12));
    assert!(!probe.observe_hog_submitted(3));
    assert!(probe.observe_hog_submitted(0));
    assert!(!probe.observe_hog_accepted(0, 0));
    assert!(!probe.observe_progress_accepted(0, 13));
    assert_eq!(probe.steps_observed(), 1);
    assert!(probe.outcome().is_none());
}

#[test]
fn a_terminal_outcome_is_sticky() {
    let mut probe = SaturationProbe::new(ProbePlan::SMP).expect("valid plan");
    assert!(probe.observe_hog_submitted(0));
    probe.observe_hog_accept_timeout(0);
    let first = probe.outcome();
    probe.observe_hog_rejected(0, 9);
    probe.observe_progress_result_timeout(0);
    assert_eq!(probe.outcome(), first, "the first failure is the diagnosis");
}

mod record_contract {
    use super::super::record::*;
    use super::super::*;

    extern crate std;

    fn header(bytes: &[u8; BYTES], kind: u32, sequence: u64, nonce: u64) {
        assert_eq!(&bytes[0..4], b"R1SP", "magic");
        assert_eq!(u16::from_le_bytes([bytes[4], bytes[5]]), 1, "major");
        assert_eq!(u16::from_le_bytes([bytes[6], bytes[7]]), 0, "minor");
        assert_eq!(
            u32::from_le_bytes(bytes[8..12].try_into().unwrap()),
            kind,
            "kind"
        );
        assert_eq!(
            u32::from_le_bytes(bytes[12..16].try_into().unwrap()),
            BYTES as u32,
            "byte length"
        );
        assert_eq!(
            u64::from_le_bytes(bytes[16..24].try_into().unwrap()),
            sequence,
            "sequence"
        );
        assert_eq!(
            u64::from_le_bytes(bytes[24..32].try_into().unwrap()),
            nonce,
            "build nonce"
        );
        assert_eq!(
            u32::from_le_bytes(bytes[60..64].try_into().unwrap()),
            0,
            "trailing reserved word must be zero; the kernel rejects otherwise"
        );
    }

    #[test]
    fn a_step_record_pins_every_offset_the_kernel_validates() {
        let bytes = encode_step(
            7,
            0x5A70_0001,
            ProbePlan::SMP,
            ProbeStep::AwaitHogAccepted { index: 3 },
            0x1234,
        );
        header(&bytes, KIND_STEP, 7, 0x5A70_0001);
        assert_eq!(u32::from_le_bytes(bytes[32..36].try_into().unwrap()), 4);
        assert_eq!(u32::from_le_bytes(bytes[36..40].try_into().unwrap()), 6);
        assert_eq!(
            u32::from_le_bytes(bytes[40..44].try_into().unwrap()),
            STEP_AWAIT_HOG_ACCEPTED
        );
        assert_eq!(u32::from_le_bytes(bytes[44..48].try_into().unwrap()), 3);
        assert_eq!(
            u64::from_le_bytes(bytes[48..56].try_into().unwrap()),
            0x1234
        );
    }

    #[test]
    fn a_failure_record_carries_its_ordinal_index_and_detail() {
        let bytes = encode_failure(
            2,
            0x5A70_0001,
            ProbePlan::SMP,
            ProbeFailure::HogAcceptTimeout { index: 1 },
        );
        header(&bytes, KIND_FAILED, 2, 0x5A70_0001);
        assert_eq!(
            u32::from_le_bytes(bytes[40..44].try_into().unwrap()),
            FAIL_HOG_ACCEPT_TIMEOUT
        );
        assert_eq!(u32::from_le_bytes(bytes[44..48].try_into().unwrap()), 1);
        assert_eq!(u64::from_le_bytes(bytes[48..56].try_into().unwrap()), 0);

        let uncorrelated = encode_failure(
            3,
            0x5A70_0001,
            ProbePlan::SMP,
            ProbeFailure::Uncorrelated {
                expected: 13,
                observed: 999,
            },
        );
        assert_eq!(
            u32::from_le_bytes(uncorrelated[44..48].try_into().unwrap()),
            13
        );
        assert_eq!(
            u64::from_le_bytes(uncorrelated[48..56].try_into().unwrap()),
            999
        );
    }

    #[test]
    fn the_terminal_record_states_pass_or_the_failure_ordinal() {
        let passed = encode_terminal(9, 1, ProbePlan::CONTROL, ProbeOutcome::Passed, 18);
        header(&passed, KIND_TERMINAL, 9, 1);
        assert_eq!(u32::from_le_bytes(passed[40..44].try_into().unwrap()), 18);
        assert_eq!(u32::from_le_bytes(passed[56..60].try_into().unwrap()), 0);

        let failed = encode_terminal(
            9,
            1,
            ProbePlan::CONTROL,
            ProbeOutcome::Failed(ProbeFailure::CleanupIncomplete { index: 2 }),
            5,
        );
        assert_eq!(
            u32::from_le_bytes(failed[56..60].try_into().unwrap()),
            FAIL_CLEANUP_INCOMPLETE
        );
    }

    #[test]
    fn every_step_and_failure_variant_has_a_distinct_nonzero_ordinal() {
        let steps = [
            ProbeStep::LaunchHog { index: 0 },
            ProbeStep::AwaitHogAccepted { index: 0 },
            ProbeStep::LaunchProgress { after_hog: 0 },
            ProbeStep::AwaitProgressResult { after_hog: 0 },
            ProbeStep::TerminateHog { index: 0 },
            ProbeStep::AwaitHogResult { index: 0 },
            ProbeStep::Complete,
        ];
        let mut seen = std::vec::Vec::new();
        for step in steps {
            let ordinal = step_ordinal(step);
            assert_ne!(ordinal, 0);
            assert!(!seen.contains(&ordinal), "duplicate step ordinal {ordinal}");
            seen.push(ordinal);
        }

        let failures = [
            ProbeFailure::HogAcceptTimeout { index: 0 },
            ProbeFailure::HogRejected {
                index: 0,
                status: 0,
            },
            ProbeFailure::ProgressResultTimeout { after_hog: 0 },
            ProbeFailure::ProgressRejected {
                after_hog: 0,
                status: 0,
            },
            ProbeFailure::ProgressNotNormalZero {
                after_hog: 0,
                code: 0,
            },
            ProbeFailure::CleanupIncomplete { index: 0 },
            ProbeFailure::Uncorrelated {
                expected: 0,
                observed: 0,
            },
        ];
        let mut seen = std::vec::Vec::new();
        for failure in failures {
            let (ordinal, _, _) = failure_fields(failure);
            assert_ne!(ordinal, 0);
            assert!(
                !seen.contains(&ordinal),
                "duplicate failure ordinal {ordinal}"
            );
            seen.push(ordinal);
        }
    }
}
