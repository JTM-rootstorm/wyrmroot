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
