//! Reset card R1A: the dynamic-launch saturation probe scenario.
//!
//! `DW1_WYR1_RUNTIME_RESET_IMPLEMENTATION_PLAN.md` section 8.1 asks for the
//! smallest production-path reproducer of the A27 SMP failure: an exact
//! four-vCPU guest, production process creation and JobV2 launch, no-yield CPU
//! hogs launched one at a time, an independent process required to make
//! progress after every launch, continuing to at least `online_cpu_count + 2`
//! hogs or the first failure, with an equivalent one-vCPU control. It
//! explicitly excludes registry replacement, UART recovery, shell parsing and
//! output-pressure floods.
//!
//! A27 died with **one** hog running and two CPUs provably spare, so this
//! scenario begins its progress requirement at the first hog rather than near
//! saturation; see `DW1_WYR1_RESET_R0C_INVENTORY.md` section 7.
//!
//! This module is the whole scenario as a deterministic state machine so the
//! ordering, the bounded step budget and every failure classification are host
//! testable without a guest. The native binary supplies syscalls; it does not
//! re-decide the sequence. Nothing here parses shell text, touches a registry
//! generation, or synthesises another component's reply.

#![no_std]

/// Progress is proved by launching a short-lived child and requiring its
/// terminal result, not by sampling a queue. An instantaneous sample would pass
/// while nothing actually ran, which is the mistake the plan's section 4 barrier
/// discussion calls out for the E8 quiescence gate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProbePlan {
    /// Hogs to launch, one at a time. Section 8.1 wants at least
    /// `online_cpu_count + 2`.
    pub hog_count: usize,
    /// vCPUs the profile actually brought online, recorded so a report cannot
    /// be misread as a different topology.
    pub online_cpus: usize,
}

impl ProbePlan {
    /// The canonical four-vCPU SMP plan: six hogs against four CPUs.
    pub const SMP: Self = Self {
        hog_count: 6,
        online_cpus: 4,
    };

    /// The one-vCPU control. Section 8.1 requires an equivalent control run so
    /// a failure cannot be attributed to SMP without evidence.
    pub const CONTROL: Self = Self {
        hog_count: 3,
        online_cpus: 1,
    };

    pub const fn is_valid(self) -> bool {
        self.hog_count >= 1 && self.hog_count <= MAX_HOGS && self.online_cpus >= 1
    }

    /// Total observable steps, used to bound the run and to size reports.
    pub const fn step_budget(self) -> usize {
        // Per hog: launch, accept, progress launch, progress result.
        // Then per hog: terminate, result.
        self.hog_count * 6
    }
}

/// Hard ceiling on hogs, so every buffer in the native binary is fixed size.
pub const MAX_HOGS: usize = 8;

/// One action the native binary must perform next.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProbeStep {
    /// Send a JobV2 launch for the no-yield hog at `index`.
    LaunchHog { index: usize },
    /// Require the correlated `LaunchAccepted` for that hog.
    AwaitHogAccepted { index: usize },
    /// Launch the short-lived progress child for the cycle after hog `index`.
    LaunchProgress { after_hog: usize },
    /// Require that child's terminal normal-zero result.
    AwaitProgressResult { after_hog: usize },
    /// Terminate the hog at `index`.
    TerminateHog { index: usize },
    /// Require that hog's terminal result and close its job.
    AwaitHogResult { index: usize },
    /// Every step observed; the probe passed.
    Complete,
}

/// Why a probe stopped early. These classifications are the point of the card:
/// the R1 gate requires a failing run to say more than "a spawn timed out".
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProbeFailure {
    /// The hog launch was submitted and no correlated accept arrived in time.
    /// This is the exact A27 shape.
    HogAcceptTimeout { index: usize },
    /// The hog launch was rejected outright, which is a legitimate negative
    /// answer and must never be reported as a liveness failure.
    HogRejected { index: usize, status: u32 },
    /// The progress child's launch was accepted but it never reached a terminal
    /// result: dynamic launch still works while execution does not.
    ProgressResultTimeout { after_hog: usize },
    /// The progress child was refused admission while hogs hold the CPUs.
    ProgressRejected { after_hog: usize, status: u32 },
    /// The progress child ran but did not exit normal-zero.
    ProgressNotNormalZero { after_hog: usize, code: u32 },
    /// Cleanup did not complete, so the run cannot be treated as bounded.
    CleanupIncomplete { index: usize },
    /// A reply arrived for a job the scenario was not waiting on.
    Uncorrelated { expected: u64, observed: u64 },
}

/// Terminal state of a probe run.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProbeOutcome {
    Passed,
    Failed(ProbeFailure),
}

/// The scenario. Advances only on an observation, so a native binary cannot
/// skip a required proof by construction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SaturationProbe {
    plan: ProbePlan,
    /// Hog currently being launched or proved.
    cursor: usize,
    phase: Phase,
    hog_jobs: [Option<u64>; MAX_HOGS],
    progress_job: Option<u64>,
    steps_observed: usize,
    outcome: Option<ProbeOutcome>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Phase {
    LaunchHog,
    AwaitHog,
    LaunchProgress,
    AwaitProgress,
    TerminateHog,
    AwaitHogResult,
    Done,
}

impl SaturationProbe {
    /// Returns `None` for an invalid plan rather than clamping it: a probe that
    /// silently ran a different topology than its report claims is worthless.
    pub const fn new(plan: ProbePlan) -> Option<Self> {
        if !plan.is_valid() {
            return None;
        }
        Some(Self {
            plan,
            cursor: 0,
            phase: Phase::LaunchHog,
            hog_jobs: [None; MAX_HOGS],
            progress_job: None,
            steps_observed: 0,
            outcome: None,
        })
    }

    pub const fn plan(&self) -> ProbePlan {
        self.plan
    }

    pub const fn steps_observed(&self) -> usize {
        self.steps_observed
    }

    pub const fn outcome(&self) -> Option<ProbeOutcome> {
        self.outcome
    }

    /// Hogs whose launch was accepted, in launch order. A stalled run reports
    /// this so the failure is attributable to an exact load level.
    pub fn admitted_hogs(&self) -> usize {
        self.hog_jobs.iter().filter(|slot| slot.is_some()).count()
    }

    /// The next action, or `None` once the run has a terminal outcome.
    pub const fn next_step(&self) -> Option<ProbeStep> {
        if self.outcome.is_some() {
            return None;
        }
        Some(match self.phase {
            Phase::LaunchHog => ProbeStep::LaunchHog { index: self.cursor },
            Phase::AwaitHog => ProbeStep::AwaitHogAccepted { index: self.cursor },
            Phase::LaunchProgress => ProbeStep::LaunchProgress {
                after_hog: self.cursor,
            },
            Phase::AwaitProgress => ProbeStep::AwaitProgressResult {
                after_hog: self.cursor,
            },
            Phase::TerminateHog => ProbeStep::TerminateHog { index: self.cursor },
            Phase::AwaitHogResult => ProbeStep::AwaitHogResult { index: self.cursor },
            Phase::Done => ProbeStep::Complete,
        })
    }

    fn fail(&mut self, failure: ProbeFailure) {
        if self.outcome.is_none() {
            self.outcome = Some(ProbeOutcome::Failed(failure));
            self.phase = Phase::Done;
        }
    }

    fn advance(&mut self, phase: Phase) {
        self.steps_observed += 1;
        self.phase = phase;
    }

    /// Records that hog `index`'s launch was submitted.
    pub fn observe_hog_submitted(&mut self, index: usize) -> bool {
        if self.phase != Phase::LaunchHog || index != self.cursor {
            return false;
        }
        self.advance(Phase::AwaitHog);
        true
    }

    /// Records the correlated accept for the current hog.
    pub fn observe_hog_accepted(&mut self, index: usize, job_id: u64) -> bool {
        if self.phase != Phase::AwaitHog || index != self.cursor || job_id == 0 {
            return false;
        }
        self.hog_jobs[index] = Some(job_id);
        self.advance(Phase::LaunchProgress);
        true
    }

    /// Records that the hog launch timed out with no reply: the A27 shape.
    pub fn observe_hog_accept_timeout(&mut self, index: usize) {
        self.fail(ProbeFailure::HogAcceptTimeout { index });
    }

    /// Records a legitimate negative reply, kept distinct from a stall.
    pub fn observe_hog_rejected(&mut self, index: usize, status: u32) {
        self.fail(ProbeFailure::HogRejected { index, status });
    }

    /// Records that the progress child's launch was accepted.
    pub fn observe_progress_accepted(&mut self, after_hog: usize, job_id: u64) -> bool {
        if self.phase != Phase::LaunchProgress || after_hog != self.cursor || job_id == 0 {
            return false;
        }
        self.progress_job = Some(job_id);
        self.advance(Phase::AwaitProgress);
        true
    }

    pub fn observe_progress_rejected(&mut self, after_hog: usize, status: u32) {
        self.fail(ProbeFailure::ProgressRejected { after_hog, status });
    }

    /// Records the progress child's terminal result. `code` must be zero for a
    /// normal exit; anything else stops the run.
    pub fn observe_progress_result(&mut self, after_hog: usize, job_id: u64, code: u32) -> bool {
        if self.phase != Phase::AwaitProgress || after_hog != self.cursor {
            return false;
        }
        let expected = self.progress_job.unwrap_or_default();
        if job_id != expected {
            self.fail(ProbeFailure::Uncorrelated {
                expected,
                observed: job_id,
            });
            return false;
        }
        if code != 0 {
            self.fail(ProbeFailure::ProgressNotNormalZero { after_hog, code });
            return false;
        }
        self.progress_job = None;
        self.steps_observed += 1;
        // Every hog launched and proved; move to bounded cleanup.
        if self.cursor + 1 >= self.plan.hog_count {
            self.cursor = 0;
            self.phase = Phase::TerminateHog;
        } else {
            self.cursor += 1;
            self.phase = Phase::LaunchHog;
        }
        true
    }

    pub fn observe_progress_result_timeout(&mut self, after_hog: usize) {
        self.fail(ProbeFailure::ProgressResultTimeout { after_hog });
    }

    pub fn observe_hog_terminated(&mut self, index: usize) -> bool {
        if self.phase != Phase::TerminateHog || index != self.cursor {
            return false;
        }
        self.advance(Phase::AwaitHogResult);
        true
    }

    /// Records a terminated hog's terminal result and its cleanup status.
    pub fn observe_hog_result(&mut self, index: usize, job_id: u64, cleanup_result: u32) -> bool {
        if self.phase != Phase::AwaitHogResult || index != self.cursor {
            return false;
        }
        let expected = self.hog_jobs[index].unwrap_or_default();
        if job_id != expected {
            self.fail(ProbeFailure::Uncorrelated {
                expected,
                observed: job_id,
            });
            return false;
        }
        if cleanup_result != 0 {
            self.fail(ProbeFailure::CleanupIncomplete { index });
            return false;
        }
        self.hog_jobs[index] = None;
        self.steps_observed += 1;
        if self.cursor + 1 >= self.plan.hog_count {
            self.phase = Phase::Done;
            self.outcome = Some(ProbeOutcome::Passed);
        } else {
            self.cursor += 1;
            self.phase = Phase::TerminateHog;
        }
        true
    }
}

#[cfg(test)]
mod tests;

/// `R1SP` record encoding. The kernel collector validates only bounded
/// transport, the build nonce, a consecutive sequence and reporter custody; the
/// step meanings below stay this crate's and the host decoder's concern.
pub mod record {
    use super::{ProbeFailure, ProbeOutcome, ProbeStep};

    pub const BYTES: usize = 64;
    const MAGIC: [u8; 4] = *b"R1SP";
    const MAJOR: u16 = 1;
    const MINOR: u16 = 0;

    pub const KIND_STEP: u32 = 1;
    pub const KIND_FAILED: u32 = 2;
    pub const KIND_TERMINAL: u32 = 255;

    /// Step ordinals. Stable: the host decoder and the kernel's retained bytes
    /// both read them.
    pub const STEP_LAUNCH_HOG: u32 = 1;
    pub const STEP_AWAIT_HOG_ACCEPTED: u32 = 2;
    pub const STEP_LAUNCH_PROGRESS: u32 = 3;
    pub const STEP_AWAIT_PROGRESS_RESULT: u32 = 4;
    pub const STEP_TERMINATE_HOG: u32 = 5;
    pub const STEP_AWAIT_HOG_RESULT: u32 = 6;
    pub const STEP_COMPLETE: u32 = 7;

    /// Failure ordinals, one per [`ProbeFailure`] variant.
    pub const FAIL_HOG_ACCEPT_TIMEOUT: u32 = 1;
    pub const FAIL_HOG_REJECTED: u32 = 2;
    pub const FAIL_PROGRESS_RESULT_TIMEOUT: u32 = 3;
    pub const FAIL_PROGRESS_REJECTED: u32 = 4;
    pub const FAIL_PROGRESS_NOT_NORMAL_ZERO: u32 = 5;
    pub const FAIL_CLEANUP_INCOMPLETE: u32 = 6;
    pub const FAIL_UNCORRELATED: u32 = 7;

    pub const fn step_ordinal(step: ProbeStep) -> u32 {
        match step {
            ProbeStep::LaunchHog { .. } => STEP_LAUNCH_HOG,
            ProbeStep::AwaitHogAccepted { .. } => STEP_AWAIT_HOG_ACCEPTED,
            ProbeStep::LaunchProgress { .. } => STEP_LAUNCH_PROGRESS,
            ProbeStep::AwaitProgressResult { .. } => STEP_AWAIT_PROGRESS_RESULT,
            ProbeStep::TerminateHog { .. } => STEP_TERMINATE_HOG,
            ProbeStep::AwaitHogResult { .. } => STEP_AWAIT_HOG_RESULT,
            ProbeStep::Complete => STEP_COMPLETE,
        }
    }

    pub const fn step_index(step: ProbeStep) -> u32 {
        match step {
            ProbeStep::LaunchHog { index }
            | ProbeStep::AwaitHogAccepted { index }
            | ProbeStep::TerminateHog { index }
            | ProbeStep::AwaitHogResult { index } => index as u32,
            ProbeStep::LaunchProgress { after_hog }
            | ProbeStep::AwaitProgressResult { after_hog } => after_hog as u32,
            ProbeStep::Complete => 0,
        }
    }

    /// Returns the failure ordinal and its two detail words.
    pub const fn failure_fields(failure: ProbeFailure) -> (u32, u32, u64) {
        match failure {
            ProbeFailure::HogAcceptTimeout { index } => (FAIL_HOG_ACCEPT_TIMEOUT, index as u32, 0),
            ProbeFailure::HogRejected { index, status } => {
                (FAIL_HOG_REJECTED, index as u32, status as u64)
            }
            ProbeFailure::ProgressResultTimeout { after_hog } => {
                (FAIL_PROGRESS_RESULT_TIMEOUT, after_hog as u32, 0)
            }
            ProbeFailure::ProgressRejected { after_hog, status } => {
                (FAIL_PROGRESS_REJECTED, after_hog as u32, status as u64)
            }
            ProbeFailure::ProgressNotNormalZero { after_hog, code } => {
                (FAIL_PROGRESS_NOT_NORMAL_ZERO, after_hog as u32, code as u64)
            }
            ProbeFailure::CleanupIncomplete { index } => (FAIL_CLEANUP_INCOMPLETE, index as u32, 0),
            ProbeFailure::Uncorrelated { expected, observed } => {
                (FAIL_UNCORRELATED, expected as u32, observed)
            }
        }
    }

    struct Writer {
        bytes: [u8; BYTES],
    }

    impl Writer {
        fn new(kind: u32, sequence: u64, nonce: u64) -> Self {
            let mut bytes = [0_u8; BYTES];
            bytes[0..4].copy_from_slice(&MAGIC);
            bytes[4..6].copy_from_slice(&MAJOR.to_le_bytes());
            bytes[6..8].copy_from_slice(&MINOR.to_le_bytes());
            bytes[8..12].copy_from_slice(&kind.to_le_bytes());
            bytes[12..16].copy_from_slice(&(BYTES as u32).to_le_bytes());
            bytes[16..24].copy_from_slice(&sequence.to_le_bytes());
            bytes[24..32].copy_from_slice(&nonce.to_le_bytes());
            Self { bytes }
        }

        fn u32_at(&mut self, offset: usize, value: u32) {
            self.bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
        }

        fn u64_at(&mut self, offset: usize, value: u64) {
            self.bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
        }
    }

    /// Encodes one observed step. Offsets 32/36 carry the topology so a report
    /// can never be misread as a different profile.
    pub fn encode_step(
        sequence: u64,
        nonce: u64,
        plan: super::ProbePlan,
        step: ProbeStep,
        job_id: u64,
    ) -> [u8; BYTES] {
        let mut writer = Writer::new(KIND_STEP, sequence, nonce);
        writer.u32_at(32, plan.online_cpus as u32);
        writer.u32_at(36, plan.hog_count as u32);
        writer.u32_at(40, step_ordinal(step));
        writer.u32_at(44, step_index(step));
        writer.u64_at(48, job_id);
        writer.bytes
    }

    /// Encodes the first failure classification.
    pub fn encode_failure(
        sequence: u64,
        nonce: u64,
        plan: super::ProbePlan,
        failure: ProbeFailure,
    ) -> [u8; BYTES] {
        let (ordinal, index, detail) = failure_fields(failure);
        let mut writer = Writer::new(KIND_FAILED, sequence, nonce);
        writer.u32_at(32, plan.online_cpus as u32);
        writer.u32_at(36, plan.hog_count as u32);
        writer.u32_at(40, ordinal);
        writer.u32_at(44, index);
        writer.u64_at(48, detail);
        writer.bytes
    }

    /// Encodes the single terminal record. Offset 56 carries zero for a pass and
    /// the failure ordinal otherwise, so a truncated capture still says which.
    pub fn encode_terminal(
        sequence: u64,
        nonce: u64,
        plan: super::ProbePlan,
        outcome: ProbeOutcome,
        steps_observed: usize,
    ) -> [u8; BYTES] {
        let mut writer = Writer::new(KIND_TERMINAL, sequence, nonce);
        writer.u32_at(32, plan.online_cpus as u32);
        writer.u32_at(36, plan.hog_count as u32);
        writer.u32_at(40, steps_observed as u32);
        writer.u32_at(
            56,
            match outcome {
                ProbeOutcome::Passed => 0,
                ProbeOutcome::Failed(failure) => failure_fields(failure).0,
            },
        );
        writer.bytes
    }
}
