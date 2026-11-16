//! The memory probes of `dev-boot --check` (Deepwyrm DW2 M5 §10.5 probes
//! 12-15). They run in the first boot while the two CPU hogs preempt
//! everything, and read init's plan and the jobs group's live usage through
//! the shell's `memory` command:
//! - 12: init's plan is the rule's arithmetic on its own read of the free
//!   count, a second read agrees with it, the jobs limit it reports is the
//!   one the kernel holds on the jobs group, and a job's INIT carries the
//!   planned budget;
//! - 13 and 14: eager objects up to 256 MiB are created, mapped, touched,
//!   protected and unmapped in steps and timed; an on-demand mapping with no
//!   handle left gives back exactly the half a partial unmap removed;
//! - 15: jobs stopped while a map, a create or a commit is in its steps, and
//!   jobs ended by init's READY timeout while committing (the stall seen in
//!   step 2), leave the jobs group's usage and the free count where they
//!   were, and the shell answers throughout.
//!
//! The kernel's step report at power-off (`[steps]` on COM1) must then show
//! that a Stop or an ended parked call landed inside a map in steps. Those
//! inside a create or a commit are reported but not required, since a kill
//! lands in them only by chance (see [`steps_report`]).
//!
//! The idle-BSP probe (Deepwyrm DW2 §10.19 revision 3) runs earlier, before
//! the hogs, while the system is quiet: `hello close-spin` closes a
//! committed 512 MiB on-demand object into an empty queue and spins half a
//! second with no syscall. When its job is on an AP from start to end, the
//! kernel must send the idle BSP an owed-work wake for it; the report's
//! `owed-wakes` line must show at least that many wakes and none unsent
//! (see [`owed_wakes`]). The longest finalize gap is reported, not bounded:
//! init's 25 ms resident tick wakes the BSP even without the wake.

use std::{thread, time::Duration};

use super::{Shell, contains, spawn_job};
use crate::error::Failure;

const MIB_KIB: u64 = 1024;
/// What `hello hold-*` maps and touches, and what `hold-released` unmaps.
const HOLD_KIB: u64 = 64 * MIB_KIB;
const RELEASED_KIB: u64 = HOLD_KIB / 2;
/// A churn job is in its loop once usage passes this much above the base.
const CHURNING_KIB: u64 = 16 * MIB_KIB;
/// How far a second read of the free count may be from init's.
const FREE_DRIFT_KIB: u64 = 64 * MIB_KIB;
/// Times `slow-ready` is ended by the READY timeout.
const SLOW_READY_RUNS: usize = 3;

/// One `memory` reply, in KiB.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(super) struct Memory {
    pub(super) capped: bool,
    pub(super) fallback_none: bool,
    pub(super) budget: u64,
    pub(super) jobs_limit: u64,
    pub(super) jobs_used: u64,
    pub(super) free: u64,
    pub(super) plan_free: u64,
    pub(super) reserve: u64,
    pub(super) cap: u64,
}

pub(super) fn parse(output: &[u8]) -> Option<Memory> {
    let text = String::from_utf8_lossy(output);
    let line = text.lines().find_map(|line| {
        line.find("memory source=")
            .map(|at| &line[at + "memory ".len()..])
    })?;
    let field = |name: &str| {
        line.split_whitespace()
            .find_map(|part| part.strip_prefix(name)?.strip_prefix('='))
    };
    let number = |name: &str| field(name)?.parse::<u64>().ok();
    Some(Memory {
        capped: field("source")? == "capped",
        fallback_none: field("fallback")? == "none",
        budget: number("job-budget-kib")?,
        jobs_limit: number("jobs-limit-kib")?,
        jobs_used: number("jobs-used-kib")?,
        free: number("free-kib")?,
        plan_free: number("plan-free-kib")?,
        reserve: number("reserve-kib")?,
        cap: number("cap-kib")?,
    })
}

/// Probe 12: the plan follows init's rule (DW2 §10.3 item 7) from its own
/// free count, and a second read of the free count agrees with it.
pub(super) fn check_plan(memory: &Memory) -> Result<(), String> {
    let pages = |kib: u64| kib / 4;
    let default_reserve = (256 * MIB_KIB).max(pages(memory.plan_free) / 8 * 4);
    let half = pages(memory.jobs_limit) / 2 * 4;
    let checks = [
        (
            memory.capped && memory.fallback_none,
            "the cap binds, with no fallback",
        ),
        (memory.reserve == default_reserve, "the default reserve"),
        (
            memory.jobs_limit == memory.plan_free - memory.reserve.min(memory.plan_free),
            "jobs limit = planned free - reserve",
        ),
        (
            memory.budget == half.min(memory.cap),
            "budget = min(half the jobs limit, cap)",
        ),
        (
            memory.free.abs_diff(memory.plan_free) <= FREE_DRIFT_KIB,
            "a second read of free is near init's",
        ),
    ];
    match checks.iter().find(|(holds, _)| !holds) {
        Some((_, rule)) => Err(format!("init's memory plan breaks `{rule}`: {memory:?}")),
        None => Ok(()),
    }
}

fn read(shell: &mut Shell<'_>) -> Result<Memory, Failure> {
    let output = shell.run("memory")?;
    parse(&output).ok_or_else(|| {
        Failure::task(format!(
            "dev-boot check: `memory` printed {:?}",
            String::from_utf8_lossy(&output)
        ))
    })
}

/// Reads `memory` until `done` holds for two reads in a row with the same
/// usage, so the reading is settled rather than caught mid-change.
fn settle(
    shell: &mut Shell<'_>,
    what: &str,
    done: impl Fn(&Memory) -> bool,
) -> Result<Memory, Failure> {
    let mut previous: Option<Memory> = None;
    let mut last = None;
    for _ in 0..shell.attempts() {
        let memory = read(shell)?;
        if done(&memory) && previous.is_some_and(|before| before.jobs_used == memory.jobs_used) {
            return Ok(memory);
        }
        previous = Some(memory);
        last = Some(memory);
        thread::sleep(Duration::from_millis(500));
    }
    // Show what was running, for the failure.
    let tasks = shell.run("tasks")?;
    Err(Failure::task(format!(
        "dev-boot check: `memory` never showed {what}; last {last:?}; tasks: {:?}",
        String::from_utf8_lossy(&super::strip_escapes(&tasks))
    )))
}

/// Usage and the free count are back to `base` once a job has gone.
fn back_to(shell: &mut Shell<'_>, base: &Memory, after: &str) -> Result<(), Failure> {
    settle(
        shell,
        &format!(
            "usage and free back to {} and {} KiB after {after}",
            base.jobs_used, base.free
        ),
        |memory| memory.jobs_used == base.jobs_used && memory.free == base.free,
    )
    .map(|_| ())
}

/// `result`, or if it failed, the failure with job `job`'s result if the
/// job has already ended (so `wait` cannot block).
fn explain(
    shell: &mut Shell<'_>,
    job: u64,
    result: Result<Memory, Failure>,
) -> Result<Memory, Failure> {
    let Err(failure) = result else {
        return result;
    };
    let tasks = shell.run("tasks")?;
    if contains(&tasks, format!("task job={job} ").as_bytes()) {
        return Err(failure);
    }
    let ended = shell.run(&format!("wait {job}"))?;
    Err(Failure::task(format!(
        "{}; job {job} had ended: {:?}",
        failure.message,
        String::from_utf8_lossy(&super::strip_escapes(&ended))
    )))
}

/// Ends a spawned job and requires that it was ended from outside.
fn end(shell: &mut Shell<'_>, job: u64) -> Result<(), Failure> {
    shell.run(&format!("terminate {job}"))?;
    let output = shell.run(&format!("wait {job}"))?;
    let prefix = format!("job result job={job} classification=");
    let ended = [b"authorized".as_slice(), b"task-group-teardown"]
        .iter()
        .any(|class| contains(&output, &[prefix.as_bytes(), class].concat()));
    if ended {
        Ok(())
    } else {
        Err(Failure::task(format!(
            "dev-boot check: job {job} was not still running: {:?}",
            String::from_utf8_lossy(&output)
        )))
    }
}

/// The value after `name=` on the line containing it.
fn line_field(output: &[u8], name: &str) -> Option<u64> {
    let text = String::from_utf8_lossy(output);
    let needle = format!("{name}=");
    text.split(|c: char| c.is_whitespace())
        .find_map(|part| part.strip_prefix(&needle)?.parse().ok())
}

/// Probes 12-15, with the hogs running.
pub(super) fn probes(shell: &mut Shell<'_>) -> Result<(), Failure> {
    // Settled: a job that ended just before (on-demand-exhaust) may still be
    // owed teardown (Deepwyrm DW2 §10.10).
    let base = settle(shell, "a settled usage to start from", |_| true)?;
    check_plan(&base).map_err(|reason| Failure::task(format!("dev-boot check: {reason}")))?;

    // Probes 12-14: the budget in the INIT, and eager objects timed.
    let output = shell.run("run bin/hello eager")?;
    let budget = line_field(&output, "budget-kib");
    if budget != Some(base.budget)
        || !contains(&output, b"eager ok")
        || !contains(&output, b"classification=normal application=0 ")
    {
        return Err(Failure::task(format!(
            "dev-boot check: `run bin/hello eager` (budget {} KiB planned) printed {:?}",
            base.budget,
            String::from_utf8_lossy(&output)
        )));
    }
    for line in String::from_utf8_lossy(&output)
        .lines()
        .filter(|line| line.starts_with("eager size-mib="))
    {
        eprintln!("dev-boot: {line}");
    }
    back_to(shell, &base, "`hello eager`")?;

    // Probe 13: a partial unmap gives back exactly what it removed.
    let job = spawn_job(shell, "bin/hello hold-touched")?;
    let touched = settle(shell, "`hello hold-touched` holding 64 MiB", |memory| {
        memory.jobs_used >= base.jobs_used + HOLD_KIB
    });
    let touched = explain(shell, job, touched)?;
    end(shell, job)?;
    back_to(shell, &base, "`hello hold-touched`")?;
    let job = spawn_job(shell, "bin/hello hold-released")?;
    let released = settle(
        shell,
        "`hello hold-released` holding half of what `hold-touched` held",
        |memory| memory.jobs_used + RELEASED_KIB == touched.jobs_used,
    );
    let released = explain(shell, job, released)?;
    eprintln!(
        "dev-boot: jobs used {} KiB at rest, {} holding 64 MiB, {} after unmapping half",
        base.jobs_used, touched.jobs_used, released.jobs_used
    );
    end(shell, job)?;
    back_to(shell, &base, "`hello hold-released`")?;

    // Probe 15: stopped mid-call, nothing is left behind.
    let churn_modes =
        std::iter::repeat_n("churn-map", CHURN_MAP_RUNS).chain(["churn-create", "churn-commit"]);
    for mode in churn_modes {
        let job = spawn_job(shell, &format!("bin/hello {mode}"))?;
        // A churn's usage swings with each round, so one read past the mark
        // shows it is in its loop.
        let mut churning = None;
        for _ in 0..shell.attempts() {
            let memory = read(shell)?;
            if memory.jobs_used >= base.jobs_used + CHURNING_KIB {
                churning = Some(memory);
                break;
            }
            thread::sleep(Duration::from_millis(200));
        }
        if churning.is_none() {
            return Err(Failure::task(format!(
                "dev-boot check: `hello {mode}` never reached its loop"
            )));
        }
        end(shell, job)?;
        back_to(shell, &base, &format!("`hello {mode}`"))?;
    }
    // The step-2 stall: init's READY timeout ends a job mid-commit.
    for _ in 0..SLOW_READY_RUNS {
        shell.expect("run bin/hello slow-ready", b"status=loader-failure")?;
        back_to(shell, &base, "`hello slow-ready`")?;
    }
    Ok(())
}

/// How many separate `close-spin` jobs run, so the scheduler places each
/// afresh.
const CLOSE_SPIN_RUNS: usize = 3;

/// One `close-spin` run: the microseconds it spun and the APIC IDs it
/// spun on (0 is the BSP).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct Spin {
    pub(super) us: u64,
    pub(super) apic_before: u64,
    pub(super) apic_after: u64,
}

impl Spin {
    /// The run's line, as `hello close-spin` prints it.
    fn parse(output: &[u8]) -> Option<Self> {
        Some(Self {
            us: line_field(output, "spin-us")?,
            apic_before: line_field(output, "apic-before")?,
            apic_after: line_field(output, "apic-after")?,
        })
    }

    /// Whether the job stayed on one AP from the close to the end of its
    /// spin: then its close queued owed work off the BSP, into an empty
    /// queue, with the BSP idle, which is one owed-work wake.
    const fn on_an_ap(self) -> bool {
        self.apic_before == self.apic_after && self.apic_before != 0
    }
}

/// The idle-BSP probe, run while nothing else does: each `hello close-spin`
/// must exit normally with its line, and the system must get its memory
/// back before the next, so each close finds the queue of owed work empty.
pub(super) fn close_spin(shell: &mut Shell<'_>) -> Result<Vec<Spin>, Failure> {
    // Settled first, as for the memory probes: nothing a job left is owed.
    let base = settle(shell, "a settled usage before `hello close-spin`", |_| true)?;
    let mut spins = Vec::with_capacity(CLOSE_SPIN_RUNS);
    for _ in 0..CLOSE_SPIN_RUNS {
        let output = shell.run("run bin/hello close-spin")?;
        let spin = Spin::parse(&output)
            .filter(|_| contains(&output, b"classification=normal application=0 "));
        let Some(spin) = spin else {
            return Err(Failure::task(format!(
                "dev-boot check: `run bin/hello close-spin` printed {:?}",
                String::from_utf8_lossy(&output)
            )));
        };
        for line in String::from_utf8_lossy(&output)
            .lines()
            .filter(|line| line.starts_with("close-spin "))
        {
            eprintln!("dev-boot: {line}");
        }
        spins.push(spin);
        back_to(shell, &base, "`hello close-spin`")?;
    }
    Ok(spins)
}

/// One line for the log: each spin with the APIC IDs it ran on, and the
/// kernel's longest finalize gap (reported, not bounded).
pub(super) fn close_spin_summary(lines: &[String], spins: &[Spin]) -> String {
    let runs: Vec<String> = spins
        .iter()
        .map(|spin| {
            format!(
                "{} us on APIC {}->{}",
                spin.us, spin.apic_before, spin.apic_after
            )
        })
        .collect();
    let gap = lines
        .iter()
        .find_map(|line| line.strip_prefix("finalize-gap-longest-us="))
        .map_or("not reported".to_owned(), |gap| {
            format!("{} us", gap.trim())
        });
    format!(
        "close-spin runs: {}; longest finalize gap {gap}",
        runs.join(", ")
    )
}

/// The kernel's owed-work wakes against the probe (DW2 §10.19): the
/// `owed-wakes` line must be there and parse, none may be unsent, and there
/// must be at least one wake per run that spun on one AP from start to end.
/// A run that moved or ran on the BSP counts for nothing.
pub(super) fn owed_wakes(lines: &[String], spins: &[Spin]) -> Result<String, String> {
    let Some(line) = lines.iter().find(|line| line.starts_with("owed-wakes=")) else {
        return Err(
            "the kernel reports no owed-work wakes (no `owed-wakes` line, DW2 §10.19)".into(),
        );
    };
    let field = |name: &str| line_field(line.as_bytes(), name);
    let (Some(sent), Some(unsent), Some(_), Some(_)) = (
        field("owed-wakes"),
        field("unsent"),
        field("queue"),
        field("retirement"),
    ) else {
        return Err(format!(
            "the kernel's owed-wakes line does not parse: {line:?}"
        ));
    };
    if unsent != 0 {
        return Err(format!(
            "the kernel could not send {unsent} owed-work wakes: {line:?}"
        ));
    }
    let on_aps = spins.iter().filter(|spin| spin.on_an_ap()).count() as u64;
    if sent < on_aps {
        return Err(format!(
            "{on_aps} close-spin runs spun on an AP but the kernel sent {sent} owed-work wakes"
        ));
    }
    Ok(format!(
        "{on_aps} close-spin runs spun on an AP and the kernel sent {sent} owed-work wakes, none unsent"
    ))
}

/// The fragmented-guest probe (Deepwyrm DW2 §12.10, part 1). It runs once
/// the hogs have ended, since a shell may hold three jobs at once and it
/// needs all three:
/// - `spawn bin/hello soak <MiB>` holds one eager object, taking the
///   largest free blocks;
/// - `spawn bin/hello fragment` commits two on-demand objects alternately,
///   one page of the pins for [`HOLE_PAGES`] of the holes, to
///   [`Fragmentation::fragment_target`]; closes the holes, so their pages
///   come free as runs of one and two pages that cannot merge past a pin;
///   then, once its budget has room again, creates one eager object that
///   brings it to [`Fragmentation::fragment_final`], which takes large
///   blocks, not holes, and is the sign the harness waits for;
/// - `run bin/hello fragmented <MiB>` creates an eager top-up of that size,
///   then times the eager cycle on [`MEASURED_KIB`], which takes what is
///   left of the large blocks and then holes.
///
/// The kernel's `backing-runs` line must then show at least
/// [`MIN_BACKING_RUNS`] runs (see [`backing_runs`]).
pub(super) fn fragmented(shell: &mut Shell<'_>) -> Result<(), Failure> {
    let base = settle(shell, "a settled usage before the fragmented probe", |_| {
        true
    })?;
    let plan = Fragmentation::new(&base);
    let soak_kib = plan.soak();
    eprintln!(
        "dev-boot: fragmented probe: free {} KiB, reserve {} KiB, budget {} KiB, jobs limit {} KiB, \
         jobs used {} KiB; soak {} KiB, fragment pins {} KiB + holes {} KiB, then {} KiB",
        base.free,
        base.reserve,
        base.budget,
        base.jobs_limit,
        base.jobs_used,
        soak_kib,
        plan.pins(),
        plan.holes(),
        plan.fragment_final()
    );
    let soak = spawn_job(shell, &format!("bin/hello soak {}", soak_kib / MIB_KIB))?;
    let soaked = settle(shell, "`hello soak` holding its object", |memory| {
        memory.jobs_used >= base.jobs_used + soak_kib
    });
    let soaked = explain(shell, soak, soaked)?;
    let fragment = spawn_job(shell, "bin/hello fragment")?;
    // Above anything the fragment held before its holes were freed.
    let threshold = soaked.jobs_used + plan.fragment_final() - FRAGMENT_SLACK_KIB;
    let fragmented = settle(
        shell,
        "`hello fragment` holding its pins and its final object",
        |memory| memory.jobs_used >= threshold,
    );
    let fragmented = explain(shell, fragment, fragmented)?;
    let top_up = plan
        .top_up(&fragmented)
        .map_err(|reason| Failure::task(format!("dev-boot check: fragmented probe: {reason}")))?;
    eprintln!(
        "dev-boot: fragmented probe: free {} KiB with the holes, jobs used {} KiB; top-up {} KiB",
        fragmented.free, fragmented.jobs_used, top_up
    );
    let command = format!("run bin/hello fragmented {}", top_up / MIB_KIB);
    let output = shell.run(&command)?;
    if line_field(&output, "budget-kib") != Some(base.budget)
        || !contains(&output, b"fragmented ok")
        || !contains(&output, b"classification=normal application=0 ")
    {
        return Err(Failure::task(format!(
            "dev-boot check: `{command}` printed {:?}",
            String::from_utf8_lossy(&output)
        )));
    }
    for line in String::from_utf8_lossy(&output)
        .lines()
        .filter(|line| line.starts_with("fragmented size-mib="))
    {
        eprintln!("dev-boot: {line}");
    }
    end(shell, fragment)?;
    end(shell, soak)?;
    back_to(shell, &base, "the fragmented probe")
}

/// The measured eager object of `hello fragmented`, as `hello eager`'s
/// largest.
const MEASURED_KIB: u64 = 448 * MIB_KIB;
/// About this much of the measured object should come from holes.
const FROM_HOLES_KIB: u64 = 96 * MIB_KIB;
/// At least this much must, or the probe cannot be fragmented.
const MIN_FROM_HOLES_KIB: u64 = 16 * MIB_KIB;
/// Pages of holes committed per pinned page (`hello fragment`'s k).
const HOLE_PAGES: u64 = 3;
/// What `hello fragment` leaves unused of its budget while it commits, and
/// after its final object.
const FRAGMENT_SPARE_KIB: u64 = 32 * MIB_KIB;
const FRAGMENT_FINAL_SPARE_KIB: u64 = 16 * MIB_KIB;
/// The harness's threshold for the final object is this far below it, and
/// still above the commits' peak.
const FRAGMENT_SLACK_KIB: u64 = 8 * MIB_KIB;
/// What a job keeps unused of its budget besides its objects (its own
/// charges: page tables and the like).
const JOB_SPARE_KIB: u64 = 8 * MIB_KIB;
/// The fewest runs the measured object must land in.
const MIN_BACKING_RUNS: u64 = 1000;

/// The probe's sizes, in KiB, from the `memory` reply it starts from. Every
/// size is whole MiB except the pins and holes, which are whole groups of
/// one pin page and [`HOLE_PAGES`] hole pages, as `hello fragment` commits
/// them.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct Fragmentation {
    budget: u64,
    free: u64,
}

impl Fragmentation {
    pub(super) const fn new(memory: &Memory) -> Self {
        Self {
            budget: memory.budget,
            free: memory.free,
        }
    }

    /// What the fragment commits, pins and holes together.
    const fn fragment_target(self) -> u64 {
        self.budget.saturating_sub(FRAGMENT_SPARE_KIB)
    }

    const fn groups(self) -> u64 {
        self.fragment_target() / (4 * (1 + HOLE_PAGES))
    }

    pub(super) const fn pins(self) -> u64 {
        self.groups() * 4
    }

    pub(super) const fn holes(self) -> u64 {
        self.groups() * 4 * HOLE_PAGES
    }

    /// What the fragment holds at the end: pins and its final object.
    pub(super) const fn fragment_final(self) -> u64 {
        self.budget.saturating_sub(FRAGMENT_FINAL_SPARE_KIB)
    }

    /// The most the measuring job can top up besides the measured object.
    const fn top_up_most(self) -> u64 {
        self.budget.saturating_sub(MEASURED_KIB + JOB_SPARE_KIB) / MIB_KIB * MIB_KIB
    }

    /// The soak job's object: what leaves the free memory outside the
    /// holes, after the fragment, about [`FROM_HOLES_KIB`] short of the
    /// measured object with half the most top-up still to come, and no more
    /// than a job may hold. Whole MiB.
    pub(super) const fn soak(self) -> u64 {
        let wanted = self.free.saturating_sub(
            self.fragment_final()
                + self.holes()
                + MEASURED_KIB.saturating_sub(FROM_HOLES_KIB)
                + self.top_up_most() / 2,
        );
        let most = self.budget.saturating_sub(JOB_SPARE_KIB);
        let soak = if wanted < most { wanted } else { most };
        soak / MIB_KIB * MIB_KIB
    }

    /// The measuring job's top-up from the reading with the fragment in
    /// place: what leaves the free memory outside the holes about
    /// [`FROM_HOLES_KIB`] short of the measured object, within the job's
    /// budget and the jobs' limit. An error if even the most it may take
    /// leaves the measured object fewer than [`MIN_FROM_HOLES_KIB`] of
    /// holes, or if the holes cannot hold what it needs from them.
    pub(super) fn top_up(self, now: &Memory) -> Result<u64, String> {
        let large = now.free.saturating_sub(self.holes());
        let room = now
            .jobs_limit
            .saturating_sub(now.jobs_used + MEASURED_KIB + JOB_SPARE_KIB);
        let most = self.top_up_most().min(room / MIB_KIB * MIB_KIB);
        let wanted = large.saturating_sub(MEASURED_KIB - FROM_HOLES_KIB);
        let top_up = wanted.div_ceil(MIB_KIB).saturating_mul(MIB_KIB).min(most);
        let left = large.saturating_sub(top_up);
        if left + MIN_FROM_HOLES_KIB > MEASURED_KIB {
            return Err(format!(
                "{left} KiB outside the holes would be left for the {MEASURED_KIB} KiB object \
                 (top-up {top_up} KiB of at most {most}); it would not reach the holes"
            ));
        }
        if left + self.holes() < MEASURED_KIB {
            return Err(format!(
                "{left} KiB outside the holes and {} KiB of holes cannot hold the \
                 {MEASURED_KIB} KiB object",
                self.holes()
            ));
        }
        Ok(top_up)
    }
}

/// The kernel's `backing-runs` line (the eager backing with the most runs
/// since boot): it must be there, parse, and show at least
/// [`MIN_BACKING_RUNS`] runs, which only the fragmented probe's object
/// reaches.
pub(super) fn backing_runs(lines: &[String]) -> Result<String, String> {
    let Some(line) = lines.iter().find(|line| line.starts_with("backing-runs ")) else {
        return Err("the kernel reports no `backing-runs` line (DW2 §12.10)".into());
    };
    let (Some(runs), Some(_)) = (
        line_field(line.as_bytes(), "longest"),
        line_field(line.as_bytes(), "pages"),
    ) else {
        return Err(format!(
            "the kernel's backing-runs line does not parse: {line:?}"
        ));
    };
    if runs < MIN_BACKING_RUNS {
        return Err(format!(
            "the fragmented object landed in {runs} runs, fewer than {MIN_BACKING_RUNS}: {line:?}"
        ));
    }
    Ok(line.clone())
}

/// How many times probe 15 kills `churn-map` in one boot. The kernel counts a
/// kill only when it lands between two steps of a map or while the map call
/// is parked; a kill at a map call's first safe point, or between two map
/// calls, is counted nowhere. One kill misses the counted window now and
/// then, so several are run and the report needs only one counted.
const CHURN_MAP_RUNS: usize = 3;

/// The kernel's `[steps]` report from a COM1 log: its three lines, which
/// must show a Stop or an ended parked call inside a map in steps (plan
/// item 15). Only a kill between two steps of a map, or one that ends a
/// parked map call, is counted; a kill at a map call's first safe point or
/// between two map calls is not, which is why the probe kills `churn-map`
/// `CHURN_MAP_RUNS` times and one counted kill suffices. Creates and commits
/// are reported, not required: a kill lands in them only by chance.
pub(super) fn steps_report(log: &[u8]) -> Result<Vec<String>, String> {
    let text = String::from_utf8_lossy(log);
    let lines: Vec<String> = text
        .lines()
        .filter_map(|line| line.split_once("[steps] ").map(|(_, rest)| rest.to_owned()))
        .collect();
    let counts = |prefix: &str| {
        lines
            .iter()
            .find_map(|line| line.strip_prefix(prefix))
            .map(|rest| rest.to_owned())
    };
    let (Some(stops), Some(ended)) = (counts("stops-between-steps "), counts("parked-ended "))
    else {
        return Err(format!("the kernel logged no full step report: {lines:?}"));
    };
    let count = |call: &str| {
        line_field(stops.as_bytes(), call).unwrap_or(0)
            + line_field(ended.as_bytes(), call).unwrap_or(0)
    };
    if count("map") == 0 {
        return Err(format!("no Stop landed inside a map in steps: {lines:?}"));
    }
    Ok(lines)
}

#[cfg(test)]
mod tests {
    use super::*;

    const REPLY: &[u8] = b"\r\x1b[2Kwyrmsh> memory\r\nmemory source=capped fallback=none \
        job-budget-kib=524288 jobs-limit-kib=1572864 jobs-used-kib=1000 free-kib=1830000 \
        plan-free-kib=1835008 reserve-kib=262144 cap-kib=524288\r\n";

    #[test]
    fn a_memory_reply_is_parsed_and_its_plan_checked() {
        let memory = parse(REPLY).unwrap();
        assert_eq!(memory.budget, 524_288);
        assert_eq!(memory.jobs_used, 1000);
        assert_eq!(check_plan(&memory), Ok(()));
        // Each rule is checked.
        for broken in [
            Memory {
                capped: false,
                ..memory
            },
            Memory {
                reserve: 300_000,
                ..memory
            },
            Memory {
                jobs_limit: 1_572_868,
                ..memory
            },
            Memory {
                budget: 524_284,
                ..memory
            },
            Memory {
                free: 1_835_008 - 70_000,
                ..memory
            },
        ] {
            assert!(check_plan(&broken).is_err(), "{broken:?}");
        }
        assert_eq!(parse(b"memory source=capped"), None);
    }

    #[test]
    fn the_step_report_needs_a_map_stopped() {
        let log = b"[DW0][INFO][steps] longest-step-us=3100 call=create\n\
            [DW0][INFO][steps] stops-between-steps map=2 unmap=0 protect=0 fill=0 commit=0 create=1\n\
            [DW0][INFO][steps] parked-ended map=0 unmap=0 protect=0 fill=0 commit=1 create=0\n";
        assert_eq!(steps_report(log).unwrap().len(), 3);
        // Creates and commits are not required.
        let no_commit = String::from_utf8_lossy(log).replace("commit=1", "commit=0");
        assert!(steps_report(no_commit.as_bytes()).is_ok());
        // A map is, and an unmap does not stand for it.
        let unmap = String::from_utf8_lossy(log).replace("map=2 unmap=0", "map=0 unmap=1");
        assert!(steps_report(unmap.as_bytes()).is_err());
        assert!(steps_report(b"").is_err());
    }

    fn report(log: &str) -> Vec<String> {
        let full = format!(
            "[DW0][INFO][steps] stops-between-steps map=1 unmap=0 protect=0 fill=0 commit=0 create=0\n\
             [DW0][INFO][steps] parked-ended map=0 unmap=0 protect=0 fill=0 commit=0 create=0\n{log}"
        );
        steps_report(full.as_bytes()).unwrap()
    }

    const fn spin(apic_before: u64, apic_after: u64) -> Spin {
        Spin {
            us: 500_000,
            apic_before,
            apic_after,
        }
    }

    #[test]
    fn a_close_spin_line_is_parsed() {
        let output = b"job budget-kib=524288\r\nclose-spin spin-us=501234 apic-before=2 \
            apic-after=2 commit=quota\r\n";
        assert_eq!(
            Spin::parse(output),
            Some(Spin {
                us: 501_234,
                apic_before: 2,
                apic_after: 2
            })
        );
        assert_eq!(Spin::parse(b"close-spin spin-us=501234\r\n"), None);
    }

    #[test]
    fn each_run_on_one_ap_needs_an_owed_work_wake() {
        let wakes = |sent: u64| {
            report(&format!(
                "[DW0][INFO][steps] owed-wakes={sent} unsent=0 queue={sent} retirement=0\n"
            ))
        };
        let on_aps = [spin(2, 2), spin(3, 3), spin(1, 1)];
        assert!(owed_wakes(&wakes(3), &on_aps).is_ok());
        assert!(owed_wakes(&wakes(40), &on_aps).is_ok());
        assert_eq!(
            owed_wakes(&wakes(2), &on_aps),
            Err("3 close-spin runs spun on an AP but the kernel sent 2 owed-work wakes".into())
        );
        // A run that moved between CPUs, or ran on the BSP, counts for
        // nothing.
        let mixed = [spin(0, 1), spin(0, 0), spin(2, 2)];
        assert!(owed_wakes(&wakes(1), &mixed).is_ok());
        assert!(owed_wakes(&wakes(0), &mixed).is_err());
        // On one CPU only the line and `unsent=0` are required.
        assert!(owed_wakes(&wakes(0), &[spin(0, 0); 3]).is_ok());
    }

    #[test]
    fn an_unsent_missing_or_garbled_wake_line_fails() {
        let on_aps = [spin(2, 2)];
        let unsent = report("[DW0][INFO][steps] owed-wakes=5 unsent=1 queue=5 retirement=0\n");
        assert!(owed_wakes(&unsent, &on_aps).is_err());
        let missing = report("[DW0][INFO][steps] finalize-gap-longest-us=19390\n");
        assert_eq!(
            owed_wakes(&missing, &[spin(0, 0)]),
            Err("the kernel reports no owed-work wakes (no `owed-wakes` line, DW2 §10.19)".into())
        );
        let garbled = report("[DW0][INFO][steps] owed-wakes=5 unsent=none queue=5\n");
        assert!(owed_wakes(&garbled, &on_aps).is_err());
    }

    /// A `memory` reading in MiB.
    fn reading(free: u64, jobs_used: u64) -> Memory {
        Memory {
            capped: true,
            fallback_none: true,
            budget: 512 * MIB_KIB,
            jobs_limit: 1536 * MIB_KIB,
            jobs_used: jobs_used * MIB_KIB,
            free: free * MIB_KIB,
            plan_free: 1792 * MIB_KIB,
            reserve: 256 * MIB_KIB,
            cap: 512 * MIB_KIB,
        }
    }

    #[test]
    fn the_fragment_commits_one_pin_page_for_three_hole_pages() {
        let plan = Fragmentation::new(&reading(1700, 1));
        // 480 MiB in groups of four pages.
        assert_eq!(plan.pins(), 120 * MIB_KIB);
        assert_eq!(plan.holes(), 360 * MIB_KIB);
        assert_eq!(plan.fragment_final(), 496 * MIB_KIB);
        assert_eq!(plan.top_up_most(), 56 * MIB_KIB);
        // A budget that is not whole groups rounds the groups down.
        let odd = Fragmentation {
            budget: 512 * MIB_KIB + 12,
            free: 0,
        };
        assert_eq!(odd.pins() + odd.holes(), 480 * MIB_KIB);
    }

    #[test]
    fn the_soak_leaves_the_measured_object_short_of_large_blocks() {
        // 1100 MiB free: 1100 - 496 - 360 - 352 - 28 = -136, so nothing.
        assert_eq!(Fragmentation::new(&reading(1100, 1)).soak(), 0);
        // 1500 MiB: 264 MiB.
        assert_eq!(Fragmentation::new(&reading(1500, 1)).soak(), 264 * MIB_KIB);
        // 1787 MiB: 551 wanted, held to the budget less the spare.
        assert_eq!(Fragmentation::new(&reading(1787, 1)).soak(), 504 * MIB_KIB);
        // Whole MiB.
        let odd = Fragmentation::new(&Memory {
            free: 1500 * MIB_KIB + 100,
            ..reading(0, 1)
        });
        assert_eq!(odd.soak(), 264 * MIB_KIB);
    }

    #[test]
    fn the_top_up_aims_the_measured_object_into_the_holes() {
        let plan = Fragmentation::new(&reading(1787, 1));
        // 787 free with 360 of holes: 427 large; 352 wanted left, so 75,
        // held to 56: 371 left, 77 MiB from the holes.
        assert_eq!(plan.top_up(&reading(787, 1001)), Ok(56 * MIB_KIB));
        // 740 free: 380 large, 28 MiB tops it up to 352.
        assert_eq!(plan.top_up(&reading(740, 1001)), Ok(28 * MIB_KIB));
        // Already short of large blocks: no top-up.
        assert_eq!(plan.top_up(&reading(650, 1001)), Ok(0));
        // A fraction of a MiB is rounded up.
        assert_eq!(
            plan.top_up(&Memory {
                free: 740 * MIB_KIB + 1,
                ..reading(0, 1001)
            }),
            Ok(29 * MIB_KIB)
        );
    }

    #[test]
    fn the_top_up_keeps_to_the_jobs_limit() {
        let plan = Fragmentation::new(&reading(1787, 1));
        // 1536 - 1050 - 448 - 8 = 30 MiB of room.
        assert_eq!(plan.top_up(&reading(740, 1050)), Ok(28 * MIB_KIB));
        assert_eq!(plan.top_up(&reading(742, 1060)), Ok(20 * MIB_KIB));
    }

    #[test]
    fn a_guest_the_probe_cannot_fragment_is_refused() {
        let plan = Fragmentation::new(&reading(1787, 1));
        // 900 free: 540 large, 56 top-up leaves 484, past the object.
        assert!(plan.top_up(&reading(900, 1001)).is_err());
        // 790: 430 large less 56 leaves 374, 74 from holes: fine.
        assert!(plan.top_up(&reading(790, 1001)).is_ok());
        // 850: 490 - 56 = 434 leaves 14 MiB from holes: too few.
        assert!(plan.top_up(&reading(850, 1001)).is_err());
        // Too little memory in all for the object.
        assert!(plan.top_up(&reading(440, 1001)).is_err());
    }

    #[test]
    fn the_backing_runs_line_needs_a_fragmented_object() {
        let line = |runs: u64| {
            report(&format!(
                "[DW0][INFO][steps] backing-runs longest={runs} pages=114688\n"
            ))
        };
        assert_eq!(
            backing_runs(&line(9856)),
            Ok("backing-runs longest=9856 pages=114688".into())
        );
        assert!(backing_runs(&line(1000)).is_ok());
        assert!(backing_runs(&line(999)).is_err());
        assert!(backing_runs(&report("")).is_err());
        assert!(
            backing_runs(&report(
                "[DW0][INFO][steps] backing-runs longest=many pages=1\n"
            ))
            .is_err()
        );
    }

    #[test]
    fn the_summary_names_each_spin_and_the_gap() {
        let lines = report("[DW0][INFO][steps] finalize-gap-longest-us=5217\n");
        assert_eq!(
            close_spin_summary(&lines, &[spin(2, 2), spin(0, 1)]),
            "close-spin runs: 500000 us on APIC 2->2, 500000 us on APIC 0->1; \
             longest finalize gap 5217 us"
        );
        assert_eq!(
            close_spin_summary(&report(""), &[spin(0, 0)]),
            "close-spin runs: 500000 us on APIC 0->0; longest finalize gap not reported"
        );
    }
}
