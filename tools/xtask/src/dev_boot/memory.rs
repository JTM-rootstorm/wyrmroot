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
//!
//! The report must also show the fragmented probe's object in many runs
//! (DW2 §12.10, see [`backing_runs`]), the longest first hold of an eager
//! backing's allocation within [`MAX_FIRST_HOLD_RUNS`] runs (DW2 §12.11, see
//! [`backing_alloc`]), and exactly one finalize step in any one hold of the
//! runtime lock (DW2 §12.11, see [`finalize_hold`]).

use std::{thread, time::Duration};

use super::shell::{Shell, contains, spawn_job};
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

pub(super) fn read(shell: &mut Shell<'_>) -> Result<Memory, Failure> {
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
pub(super) fn settle(
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
pub(super) fn back_to(shell: &mut Shell<'_>, base: &Memory, after: &str) -> Result<(), Failure> {
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
/// job has already ended (so `wait` cannot block), and what a `hello` probe
/// said by it (see [`hello_failure`]).
pub(super) fn explain<T>(
    shell: &mut Shell<'_>,
    job: u64,
    result: Result<T, Failure>,
) -> Result<T, Failure> {
    let Err(failure) = result else {
        return result;
    };
    let tasks = shell.run("tasks")?;
    if contains(&tasks, format!("task job={job} ").as_bytes()) {
        return Err(failure);
    }
    let ended = shell.run(&format!("wait {job}"))?;
    Err(Failure::task(format!(
        "{}; job {job} had ended: {:?}{}",
        failure.message,
        String::from_utf8_lossy(&super::strip_escapes(&ended)),
        said(&ended)
    )))
}

/// Ends a spawned job and requires that it was ended from outside.
pub(super) fn end(shell: &mut Shell<'_>, job: u64) -> Result<(), Failure> {
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
            "dev-boot check: job {job} was not still running: {:?}{}",
            String::from_utf8_lossy(&output),
            said(&output)
        )))
    }
}

/// The top byte of a `hello` memory probe's failure status (`hello`'s
/// `PROBE_FAILURE_PREFIX`, Deepwyrm DW2 M8 §13.4 item 2): the status is
/// `0x4D00_0000 | (round << 16) | (site << 8) | code`, `code` being the low
/// byte of the negated kernel status of the call that failed, or 0 for
/// none, and `round` how far a churn probe got, saturating at 255 (0 for
/// every other site).
const PROBE_FAILURE_PREFIX: u64 = 0x4D00_0000;

/// What a `hello` memory probe's status says, from the first `job result`
/// line in `output` (as `wyrmsh` prints it, `application=` in decimal):
/// `hello failed at site S with kernel status -C`, or `... with no kernel
/// status`, then ` after N rounds` for a nonzero round (` after 255 or more
/// rounds` at the saturated 255). `None` without such a line or when the status is not a probe
/// failure.
pub(super) fn hello_failure(output: &[u8]) -> Option<String> {
    let text = String::from_utf8_lossy(output);
    let line = text.lines().find(|line| line.contains("job result job="))?;
    let status = line_field(line.as_bytes(), "application")?;
    if status >> 24 != PROBE_FAILURE_PREFIX >> 24 {
        return None;
    }
    let (site, code, round) = ((status >> 8) & 0xff, status & 0xff, (status >> 16) & 0xff);
    let failed = if code == 0 {
        format!("hello failed at site {site} with no kernel status")
    } else {
        format!("hello failed at site {site} with kernel status -{code}")
    };
    Some(match round {
        0 => failed,
        255 => format!("{failed} after 255 or more rounds"),
        _ => format!("{failed} after {round} rounds"),
    })
}

/// [`hello_failure`] as a suffix for a failure message: `; <text>`, or
/// nothing.
pub(super) fn said(output: &[u8]) -> String {
    hello_failure(output).map_or_else(String::new, |text| format!("; {text}"))
}

/// The value after `name=` on the line containing it.
pub(super) fn line_field(output: &[u8], name: &str) -> Option<u64> {
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
            "dev-boot check: `run bin/hello eager` (budget {} KiB planned) printed {:?}{}",
            base.budget,
            String::from_utf8_lossy(&output),
            said(&output)
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
            // With the job's result if it has already ended, and what it
            // said by it.
            return explain(
                shell,
                job,
                Err(Failure::task(format!(
                    "dev-boot check: `hello {mode}` never reached its loop"
                ))),
            );
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
                "dev-boot check: `run bin/hello close-spin` printed {:?}{}",
                String::from_utf8_lossy(&output),
                said(&output)
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
/// needs all three. Each job's budget is capped well below free memory, so
/// two jobs fragment, one after the other:
/// - first, the baseline: `run bin/hello unfragmented` times the same
///   cycle as `hello fragmented` below, on the same size, before anything
///   is fragmented;
/// - `spawn bin/hello fragment 0` commits two on-demand objects without
///   mapping them, alternately one page of pins for [`HOLE_PAGES`] pages of
///   holes, to [`Fragmentation::commit_target`]; closes the holes, whose
///   pages then come free as runs of one and two pages that cannot merge
///   past a pin; and once its budget has room again creates an eager object
///   that brings it to [`Fragmentation::fragment_final`], above anything it
///   held while committing, which is the sign the harness waits for. Being
///   eager, that object takes large blocks, not holes.
/// - `spawn bin/hello fragment <MiB>` does the same after first committing
///   a filler of that many MiB, which takes the first job's holes (single
///   pages come from the smallest free blocks), so its own pins and holes
///   land in large blocks; it closes the filler with its holes, which gives
///   the first job's holes back as they were.
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
    // The baseline: the same cycle on the same size, before anything is
    // fragmented and with the hogs ended.
    let output = shell.run("run bin/hello unfragmented")?;
    measured(&output, "run bin/hello unfragmented", "unfragmented", &base)?;
    back_to(shell, &base, "`hello unfragmented`")?;
    let plan = Fragmentation::new(&base);
    eprintln!(
        "dev-boot: fragmented probe: free {} KiB, reserve {} KiB, budget {} KiB, jobs limit {} KiB, \
         jobs used {} KiB; first pins {} + holes {} KiB, filler {} KiB, second pins {} + holes {} KiB, \
         each then {} KiB",
        base.free,
        base.reserve,
        base.budget,
        base.jobs_limit,
        base.jobs_used,
        plan.first().0,
        plan.first().1,
        plan.filler(),
        plan.second().0,
        plan.second().1,
        plan.fragment_final()
    );
    let mut before = base;
    let mut jobs = [0; 2];
    for (index, filler) in [0, plan.filler()].into_iter().enumerate() {
        let job = spawn_job(shell, &format!("bin/hello fragment {}", filler / MIB_KIB))?;
        jobs[index] = job;
        // Above anything the job held before its holes were freed.
        let threshold = before.jobs_used + plan.fragment_final() - FRAGMENT_SLACK_KIB;
        let held = settle(
            shell,
            "`hello fragment` holding its pins and its final object",
            |memory| memory.jobs_used >= threshold,
        );
        before = explain(shell, job, held)?;
    }
    let top_up = plan
        .top_up(&before)
        .map_err(|reason| Failure::task(format!("dev-boot check: fragmented probe: {reason}")))?;
    eprintln!(
        "dev-boot: fragmented probe: free {} KiB with {} KiB of holes, jobs used {} KiB; \
         top-up {} KiB",
        before.free,
        plan.holes(),
        before.jobs_used,
        top_up
    );
    let command = format!("run bin/hello fragmented {}", top_up / MIB_KIB);
    let output = shell.run(&command)?;
    measured(&output, &command, "fragmented", &base)?;
    for job in jobs {
        end(shell, job)?;
    }
    back_to(shell, &base, "the fragmented probe")
}

/// `hello unfragmented`'s or `hello fragmented`'s output (`name`): the
/// planned budget, `<name> ok` and a normal exit; echoes its timed line.
fn measured(output: &[u8], command: &str, name: &str, base: &Memory) -> Result<(), Failure> {
    if line_field(output, "budget-kib") != Some(base.budget)
        || !contains(output, format!("{name} ok").as_bytes())
        || !contains(output, b"classification=normal application=0 ")
    {
        return Err(Failure::task(format!(
            "dev-boot check: `{command}` printed {:?}{}",
            String::from_utf8_lossy(output),
            said(output)
        )));
    }
    let prefix = format!("{name} size-mib=");
    for line in String::from_utf8_lossy(output)
        .lines()
        .filter(|line| line.starts_with(&prefix))
    {
        eprintln!("dev-boot: {line}");
    }
    Ok(())
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
/// One pinned page and its holes.
const GROUP_KIB: u64 = 4 * (1 + HOLE_PAGES);
/// What `hello fragment` leaves unused of its budget while it commits, and
/// after its final object (`COMMIT_SPARE` and `FINAL_SPARE` there).
const COMMIT_SPARE_KIB: u64 = 4 * MIB_KIB;
const FINAL_SPARE_KIB: u64 = MIB_KIB;
/// The harness's threshold for the final object is this far below it, and
/// still above the commits' peak with the job's own charges.
const FRAGMENT_SLACK_KIB: u64 = MIB_KIB;
/// The filler covers the first job's holes and this much more, for small
/// blocks that were free before.
const FILLER_SLACK_KIB: u64 = MIB_KIB;
/// What the measuring job keeps unused of its budget besides its objects,
/// for its own charges (the measured object's page tables and the like).
const MEASURE_SPARE_KIB: u64 = 4 * MIB_KIB;
/// The fewest runs the measured object must land in.
const MIN_BACKING_RUNS: u64 = 1000;

/// The probe's sizes, in KiB, from the job budget. Pins and holes are whole
/// groups of one pin page and [`HOLE_PAGES`] hole pages, as `hello
/// fragment` commits them; the filler and the top-up are whole MiB.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct Fragmentation {
    budget: u64,
}

impl Fragmentation {
    pub(super) const fn new(memory: &Memory) -> Self {
        Self {
            budget: memory.budget,
        }
    }

    /// What each fragmenting job commits: filler, pins and holes together.
    const fn commit_target(self) -> u64 {
        self.budget.saturating_sub(COMMIT_SPARE_KIB)
    }

    /// Pins and holes of `groups` groups.
    const fn groups(groups: u64) -> (u64, u64) {
        (groups * 4, groups * 4 * HOLE_PAGES)
    }

    /// The first job's pins and holes.
    pub(super) const fn first(self) -> (u64, u64) {
        Self::groups(self.commit_target() / GROUP_KIB)
    }

    /// The second job's filler: the first job's holes and a little more,
    /// whole MiB.
    pub(super) const fn filler(self) -> u64 {
        (self.first().1 + FILLER_SLACK_KIB).div_ceil(MIB_KIB) * MIB_KIB
    }

    /// The second job's pins and holes, after its filler.
    pub(super) const fn second(self) -> (u64, u64) {
        Self::groups(self.commit_target().saturating_sub(self.filler()) / GROUP_KIB)
    }

    pub(super) const fn holes(self) -> u64 {
        self.first().1 + self.second().1
    }

    /// What each fragmenting job holds at the end: pins and its final
    /// object.
    pub(super) const fn fragment_final(self) -> u64 {
        self.budget.saturating_sub(FINAL_SPARE_KIB)
    }

    /// The most the measuring job can top up besides the measured object.
    const fn top_up_most(self) -> u64 {
        self.budget.saturating_sub(MEASURED_KIB + MEASURE_SPARE_KIB) / MIB_KIB * MIB_KIB
    }

    /// The measuring job's top-up from the reading with both fragmenting
    /// jobs in place: what leaves the free memory outside the holes about
    /// [`FROM_HOLES_KIB`] short of the measured object, within the job's
    /// budget and the jobs' limit. An error if even the most it may take
    /// leaves the measured object fewer than [`MIN_FROM_HOLES_KIB`] of
    /// holes, or if the holes cannot hold what it needs from them.
    pub(super) fn top_up(self, now: &Memory) -> Result<u64, String> {
        let large = now.free.saturating_sub(self.holes());
        let room = now
            .jobs_limit
            .saturating_sub(now.jobs_used + MEASURED_KIB + MEASURE_SPARE_KIB);
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

/// The most runs the first hold of an eager backing's allocation may take
/// (Deepwyrm DW2 plan §12.11 part 2 item 2).
const MAX_FIRST_HOLD_RUNS: u64 = 16;

/// The kernel's `backing-alloc-longest-us` line (the longest first hold of
/// an eager backing's allocation a create made, with the runs that hold took
/// and the pages wanted): it must be there, parse, and show at most
/// [`MAX_FIRST_HOLD_RUNS`] runs (DW2 §12.11 part 2 item 2).
pub(super) fn backing_alloc(lines: &[String]) -> Result<String, String> {
    let Some(line) = lines
        .iter()
        .find(|line| line.starts_with("backing-alloc-longest-us="))
    else {
        return Err("the kernel reports no `backing-alloc-longest-us` line (DW2 §12.11)".into());
    };
    let (Some(_), Some(runs), Some(_)) = (
        line_field(line.as_bytes(), "backing-alloc-longest-us"),
        line_field(line.as_bytes(), "runs"),
        line_field(line.as_bytes(), "pages"),
    ) else {
        return Err(format!(
            "the kernel's backing-alloc-longest-us line does not parse: {line:?}"
        ));
    };
    if runs > MAX_FIRST_HOLD_RUNS {
        return Err(format!(
            "the first allocation hold took {runs} runs, more than {MAX_FIRST_HOLD_RUNS}: {line:?}"
        ));
    }
    Ok(line.clone())
}

/// The kernel's `finalize-steps-in-one-hold` line (the most finalize steps
/// any one hold of the runtime lock ran since boot): it must be there,
/// parse, and show exactly one (DW2 §12.11 part 2 item 11). Zero fails too:
/// the check's probes close objects whose freeing is stepped, so a boot that
/// ran no finalize step did not exercise the rule.
pub(super) fn finalize_hold(lines: &[String]) -> Result<String, String> {
    let Some(line) = lines
        .iter()
        .find(|line| line.starts_with("finalize-steps-in-one-hold "))
    else {
        return Err("the kernel reports no `finalize-steps-in-one-hold` line (DW2 §12.11)".into());
    };
    let Some(longest) = line_field(line.as_bytes(), "longest") else {
        return Err(format!(
            "the kernel's finalize-steps-in-one-hold line does not parse: {line:?}"
        ));
    };
    match longest {
        1 => Ok(line.clone()),
        0 => Err(format!(
            "no hold of the runtime lock ran a finalize step, so the probes' stepped frees \
             did not exercise the one-step rule: {line:?}"
        )),
        _ => Err(format!(
            "one hold of the runtime lock ran {longest} finalize steps, more than 1: {line:?}"
        )),
    }
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

/// The kernel's `records-dropped=<n>` line, the last of its step report
/// (Deepwyrm DW2 M8 §13.4 item 4): it must be there and `n` must be 0, or
/// a kernel record was lost to a contended writer. Read from the raw COM1
/// log, not through [`steps_report`], so it applies to a boot that ran no
/// probe. Returns the line.
pub(super) fn records_dropped(log: &[u8]) -> Result<String, String> {
    let text = String::from_utf8_lossy(log);
    let Some(line) = text
        .lines()
        .filter_map(|line| line.split_once("[steps] ").map(|(_, rest)| rest.trim_end()))
        .find(|line| line.starts_with("records-dropped="))
    else {
        return Err(
            "the kernel's step report has no `records-dropped` line (DW2 M8 §13.4 item 4)".into(),
        );
    };
    match line_field(line.as_bytes(), "records-dropped") {
        Some(0) => Ok(line.to_owned()),
        Some(dropped) => Err(format!(
            "the kernel dropped {dropped} records under contention: {line:?}"
        )),
        None => Err(format!(
            "the kernel's records-dropped line does not parse: {line:?}"
        )),
    }
}

/// The kernel's `usage-check groups=<g> mismatches=<m>` line in its step
/// report (Deepwyrm DW2 M8 §13.12 part a): at power-off the kernel compares
/// every live TaskGroup's kept usage counters with a scan. It must be there,
/// `m` must be 0, and `g` must not be 0, since a check that compared nothing
/// proves nothing. Read from the raw COM1 log, like [`records_dropped`].
/// Returns the line.
pub(super) fn usage_check(log: &[u8]) -> Result<String, String> {
    let text = String::from_utf8_lossy(log);
    let Some(line) = text
        .lines()
        .filter_map(|line| line.split_once("[steps] ").map(|(_, rest)| rest.trim_end()))
        .find(|line| line.starts_with("usage-check "))
    else {
        return Err(
            "the kernel's step report has no `usage-check` line (DW2 M8 §13.12 part a)".into(),
        );
    };
    match (
        line_field(line.as_bytes(), "groups"),
        line_field(line.as_bytes(), "mismatches"),
    ) {
        (Some(0), Some(_)) => Err(format!(
            "the kernel's usage check compared no TaskGroup (DW2 M8 §13.12 part a): {line:?}"
        )),
        (Some(_), Some(0)) => Ok(line.to_owned()),
        (Some(_), Some(mismatches)) => Err(format!(
            "the kernel's usage check found {mismatches} TaskGroups whose kept usage differs \
             from a scan (DW2 M8 §13.12 part a): {line:?}"
        )),
        _ => Err(format!(
            "the kernel's usage-check line does not parse (DW2 M8 §13.12 part a): {line:?}"
        )),
    }
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
    fn two_jobs_fragment_and_the_second_fills_the_first_ones_holes() {
        let plan = Fragmentation::new(&reading(1927, 0));
        // 508 MiB in groups of four pages: a quarter pins.
        assert_eq!(plan.first(), (127 * MIB_KIB, 381 * MIB_KIB));
        // The first job's holes and a MiB, whole MiB.
        assert_eq!(plan.filler(), 382 * MIB_KIB);
        // The rest of the 508 MiB.
        assert_eq!(plan.second(), (32_256, 96_768));
        assert_eq!(plan.holes(), 381 * MIB_KIB + 96_768);
        // Each ends above its commits' peak, and the harness's threshold is
        // between them.
        assert_eq!(plan.fragment_final(), 511 * MIB_KIB);
        assert!(plan.fragment_final() - FRAGMENT_SLACK_KIB > plan.commit_target());
        assert_eq!(plan.top_up_most(), 60 * MIB_KIB);
        // A budget that is not whole groups rounds the groups down.
        let odd = Fragmentation {
            budget: 512 * MIB_KIB + 12,
        };
        assert_eq!(odd.first().0 + odd.first().1, 508 * MIB_KIB);
    }

    #[test]
    fn the_top_up_aims_the_measured_object_into_the_holes() {
        let plan = Fragmentation::new(&reading(1927, 0));
        // 905 MiB free with 475.5 of holes: 429.5 large; 352 wanted left,
        // so 78, held to 60: 369.5 left, 78.5 MiB from the holes.
        assert_eq!(plan.top_up(&reading(905, 1022)), Ok(60 * MIB_KIB));
        // 850 free: 374.5 large, 22.5 tops it up, rounded up to 23.
        assert_eq!(plan.top_up(&reading(850, 1022)), Ok(23 * MIB_KIB));
        // Already short of large blocks: no top-up.
        assert_eq!(plan.top_up(&reading(800, 1022)), Ok(0));
    }

    #[test]
    fn the_top_up_keeps_to_the_jobs_limit() {
        let plan = Fragmentation::new(&reading(1927, 0));
        // 1536 - 1080 - 448 - 4 = 4 MiB of room.
        assert_eq!(plan.top_up(&reading(850, 1080)), Ok(4 * MIB_KIB));
        assert_eq!(plan.top_up(&reading(850, 1090)), Ok(0));
    }

    #[test]
    fn a_guest_the_probe_cannot_fragment_is_refused() {
        let plan = Fragmentation::new(&reading(1927, 0));
        // 920 free: 444.5 large less 60 leaves 384.5, 63.5 from holes.
        assert!(plan.top_up(&reading(920, 1022)).is_ok());
        // 975: 499.5 - 60 leaves 439.5, 8.5 MiB from holes: too few.
        assert!(plan.top_up(&reading(975, 1022)).is_err());
        // 1000: past the object even with the top-up.
        assert!(plan.top_up(&reading(1000, 1022)).is_err());
        // Holes and large blocks together too small for the object.
        let small = Memory {
            budget: 256 * MIB_KIB,
            ..reading(400, 0)
        };
        let plan = Fragmentation::new(&small);
        assert!(plan.holes() < MEASURED_KIB);
        assert!(plan.top_up(&small).is_err());
        assert!(
            plan.top_up(&Memory {
                free: 600 * MIB_KIB,
                ..small
            })
            .is_ok()
        );
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
    fn the_first_allocation_hold_takes_at_most_16_runs() {
        let line = |runs: &str| {
            report(&format!(
                "[DW0][INFO][steps] backing-alloc-longest-us=13 runs={runs} pages=114688\n"
            ))
        };
        assert_eq!(
            backing_alloc(&line("16")),
            Ok("backing-alloc-longest-us=13 runs=16 pages=114688".into())
        );
        assert!(backing_alloc(&line("1")).is_ok());
        assert!(backing_alloc(&line("17")).is_err());
        assert!(backing_alloc(&line("many")).is_err());
        assert!(
            backing_alloc(&report(
                "[DW0][INFO][steps] backing-alloc-longest-us=13 pages=114688\n"
            ))
            .is_err()
        );
        assert!(backing_alloc(&report("")).is_err());
        // The backing-runs line is not this one, nor the reverse.
        let runs = report("[DW0][INFO][steps] backing-runs longest=9856 pages=114688\n");
        assert!(backing_alloc(&runs).is_err());
        assert!(backing_runs(&line("16")).is_err());
    }

    #[test]
    fn one_hold_runs_exactly_one_finalize_step() {
        let line = |longest: &str| {
            report(&format!(
                "[DW0][INFO][steps] finalize-steps-in-one-hold longest={longest}\n"
            ))
        };
        assert_eq!(
            finalize_hold(&line("1")),
            Ok("finalize-steps-in-one-hold longest=1".into())
        );
        assert!(finalize_hold(&line("2")).is_err());
        assert!(finalize_hold(&line("0")).is_err());
        assert!(finalize_hold(&line("one")).is_err());
        assert!(finalize_hold(&report("")).is_err());
    }

    #[test]
    fn a_probe_failure_in_a_job_result_is_decoded() {
        // `wait 7` after `hello churn-commit` ended at site 39 with
        // NO_RESOURCES (0x4D00_270D), as wyrmsh prints it.
        let output = b"wait 7\r\njob result job=7 classification=normal \
            application=1291855629 exception-class=0 exception-detail=0 \
            exception-address=0 cleanup=0\r\nwyrmsh> ";
        assert_eq!(
            hello_failure(output).as_deref(),
            Some("hello failed at site 39 with kernel status -13")
        );
        assert_eq!(
            said(output),
            "; hello failed at site 39 with kernel status -13"
        );
        // Code 0: a data check or an unknown mode (0x4D00_3700, site 55).
        let none = b"job result job=3 classification=normal application=1291859712 \
            exception-class=0 exception-detail=0 exception-address=0 cleanup=0\r\n";
        assert_eq!(
            hello_failure(none).as_deref(),
            Some("hello failed at site 55 with no kernel status")
        );
        // A churn probe's round: `churn-create` refused NO_RESOURCES after
        // 37 rounds (0x4D25_260D), and one past 255 rounds (0x4DFF_260D).
        let rounds = |application: u64| {
            hello_failure(
                format!(
                    "job result job=9 classification=normal application={application} \
                     exception-class=0 exception-detail=0 exception-address=0 cleanup=0\r\n"
                )
                .as_bytes(),
            )
        };
        assert_eq!(
            rounds(1_294_280_205).as_deref(),
            Some("hello failed at site 38 with kernel status -13 after 37 rounds")
        );
        assert_eq!(
            rounds(1_308_567_053).as_deref(),
            Some("hello failed at site 38 with kernel status -13 after 255 or more rounds")
        );
    }

    #[test]
    fn a_status_that_is_not_a_probe_failure_says_nothing() {
        for application in ["0", "1", "2", "1207959565", "4278190080"] {
            let output = format!(
                "job result job=4 classification=authorized application={application} \
                 exception-class=0 exception-detail=0 exception-address=0 cleanup=0\r\n"
            );
            assert_eq!(hello_failure(output.as_bytes()), None, "{application}");
            assert_eq!(said(output.as_bytes()), "");
        }
        // No job result line at all.
        assert_eq!(hello_failure(b"wyrmsh> wait 4\r\nwyrmsh> "), None);
    }

    #[test]
    fn the_step_report_must_drop_no_record() {
        let log = |line: &str| {
            format!(
                "[DW0][INFO][steps] timer-arm retries=0 deferred=0\n\
                 {line}[DW0][INFO] no process remains; powering off\n"
            )
        };
        assert_eq!(
            records_dropped(log("[DW0][INFO][steps] records-dropped=0\n").as_bytes()),
            Ok("records-dropped=0".into())
        );
        assert_eq!(
            records_dropped(log("[DW0][INFO][steps] records-dropped=3\r\n").as_bytes()),
            Err("the kernel dropped 3 records under contention: \"records-dropped=3\"".into())
        );
        assert!(records_dropped(log("").as_bytes()).is_err());
        assert!(
            records_dropped(log("[DW0][INFO][steps] records-dropped=many\n").as_bytes()).is_err()
        );
        // The line outside the step report does not count.
        assert!(records_dropped(log("records-dropped=0\n").as_bytes()).is_err());
    }

    #[test]
    fn the_usage_check_must_compare_groups_and_find_no_mismatch() {
        let log = |line: &str| {
            format!(
                "[DW0][INFO][steps] timer-arm retries=0 deferred=0\n\
                 {line}[DW0][INFO][steps] records-dropped=0\n\
                 [DW0][INFO] no process remains; powering off\n"
            )
        };
        let check = |line: &str| usage_check(log(line).as_bytes());
        assert_eq!(
            check("[DW0][INFO][steps] usage-check groups=4 mismatches=0\n"),
            Ok("usage-check groups=4 mismatches=0".into())
        );
        // A CRLF line ending is not part of the line.
        assert_eq!(
            check("[DW0][INFO][steps] usage-check groups=4 mismatches=0\r\n"),
            Ok("usage-check groups=4 mismatches=0".into())
        );
        assert_eq!(
            check("[DW0][INFO][steps] usage-check groups=4 mismatches=3\n"),
            Err(
                "the kernel's usage check found 3 TaskGroups whose kept usage differs \
                 from a scan (DW2 M8 §13.12 part a): \"usage-check groups=4 mismatches=3\""
                    .into()
            )
        );
        assert_eq!(
            check("[DW0][INFO][steps] usage-check groups=0 mismatches=0\n"),
            Err(
                "the kernel's usage check compared no TaskGroup (DW2 M8 §13.12 part a): \
                 \"usage-check groups=0 mismatches=0\""
                    .into()
            )
        );
        assert_eq!(
            check(""),
            Err("the kernel's step report has no `usage-check` line (DW2 M8 §13.12 part a)".into())
        );
        for unparseable in [
            "[DW0][INFO][steps] usage-check groups=4 mismatches=some\n",
            "[DW0][INFO][steps] usage-check groups=4\n",
            "[DW0][INFO][steps] usage-check mismatches=0\n",
        ] {
            let reason = check(unparseable).unwrap_err();
            assert!(
                reason.contains("does not parse"),
                "{unparseable:?}: {reason}"
            );
        }
        // The line outside the step report does not count.
        assert!(check("usage-check groups=4 mismatches=0\n").is_err());
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
