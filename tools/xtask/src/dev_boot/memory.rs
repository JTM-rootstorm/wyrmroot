//! The memory probes of `dev-boot --check` (Deepwyrm DW2 M5 §10.5 probes
//! 12-15). They run in the first boot while the two CPU hogs preempt
//! everything, and read init's plan and the jobs group's live usage through
//! the shell's `memory` command:
//! - 12: init's plan is the rule's arithmetic on its own read of the free
//!   count, a second read agrees with it, and a job's INIT carries the
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
//! that a Stop or an ended parked call landed inside each of a map, a create
//! and a commit.

use std::{thread, time::Duration};

use super::{ATTEMPTS, Shell, contains, spawn_job};
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
    for _ in 0..ATTEMPTS {
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
    for mode in ["churn-map", "churn-create", "churn-commit"] {
        let job = spawn_job(shell, &format!("bin/hello {mode}"))?;
        // A churn's usage swings with each round, so one read past the mark
        // shows it is in its loop.
        let mut churning = None;
        for _ in 0..ATTEMPTS {
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

/// The kernel's `[steps]` report from a COM1 log: its three lines, which
/// must show a Stop or an ended parked call inside a map in steps (plan
/// item 15; `churn-map` is nearly always mapping). Creates and commits are
/// reported, not required: a kill lands in them only by chance.
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
}
