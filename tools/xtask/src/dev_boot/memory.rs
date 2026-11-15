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
    let churn_modes =
        std::iter::repeat_n("churn-map", CHURN_MAP_RUNS).chain(["churn-create", "churn-commit"]);
    for mode in churn_modes {
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
