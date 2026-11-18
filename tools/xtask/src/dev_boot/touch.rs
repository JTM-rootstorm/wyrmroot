//! The first-touch measurement of `dev-boot --check` (Deepwyrm DW2 M8
//! §13.5): `hello touch-loop`, which times a first touch of every page of a
//! fresh on-demand mapping, and the kernel's step report lines on faults,
//! the wait for the runtime lock, the usage check, commit steps and
//! admission waits.
//! - The first boot runs `touch-loop 64 20` alone, in the quiet part with
//!   `close-spin`, before the CPU hogs start.
//! - The second boot, under `--smp` only, spawns two `touch-loop 64 64`
//!   jobs, waits until they are touching, runs `touch-loop 64 20` in the
//!   foreground beside them (three at once: a shell holds at most three
//!   jobs), and then ends the two, each of which must still have been
//!   running, so all three overlapped.
//!
//! The kernel serves a first-touch fault either under its main lock (the
//! `faults` line) or fast, without it (the `faults-fast` line; DW2 M8
//! §13.16). Where the foreground run ran, the two lines' `served` counts
//! together must reach at least the pages it touched
//! ([`TOUCH_LOOP_PAGES`]); the check prints the mean a fault took in the
//! kernel and its parts, one line for each way. In the first boot at least
//! [`FAST_SHARE`] of the served fault passes must have been fast
//! ([`fast_share`]). Each boot's step report must carry the
//! `fault-windows` line ([`fault_windows`]); its counts are not checked.
//!
//! `touch-loop` no longer waits out a refused create: the kernel waits for
//! owed work inside the call (DW2 M8 §13.12 part b), so a refusal ends the
//! job at its site. Each boot's step report must carry the kernel's
//! `admission-waits create=<n> commit=<n> fault=<n>` line
//! ([`admission_waits`]), printed once with each boot's other step-report
//! lines; it requires no particular counts, since whether a call waits
//! depends on timing.

use std::{thread, time::Duration};

use super::{
    memory,
    shell::{Shell, contains, spawn_job},
};
use crate::error::Failure;

/// The foreground run, in both boots.
const SINGLE: &str = "run bin/hello touch-loop 64 20";
/// Each of the second boot's two background jobs: enough rounds to outlast
/// the foreground run.
const SPAWNED: &str = "bin/hello touch-loop 64 64";
/// The pages the foreground run touches: 64 MiB of 4 KiB pages, 20 times.
pub(super) const TOUCH_LOOP_PAGES: u64 = 64 * 256 * 20;
/// The background jobs are touching once usage is this far above the base.
const TOUCHING_KIB: u64 = 32 * 1024;
/// The step report lines the check prints from the second boot.
const SECOND_BOOT_PREFIXES: [&str; 9] = [
    "faults ",
    "faults-fast ",
    "fault-passes ",
    "fault-windows ",
    "t-lock ",
    "p-lock ",
    "usage-check ",
    "commit-steps ",
    "admission-waits ",
];

/// The `touch-loop` line in a job's output, without its line ending.
fn touch_line(output: &[u8]) -> Option<String> {
    const FIELDS: [&str; 5] = [
        "size-mib",
        "rounds",
        "min-ns-per-page",
        "median-ns-per-page",
        "max-ns-per-page",
    ];
    let text = String::from_utf8_lossy(output);
    let line = text.lines().find_map(|line| {
        line.find("touch-loop size-mib=")
            .map(|at| line[at..].trim_end().to_owned())
    })?;
    FIELDS
        .iter()
        .all(|field| memory::line_field(line.as_bytes(), field).is_some())
        .then_some(line)
}

/// `command`'s output: its `touch-loop` line and a normal exit with status
/// 0; else a failure with the output and what the job's status says.
fn finished(output: &[u8], command: &str) -> Result<String, Failure> {
    touch_line(output)
        .filter(|_| contains(output, b"classification=normal application=0 "))
        .ok_or_else(|| {
            Failure::task(format!(
                "dev-boot check: `{command}` printed {:?}{}",
                String::from_utf8_lossy(output),
                memory::said(output)
            ))
        })
}

/// The first boot's single job: `touch-loop 64 20`, alone.
pub(super) fn single(shell: &mut Shell<'_>) -> Result<(), Failure> {
    let output = shell.run(SINGLE)?;
    let line = finished(&output, SINGLE)?;
    eprintln!("dev-boot: {line}");
    Ok(())
}

/// The second boot's three at once (under `--smp`): two spawned jobs
/// touching while the foreground run is timed, then ended; each must still
/// have been running. Usage must then return to where it started.
pub(super) fn three_at_once(shell: &mut Shell<'_>) -> Result<(), Failure> {
    let base = memory::settle(shell, "a settled usage before `hello touch-loop`", |_| true)?;
    let jobs = [spawn_job(shell, SPAWNED)?, spawn_job(shell, SPAWNED)?];
    // Usage swings with each round, so one read past the mark shows they
    // are touching.
    let mut touching = false;
    for _ in 0..shell.attempts() {
        if memory::read(shell)?.jobs_used >= base.jobs_used + TOUCHING_KIB {
            touching = true;
            break;
        }
        thread::sleep(Duration::from_millis(200));
    }
    if !touching {
        let failed = Err(Failure::task(format!(
            "dev-boot check: two `{SPAWNED}` jobs never used {TOUCHING_KIB} KiB above {} KiB",
            base.jobs_used
        )));
        let failed = memory::explain(shell, jobs[0], failed);
        return memory::explain(shell, jobs[1], failed);
    }
    let output = shell.run(SINGLE)?;
    let line = finished(&output, SINGLE)?;
    eprintln!(
        "dev-boot: touch-loop (three at once) {}",
        line.strip_prefix("touch-loop ").unwrap_or(&line)
    );
    for job in jobs {
        memory::end(shell, job)?;
    }
    memory::back_to(shell, &base, "`hello touch-loop` three at once")
}

/// Every line of the kernel's step report in a COM1 log, after `[steps] `,
/// whatever the boot ran.
pub(super) fn report_lines(log: &[u8]) -> Vec<String> {
    String::from_utf8_lossy(log)
        .lines()
        .filter_map(|line| {
            line.split_once("[steps] ")
                .map(|(_, rest)| rest.trim_end().to_owned())
        })
        .collect()
}

/// The second boot's lines the check prints: `faults`, `faults-fast`,
/// `fault-passes`, `fault-windows`, `t-lock` and `p-lock` (one a CPU and
/// source), `usage-check`, `commit-steps` and `admission-waits`. Each
/// prefix ends in a space, so `faults ` does not stand for `faults-fast `.
pub(super) fn second_boot_lines(lines: &[String]) -> Vec<&String> {
    lines
        .iter()
        .filter(|line| {
            SECOND_BOOT_PREFIXES
                .iter()
                .any(|prefix| line.starts_with(prefix))
        })
        .collect()
}

/// The line in a boot's step report `lines` that starts with `prefix`,
/// without its line ending; else an error naming the line's `name` and the
/// design `section` that asks for it.
fn required_line(
    lines: &[String],
    prefix: &str,
    name: &str,
    section: &str,
) -> Result<String, String> {
    lines
        .iter()
        .find(|line| line.starts_with(prefix))
        .map(|line| line.trim_end().to_owned())
        .ok_or_else(|| format!("the kernel's step report has no `{name}` line ({section})"))
}

/// The kernel's `admission-waits create=<n> commit=<n> fault=<n>` line in a
/// boot's step report `lines`, without its line ending: the creates,
/// commits and faults the kernel held inside the call until owed work could
/// admit them (DW2 M8 §13.12 part b). It must be there; its counts are not
/// checked, since whether a call waits depends on timing.
pub(super) fn admission_waits(lines: &[String]) -> Result<String, String> {
    required_line(
        lines,
        "admission-waits ",
        "admission-waits",
        "DW2 M8 §13.12 part b",
    )
}

/// The kernel's `fault-windows opened=<n> closed=<n> declined-identity=<n>
/// declined-mapping=<n> declined-tables=<n> declined-credit=<n>
/// declined-memory=<n> declined-leaf=<n> declined-return=<n>` line in a
/// boot's step report `lines`, without its line ending: the windows the
/// fast serve opened and closed, and why it declined the others (DW2 M8
/// §13.16). It must be there; its counts are not checked.
pub(super) fn fault_windows(lines: &[String]) -> Result<String, String> {
    required_line(lines, "fault-windows ", "fault-windows", "DW2 M8 §13.16")
}

/// The kernel's `faults` line: faults served from the fault gate under the
/// main lock (not the fast ones, DW2 M8 §13.16) and the microseconds they
/// took, in all and by part.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Faults {
    served: u64,
    total: u64,
    sync: u64,
    lookup: u64,
    admit: u64,
    commit: u64,
    tables: u64,
    returning: u64,
}

impl Faults {
    /// `None` without a `faults` line; an error if it does not parse.
    fn parse(lines: &[String]) -> Option<Result<Self, String>> {
        let line = lines.iter().find(|line| line.starts_with("faults "))?;
        let field = |name: &str| memory::line_field(line.as_bytes(), name);
        let parsed = (|| {
            Some(Self {
                served: field("served")?,
                total: field("total-us")?,
                sync: field("sync-us")?,
                lookup: field("lookup-us")?,
                admit: field("admit-us")?,
                commit: field("commit-us")?,
                tables: field("tables-us")?,
                returning: field("return-us")?,
            })
        })();
        Some(parsed.ok_or_else(|| format!("the kernel's faults line does not parse: {line:?}")))
    }

    /// `first touch in the kernel: mean <ns> ns (sync <ns>, lookup <ns>,
    /// admit <ns>, commit <ns>, tables <ns>, return <ns>) over <n> faults`:
    /// each microsecond sum over `served`, in nanoseconds. `None` with no
    /// fault served.
    fn mean_line(self) -> Option<String> {
        if self.served == 0 {
            return None;
        }
        let ns = |us: u64| u128::from(us) * 1000 / u128::from(self.served);
        Some(format!(
            "first touch in the kernel: mean {} ns (sync {}, lookup {}, admit {}, commit {}, \
             tables {}, return {}) over {} faults",
            ns(self.total),
            ns(self.sync),
            ns(self.lookup),
            ns(self.admit),
            ns(self.commit),
            ns(self.tables),
            ns(self.returning),
            self.served
        ))
    }
}

/// The kernel's `faults-fast` line: faults served fast, without the main
/// lock (DW2 M8 §13.16), and the microseconds they took, in all and by
/// part. The kernel always prints it, zeros included.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FaultsFast {
    served: u64,
    total: u64,
    check: u64,
    commit: u64,
    tables: u64,
    returning: u64,
}

impl FaultsFast {
    /// `None` without a `faults-fast` line; an error if it does not parse.
    fn parse(lines: &[String]) -> Option<Result<Self, String>> {
        let line = lines.iter().find(|line| line.starts_with("faults-fast "))?;
        let field = |name: &str| memory::line_field(line.as_bytes(), name);
        let parsed = (|| {
            Some(Self {
                served: field("served")?,
                total: field("total-us")?,
                check: field("check-us")?,
                commit: field("commit-us")?,
                tables: field("tables-us")?,
                returning: field("return-us")?,
            })
        })();
        Some(parsed.ok_or_else(|| {
            format!("the kernel's faults-fast line does not parse (DW2 M8 §13.16): {line:?}")
        }))
    }

    /// `first touch in the kernel, fast: mean <ns> ns (check <ns>, commit
    /// <ns>, tables <ns>, return <ns>) over <n> faults`: each microsecond sum
    /// over `served`, in nanoseconds. `None` with no fault served fast.
    fn mean_line(self) -> Option<String> {
        if self.served == 0 {
            return None;
        }
        let ns = |us: u64| u128::from(us) * 1000 / u128::from(self.served);
        Some(format!(
            "first touch in the kernel, fast: mean {} ns (check {}, commit {}, tables {}, \
             return {}) over {} faults",
            ns(self.total),
            ns(self.check),
            ns(self.commit),
            ns(self.tables),
            ns(self.returning),
            self.served
        ))
    }
}

/// A boot's faults against its step report `lines`. With `least`, the
/// `faults` and `faults-fast` lines must both be there and their `served`
/// counts together reach at least `least` (DW2 M8 §13.16: a fault is served
/// either under the main lock or fast); without, either may be missing.
/// A line that is there must parse. Returns [`Faults::mean_line`] and then
/// [`FaultsFast::mean_line`], each when its line is there with a fault
/// served.
pub(super) fn first_touch(lines: &[String], least: Option<u64>) -> Result<Vec<String>, String> {
    let faults = Faults::parse(lines).transpose()?;
    let fast = FaultsFast::parse(lines).transpose()?;
    if let Some(least) = least {
        let Some(faults) = faults else {
            return Err("the kernel's step report has no `faults` line (DW2 M8 §13.5)".into());
        };
        let Some(fast) = fast else {
            return Err(
                "the kernel's step report has no `faults-fast` line (DW2 M8 §13.16)".into(),
            );
        };
        let served = u128::from(faults.served) + u128::from(fast.served);
        if served < u128::from(least) {
            return Err(format!(
                "the kernel served {served} faults ({} under the main lock, {} fast; \
                 DW2 M8 §13.16), fewer than the {least} pages `touch-loop 64 20` touched",
                faults.served, fast.served
            ));
        }
    }
    Ok(faults
        .and_then(Faults::mean_line)
        .into_iter()
        .chain(fast.and_then(FaultsFast::mean_line))
        .collect())
}

/// The least share of the first boot's served fault passes the fast serve
/// must have answered, as (numerator, denominator): one half (DW2 M8
/// §13.16). `touch-loop` alone touches fresh pages of one mapping, the case
/// the fast serve is for, so most of its faults should not need the main
/// lock. The second boot, with three jobs at once, is not held to it.
const FAST_SHARE: (u64, u64) = (1, 2);

/// The kernel's `fault-passes served=<n> already-present=<n> released=<n>
/// retry=<n> unserved=<n> exhausted=<n> fill-in-serves=<n> fast=<n>` line in
/// a boot's step report `lines`: `fast`, the passes the fast serve answered
/// (also counted under `served` or `already-present`), must be at least
/// [`FAST_SHARE`] of `served` (DW2 M8 §13.16). The line must be there and
/// parse.
pub(super) fn fast_share(lines: &[String]) -> Result<(), String> {
    let line = lines
        .iter()
        .find(|line| line.starts_with("fault-passes "))
        .ok_or("the kernel's step report has no `fault-passes` line (DW2 M8 §13.16)")?;
    let field = |name: &str| memory::line_field(line.as_bytes(), name);
    let (Some(served), Some(fast)) = (field("served"), field("fast")) else {
        return Err(format!(
            "the kernel's fault-passes line does not parse (DW2 M8 §13.16): {line:?}"
        ));
    };
    let (numerator, denominator) = FAST_SHARE;
    if u128::from(fast) * u128::from(denominator) < u128::from(served) * u128::from(numerator) {
        return Err(format!(
            "the fast serve answered {fast} fault passes, fewer than {numerator}/{denominator} \
             of the {served} served (DW2 M8 §13.16)"
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const LOG: &str = "[DW0][INFO][steps] call-steps map=4 unmap=3\n\
        [DW0][INFO][steps] faults served=100000 total-us=30000 longest-us=900 sync-us=2500 \
        lookup-us=2000 admit-us=10000 commit-us=7500 tables-us=3000 return-us=5000\n\
        [DW0][INFO][steps] faults-fast served=300000 total-us=60000 longest-us=400 \
        check-us=6000 commit-us=24000 tables-us=12000 return-us=15000\n\
        [DW0][INFO][steps] fault-passes served=399990 already-present=10 released=0 retry=0 \
        unserved=0 exhausted=0 fill-in-serves=0 fast=300000\n\
        [DW0][INFO][steps] fault-windows opened=300004 closed=300004 declined-identity=0 \
        declined-mapping=1 declined-tables=99990 declined-credit=0 declined-memory=0 \
        declined-leaf=3 declined-return=0\n\
        [DW0][INFO][steps] t-lock cpu=0 source=thread count=5000 wait-us=300 \
        wait-longest-us=40 held-us=9000 held-longest-us=700\n\
        [DW0][INFO][steps] t-lock cpu=1 source=idle count=4000 wait-us=200 \
        wait-longest-us=30 held-us=8000 held-longest-us=600\n\
        [DW0][INFO][steps] p-lock cpu=0 source=fault count=100000 waited=12 wait-us=40 \
        held-us=30000\n\
        [DW0][INFO][steps] p-lock cpu=1 source=usercopy count=7 waited=0 wait-us=0 held-us=2\n\
        [DW0][INFO][steps] usage-check groups=4 mismatches=0\n\
        [DW0][INFO][steps] commit-steps count=7 admit-us=10 take-us=20 rest-us=5\n\
        [DW0][INFO][steps] admission-waits create=2 commit=0 fault=1\r\n\
        [DW0][INFO][steps] records-dropped=0\n\
        [DW0][INFO] no process remains; powering off\n";

    /// The report without the lines that start with `prefix`.
    fn without(prefix: &str) -> Vec<String> {
        lines()
            .into_iter()
            .filter(|line| !line.starts_with(prefix))
            .collect()
    }

    /// The report with `from` replaced by `to`.
    fn replaced(from: &str, to: &str) -> Vec<String> {
        assert!(LOG.contains(from), "{from:?}");
        report_lines(LOG.replace(from, to).as_bytes())
    }

    fn lines() -> Vec<String> {
        report_lines(LOG.as_bytes())
    }

    #[test]
    fn a_touch_loop_line_is_found_in_the_job_output() {
        let output = b"run bin/hello touch-loop 64 20\r\njob budget-kib=524288\r\n\
            touch-loop size-mib=64 rounds=20 min-ns-per-page=180 \
            median-ns-per-page=205 max-ns-per-page=1234\r\n\
            job result job=4 classification=normal application=0 exception-class=0\r\n\
            wyrmsh> ";
        let line = "touch-loop size-mib=64 rounds=20 min-ns-per-page=180 \
                    median-ns-per-page=205 max-ns-per-page=1234";
        assert_eq!(touch_line(output).as_deref(), Some(line));
        assert_eq!(finished(output, SINGLE).unwrap(), line);
        // The command's echo is not the line, nor is a cut-off one.
        assert_eq!(touch_line(b"run bin/hello touch-loop 64 20\r\n"), None);
        assert_eq!(touch_line(b"touch-loop size-mib=64 rounds=20\r\n"), None);
    }

    #[test]
    fn a_touch_loop_that_failed_says_where() {
        // Site 63 (map) with NO_RESOURCES after 3 rounds: 0x4D03_3F0D.
        let output = b"run bin/hello touch-loop 64 20\r\njob budget-kib=524288\r\n\
            job result job=4 classification=normal application=1292058381 \
            exception-class=0\r\nwyrmsh> ";
        let failure = finished(output, SINGLE).unwrap_err();
        assert!(
            failure
                .message
                .ends_with("; hello failed at site 63 with kernel status -13 after 3 rounds"),
            "{}",
            failure.message
        );
        // A line with a status other than 0 fails too.
        let output = b"touch-loop size-mib=64 rounds=20 min-ns-per-page=1 \
            median-ns-per-page=2 max-ns-per-page=3\r\n\
            job result job=4 classification=normal application=1 exception-class=0\r\n";
        assert!(finished(output, SINGLE).is_err());
    }

    #[test]
    fn the_second_boot_prints_the_fault_window_lock_usage_check_commit_and_admission_lines() {
        let lines = lines();
        let printed: Vec<&str> = second_boot_lines(&lines)
            .iter()
            .map(|line| line.split_whitespace().next().unwrap())
            .collect();
        assert_eq!(
            printed,
            [
                "faults",
                "faults-fast",
                "fault-passes",
                "fault-windows",
                "t-lock",
                "t-lock",
                "p-lock",
                "p-lock",
                "usage-check",
                "commit-steps",
                "admission-waits"
            ]
        );
        assert!(second_boot_lines(&report_lines(b"")).is_empty());
        // `faults ` does not stand for `faults-fast `: without the `faults`
        // line, the `faults-fast` line is printed once, by its own prefix.
        let fast_only = without("faults ");
        let printed: Vec<&str> = second_boot_lines(&fast_only)
            .iter()
            .map(|line| line.split_whitespace().next().unwrap())
            .collect();
        assert_eq!(printed.iter().filter(|&&name| name == "faults").count(), 0);
        assert_eq!(
            printed
                .iter()
                .filter(|&&name| name == "faults-fast")
                .count(),
            1
        );
        // Nor does any other name stand for one it is a beginning of: a line
        // named only like a longer one is not printed.
        let lookalikes = report_lines(
            b"[DW0][INFO][steps] faults-fastest served=1\n\
              [DW0][INFO][steps] fault-windowsill opened=1\n\
              [DW0][INFO][steps] p-locked cpu=0\n",
        );
        assert!(second_boot_lines(&lookalikes).is_empty());
    }

    #[test]
    fn each_boot_needs_the_admission_waits_line_whatever_its_counts() {
        assert_eq!(
            admission_waits(&lines()),
            Ok("admission-waits create=2 commit=0 fault=1".into())
        );
        // No wait at all is as good as many.
        let none = report_lines(
            b"[DW0][INFO][steps] admission-waits create=0 commit=0 fault=0\n\
              [DW0][INFO][steps] records-dropped=0\n",
        );
        assert_eq!(
            admission_waits(&none),
            Ok("admission-waits create=0 commit=0 fault=0".into())
        );
        assert_eq!(
            admission_waits(&without("admission-waits ")),
            Err(
                "the kernel's step report has no `admission-waits` line (DW2 M8 §13.12 part b)"
                    .into()
            )
        );
        assert!(admission_waits(&report_lines(b"")).is_err());
    }

    #[test]
    fn each_boot_needs_the_fault_windows_line_whatever_its_counts() {
        assert_eq!(
            fault_windows(&lines()),
            Ok(
                "fault-windows opened=300004 closed=300004 declined-identity=0 \
                declined-mapping=1 declined-tables=99990 declined-credit=0 \
                declined-memory=0 declined-leaf=3 declined-return=0"
                    .into()
            )
        );
        let none = report_lines(
            b"[DW0][INFO][steps] fault-windows opened=0 closed=0 declined-identity=0 \
              declined-mapping=0 declined-tables=0 declined-credit=0 declined-memory=0 \
              declined-leaf=0 declined-return=0\r\n",
        );
        assert!(fault_windows(&none).is_ok());
        assert_eq!(
            fault_windows(&without("fault-windows ")),
            Err("the kernel's step report has no `fault-windows` line (DW2 M8 §13.16)".into())
        );
        // `fault-passes` does not stand for it.
        assert!(
            without("fault-windows ")
                .iter()
                .any(|line| line.starts_with("fault-passes "))
        );
        assert!(fault_windows(&report_lines(b"")).is_err());
    }

    #[test]
    fn the_mean_first_touch_is_each_sum_over_the_faults_served_each_way() {
        // 30,000 us over 100,000 faults is 300 ns; 60,000 us over 300,000
        // fast ones is 200 ns.
        assert_eq!(
            first_touch(&lines(), Some(TOUCH_LOOP_PAGES)),
            Ok(vec![
                "first touch in the kernel: mean 300 ns (sync 25, lookup 20, admit 100, \
                 commit 75, tables 30, return 50) over 100000 faults"
                    .into(),
                "first touch in the kernel, fast: mean 200 ns (check 20, commit 80, \
                 tables 40, return 50) over 300000 faults"
                    .into(),
            ])
        );
        // Rounded down.
        let odd = vec![
            "faults served=3 total-us=1 longest-us=1 sync-us=2 lookup-us=0 admit-us=0 \
             commit-us=0 tables-us=0 return-us=0"
                .to_owned(),
            "faults-fast served=3 total-us=2 longest-us=1 check-us=1 commit-us=0 tables-us=0 \
             return-us=0"
                .to_owned(),
        ];
        assert_eq!(
            first_touch(&odd, None),
            Ok(vec![
                "first touch in the kernel: mean 333 ns (sync 666, lookup 0, admit 0, commit 0, \
                 tables 0, return 0) over 3 faults"
                    .into(),
                "first touch in the kernel, fast: mean 666 ns (check 333, commit 0, tables 0, \
                 return 0) over 3 faults"
                    .into(),
            ])
        );
        // A way with no fault served prints no mean; the other still does.
        let none_fast = replaced("faults-fast served=300000", "faults-fast served=0");
        assert_eq!(
            first_touch(&none_fast, None),
            Ok(vec![
                "first touch in the kernel: mean 300 ns (sync 25, lookup 20, admit 100, \
                 commit 75, tables 30, return 50) over 100000 faults"
                    .into()
            ])
        );
        let none_locked = replaced("faults served=100000", "faults served=0");
        assert_eq!(
            first_touch(&none_locked, None),
            Ok(vec![
                "first touch in the kernel, fast: mean 200 ns (check 20, commit 80, \
                 tables 40, return 50) over 300000 faults"
                    .into()
            ])
        );
        // Both lines begin with the words a timing script looks for.
        for line in first_touch(&lines(), None).unwrap() {
            assert!(line.starts_with("first touch in the kernel"), "{line}");
        }
    }

    #[test]
    fn a_boot_that_must_touch_needs_both_lines_and_enough_faults_between_them() {
        assert_eq!(TOUCH_LOOP_PAGES, 327_680);
        let served = |locked: u64, fast: u64| {
            report_lines(
                LOG.replace("faults served=100000", &format!("faults served={locked}"))
                    .replace(
                        "faults-fast served=300000",
                        &format!("faults-fast served={fast}"),
                    )
                    .as_bytes(),
            )
        };
        // Enough only with both lines' counts.
        assert!(first_touch(&served(27_680, 300_000), Some(TOUCH_LOOP_PAGES)).is_ok());
        assert!(first_touch(&served(0, 327_680), Some(TOUCH_LOOP_PAGES)).is_ok());
        assert!(first_touch(&served(327_680, 0), Some(TOUCH_LOOP_PAGES)).is_ok());
        assert_eq!(
            first_touch(&served(27_679, 300_000), Some(TOUCH_LOOP_PAGES)),
            Err(
                "the kernel served 327679 faults (27679 under the main lock, 300000 fast; \
                 DW2 M8 §13.16), fewer than the 327680 pages `touch-loop 64 20` touched"
                    .into()
            )
        );
        // Neither line alone would do here.
        assert!(first_touch(&served(200_000, 0), Some(TOUCH_LOOP_PAGES)).is_err());
        assert!(first_touch(&served(0, 300_000), Some(TOUCH_LOOP_PAGES)).is_err());
        // `faults` missing: required, or not.
        let missing = without("faults ");
        assert_eq!(
            first_touch(&missing, Some(TOUCH_LOOP_PAGES)),
            Err("the kernel's step report has no `faults` line (DW2 M8 §13.5)".into())
        );
        assert_eq!(first_touch(&missing, None).map(|lines| lines.len()), Ok(1));
        // `faults-fast` missing: an error when required, even with enough
        // faults under the main lock; else only its mean is left out.
        let missing_fast: Vec<String> = served(400_000, 300_000)
            .into_iter()
            .filter(|line| !line.starts_with("faults-fast "))
            .collect();
        assert_eq!(
            first_touch(&missing_fast, Some(TOUCH_LOOP_PAGES)),
            Err("the kernel's step report has no `faults-fast` line (DW2 M8 §13.16)".into())
        );
        assert_eq!(
            first_touch(&missing_fast, None).map(|lines| lines.len()),
            Ok(1)
        );
        // `fault-passes` and `fault-windows` stand for neither.
        assert!(missing.iter().any(|line| line.starts_with("fault-passes ")));
        assert!(
            missing_fast
                .iter()
                .any(|line| line.starts_with("fault-windows "))
        );
        // A garbled line fails whether required or not.
        let garbled = replaced("admit-us=10000", "admit-us=x");
        assert!(first_touch(&garbled, None).is_err());
        assert!(first_touch(&garbled, Some(1)).is_err());
        let garbled_fast = replaced("check-us=6000", "check-us=x");
        let expected = Err(format!(
            "the kernel's faults-fast line does not parse (DW2 M8 §13.16): {:?}",
            garbled_fast
                .iter()
                .find(|line| line.starts_with("faults-fast "))
                .unwrap()
        ));
        assert_eq!(first_touch(&garbled_fast, None), expected);
        assert_eq!(first_touch(&garbled_fast, Some(1)), expected);
        // A boot that served none prints no mean.
        assert_eq!(first_touch(&served(0, 0), None), Ok(Vec::new()));
        assert!(first_touch(&served(0, 0), Some(1)).is_err());
        assert_eq!(first_touch(&report_lines(b""), None), Ok(Vec::new()));
    }

    #[test]
    fn at_least_half_of_the_served_passes_must_be_fast() {
        assert_eq!(FAST_SHARE, (1, 2));
        let passes = |served: u64, fast: u64| {
            vec![format!(
                "fault-passes served={served} already-present=10 released=0 retry=0 unserved=0 \
                 exhausted=0 fill-in-serves=0 fast={fast}"
            )]
        };
        assert_eq!(fast_share(&lines()), Ok(()));
        // At one half, above it, and below it.
        assert_eq!(fast_share(&passes(400_000, 200_000)), Ok(()));
        assert_eq!(fast_share(&passes(400_001, 200_001)), Ok(()));
        assert_eq!(fast_share(&passes(400_000, 400_000)), Ok(()));
        assert_eq!(
            fast_share(&passes(400_000, 199_999)),
            Err(
                "the fast serve answered 199999 fault passes, fewer than 1/2 of the 400000 \
                 served (DW2 M8 §13.16)"
                    .into()
            )
        );
        assert_eq!(
            fast_share(&passes(400_001, 200_000)),
            Err(
                "the fast serve answered 200000 fault passes, fewer than 1/2 of the 400001 \
                 served (DW2 M8 §13.16)"
                    .into()
            )
        );
        // None served: no share to fall short of.
        assert_eq!(fast_share(&passes(0, 0)), Ok(()));
        // Missing, or a line that does not parse.
        assert_eq!(
            fast_share(&without("fault-passes ")),
            Err("the kernel's step report has no `fault-passes` line (DW2 M8 §13.16)".into())
        );
        let garbled = replaced("fast=300000", "fast=many");
        assert_eq!(
            fast_share(&garbled),
            Err(format!(
                "the kernel's fault-passes line does not parse (DW2 M8 §13.16): {:?}",
                garbled
                    .iter()
                    .find(|line| line.starts_with("fault-passes "))
                    .unwrap()
            ))
        );
        // The line from before the fast serve, without `fast`, does not parse.
        assert!(
            fast_share(&[
                "fault-passes served=10 already-present=0 released=0 retry=0 unserved=0 \
                 exhausted=0 fill-in-serves=0"
                    .to_owned()
            ])
            .is_err()
        );
    }
}
