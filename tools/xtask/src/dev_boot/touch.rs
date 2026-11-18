//! The first-touch measurement of `dev-boot --check` (Deepwyrm DW2 M8
//! §13.5): `hello touch-loop`, which times a first touch of every page of a
//! fresh on-demand mapping, and the kernel's step report lines on faults,
//! the wait for the runtime lock, the usage check and commit steps.
//! - The first boot runs `touch-loop 64 20` alone, in the quiet part with
//!   `close-spin`, before the CPU hogs start.
//! - The second boot, under `--smp` only, spawns two `touch-loop 64 64`
//!   jobs, waits until they are touching, runs `touch-loop 64 20` in the
//!   foreground beside them (three at once: a shell holds at most three
//!   jobs), and then ends the two, each of which must still have been
//!   running, so all three overlapped.
//!
//! Each boot's `faults` line must count at least the pages the foreground
//! run touched where it ran ([`TOUCH_LOOP_PAGES`]); the check prints the
//! mean a fault took in the kernel and its parts.

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
const SECOND_BOOT_PREFIXES: [&str; 5] = [
    "faults ",
    "fault-passes ",
    "t-lock ",
    "usage-check ",
    "commit-steps ",
];

/// The `touch-loop` line in a job's output, without its line ending.
fn touch_line(output: &[u8]) -> Option<String> {
    const FIELDS: [&str; 6] = [
        "size-mib",
        "rounds",
        "pauses",
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

/// The second boot's lines the check prints: `faults`, `fault-passes`,
/// `t-lock` (one a CPU), `usage-check` and `commit-steps`.
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

/// The kernel's `faults` line: faults served from the fault gate and the
/// microseconds they took, in all and by part.
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

/// A boot's faults against its step report `lines`. With `least`, the
/// `faults` line must be there and count at least that many served;
/// without, it may be missing. Returns [`Faults::mean_line`] when there is
/// a line with a fault served.
pub(super) fn first_touch(lines: &[String], least: Option<u64>) -> Result<Option<String>, String> {
    let faults = match (Faults::parse(lines), least) {
        (None, None) => return Ok(None),
        (None, Some(_)) => {
            return Err("the kernel's step report has no `faults` line (DW2 M8 §13.5)".into());
        }
        (Some(parsed), _) => parsed?,
    };
    if let Some(least) = least
        && faults.served < least
    {
        return Err(format!(
            "the kernel served {} faults, fewer than the {least} pages `touch-loop 64 20` \
             touched",
            faults.served
        ));
    }
    Ok(faults.mean_line())
}

#[cfg(test)]
mod tests {
    use super::*;

    const LOG: &str = "[DW0][INFO][steps] call-steps map=4 unmap=3\n\
        [DW0][INFO][steps] faults served=400000 total-us=120000 longest-us=900 sync-us=10000 \
        lookup-us=8000 admit-us=40000 commit-us=30000 tables-us=12000 return-us=20000\n\
        [DW0][INFO][steps] fault-passes one=399990 two=10\n\
        [DW0][INFO][steps] t-lock cpu=0 source=thread count=5000 wait-us=300 \
        wait-longest-us=40 held-us=9000 held-longest-us=700\n\
        [DW0][INFO][steps] t-lock cpu=1 source=idle count=4000 wait-us=200 \
        wait-longest-us=30 held-us=8000 held-longest-us=600\n\
        [DW0][INFO][steps] usage-check groups=4 mismatches=0\n\
        [DW0][INFO][steps] commit-steps count=7 admit-us=10 take-us=20 rest-us=5\n\
        [DW0][INFO][steps] records-dropped=0\n\
        [DW0][INFO] no process remains; powering off\n";

    fn lines() -> Vec<String> {
        report_lines(LOG.as_bytes())
    }

    #[test]
    fn a_touch_loop_line_is_found_in_the_job_output() {
        let output = b"run bin/hello touch-loop 64 20\r\njob budget-kib=524288\r\n\
            touch-loop size-mib=64 rounds=20 pauses=0 min-ns-per-page=180 \
            median-ns-per-page=205 max-ns-per-page=1234\r\n\
            job result job=4 classification=normal application=0 exception-class=0\r\n\
            wyrmsh> ";
        let line = "touch-loop size-mib=64 rounds=20 pauses=0 min-ns-per-page=180 \
                    median-ns-per-page=205 max-ns-per-page=1234";
        assert_eq!(touch_line(output).as_deref(), Some(line));
        assert_eq!(finished(output, SINGLE).unwrap(), line);
        // The command's echo is not the line, nor is a cut-off one.
        assert_eq!(touch_line(b"run bin/hello touch-loop 64 20\r\n"), None);
        assert_eq!(
            touch_line(b"touch-loop size-mib=64 rounds=20 pauses=0\r\n"),
            None
        );
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
        let output = b"touch-loop size-mib=64 rounds=20 pauses=0 min-ns-per-page=1 \
            median-ns-per-page=2 max-ns-per-page=3\r\n\
            job result job=4 classification=normal application=1 exception-class=0\r\n";
        assert!(finished(output, SINGLE).is_err());
    }

    #[test]
    fn the_second_boot_prints_the_fault_lock_usage_check_and_commit_lines() {
        let lines = lines();
        let printed: Vec<&str> = second_boot_lines(&lines)
            .iter()
            .map(|line| line.split_whitespace().next().unwrap())
            .collect();
        assert_eq!(
            printed,
            [
                "faults",
                "fault-passes",
                "t-lock",
                "t-lock",
                "usage-check",
                "commit-steps"
            ]
        );
        assert!(second_boot_lines(&report_lines(b"")).is_empty());
    }

    #[test]
    fn the_mean_first_touch_is_each_sum_over_the_faults_served() {
        // 120,000 us over 400,000 faults is 300 ns; 10,000 us is 25 ns.
        assert_eq!(
            first_touch(&lines(), Some(TOUCH_LOOP_PAGES)),
            Ok(Some(
                "first touch in the kernel: mean 300 ns (sync 25, lookup 20, admit 100, \
                 commit 75, tables 30, return 50) over 400000 faults"
                    .into()
            ))
        );
        // Rounded down.
        let odd = vec![
            "faults served=3 total-us=1 longest-us=1 sync-us=2 lookup-us=0 admit-us=0 \
             commit-us=0 tables-us=0 return-us=0"
                .to_owned(),
        ];
        assert_eq!(
            first_touch(&odd, None),
            Ok(Some(
                "first touch in the kernel: mean 333 ns (sync 666, lookup 0, admit 0, commit 0, \
                 tables 0, return 0) over 3 faults"
                    .into()
            ))
        );
    }

    #[test]
    fn a_boot_that_must_touch_needs_the_line_and_enough_faults() {
        assert_eq!(TOUCH_LOOP_PAGES, 327_680);
        let served = |count: u64| {
            report_lines(
                LOG.replace("served=400000", &format!("served={count}"))
                    .as_bytes(),
            )
        };
        assert!(first_touch(&served(327_680), Some(TOUCH_LOOP_PAGES)).is_ok());
        assert_eq!(
            first_touch(&served(327_679), Some(TOUCH_LOOP_PAGES)),
            Err(
                "the kernel served 327679 faults, fewer than the 327680 pages \
                 `touch-loop 64 20` touched"
                    .into()
            )
        );
        // Missing: required, or not.
        let missing: Vec<String> = lines()
            .into_iter()
            .filter(|line| !line.starts_with("faults "))
            .collect();
        assert_eq!(
            first_touch(&missing, Some(TOUCH_LOOP_PAGES)),
            Err("the kernel's step report has no `faults` line (DW2 M8 §13.5)".into())
        );
        assert_eq!(first_touch(&missing, None), Ok(None));
        // `fault-passes` does not stand for `faults`.
        assert!(missing.iter().any(|line| line.starts_with("fault-passes ")));
        // A garbled line fails whether required or not.
        let garbled = report_lines(LOG.replace("admit-us=40000", "admit-us=x").as_bytes());
        assert!(first_touch(&garbled, None).is_err());
        assert!(first_touch(&garbled, Some(1)).is_err());
        // A boot that served none prints no mean.
        assert_eq!(first_touch(&served(0), None), Ok(None));
        assert!(first_touch(&served(0), Some(1)).is_err());
    }
}
