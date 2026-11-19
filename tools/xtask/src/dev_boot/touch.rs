//! The first-touch measurement of `dev-boot --check` (Deepwyrm DW2 M8
//! §13.5): `hello touch-loop`, which times a first touch of every page of a
//! fresh on-demand mapping, and the kernel's step report lines on faults,
//! the wait for the runtime lock, the usage check, commit steps and
//! admission waits. Each run is made twice: as it always was, and with
//! `committed`, which commits each round's object before touching it, so
//! every touch is of a page already committed and the kernel can serve it
//! with its paging lock shared (DW2 M8b §15.2 step 1).
//! - The first boot runs `touch-loop 64 20` alone, in the quiet part with
//!   `close-spin`, before the CPU hogs start, and right after it
//!   `touch-loop 64 20 committed`.
//! - The second boot, under `--smp` only, spawns two `touch-loop 64 64`
//!   jobs, waits until they are touching, runs `touch-loop 64 20` in the
//!   foreground beside them (three at once: a shell holds at most three
//!   jobs), and then ends the two, each of which must still have been
//!   running, so all three overlapped. Once usage is back, it does the same
//!   with all three jobs `committed` ([`ThreeAtOnce`]). A committed job
//!   holds its whole object from the commit, so the committed run's mark
//!   ([`TOUCHING_COMMITTED_KIB`]) is one only two jobs holding their objects
//!   at once can pass.
//!
//! The kernel serves a first-touch fault one of three ways: under its main
//! lock (the `faults` line), fast without it, holding the paging lock
//! exclusively (the `faults-fast` line; DW2 M8 §13.16), or fast with the
//! paging lock shared, on a page already committed (the `faults-shared`
//! line; DW2 M8b §15.2 step 1). Where the foreground run ran, the three
//! lines' `served` counts together must reach at least the pages it touched
//! ([`TOUCH_LOOP_PAGES`]); the check prints the mean a fault took in the
//! kernel and its parts, one line for each way. In the first boot at least
//! [`FAST_SHARE`] of the served fault passes must have been fast, shared
//! serves included ([`fast_share`]). Each boot's step report must carry the
//! `fault-windows opened=<n> closed=<n>` line ([`fault_windows`]) and the
//! `fault-declines identity=<n> mapping=<n> tables=<n> credit=<n>
//! memory=<n> leaf=<n> return=<n>` line ([`fault_declines`]); their counts
//! are not checked. The committed runs only add faults to these sums.
//!
//! A fault on a page already committed is served with the paging lock
//! shared (the `faults-shared` line, DW2 M8b §15.2 step 1); a shared serve
//! that finds the page not committed falls to the ordinary fast serve (the
//! `fault-declines-shared not-committed=<n>` line). Each boot's step report
//! must carry both lines, and they must parse ([`shared_faults`],
//! [`fault_declines_shared`]); where a committed foreground run ran, the
//! shared serves must reach [`SHARED_LEAST`]. The check prints their mean.
//!
//! The kernel also commits ahead of a forward stream of touches (DW2 M8b
//! §15.6 step 2): once a window shows a stream, the serve under the main
//! lock commits the next pages at once, so the stream's later touches find
//! them committed and are served shared. An ordinary `touch-loop` is such
//! a stream. Each boot's step report must carry the `fault-ahead
//! commits=<n> frames=<n> us=<n>` line ([`fault_ahead`]) and the `streams
//! started=<n> ended=<n>` line ([`streams`]), and they must parse; in the
//! first boot the frames committed ahead must reach [`AHEAD_LEAST`]. The
//! check prints the frames, the holds and the mean a frame took.
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
/// The foreground run with each round's object committed before the touch
/// (DW2 M8b §15.2 step 1), in both boots.
const SINGLE_COMMITTED: &str = "run bin/hello touch-loop 64 20 committed";
/// Each of the second boot's two background jobs: enough rounds to outlast
/// the foreground run.
const SPAWNED: &str = "bin/hello touch-loop 64 64";
/// [`SPAWNED`], committed.
const SPAWNED_COMMITTED: &str = "bin/hello touch-loop 64 64 committed";
/// The pages the foreground run touches: 64 MiB of 4 KiB pages, 20 times.
pub(super) const TOUCH_LOOP_PAGES: u64 = 64 * 256 * 20;
/// The background jobs are touching once usage is this far above the base.
/// Their usage grows with each touch of a round and falls at its unmaps,
/// so this says at least one of them is inside a round; that both were
/// still running is what ending them requires ([`memory::end`]).
const TOUCHING_KIB: u64 = 32 * 1024;
/// The committed background jobs are both in a round once usage is this
/// far above the base. A committed job's usage is its whole 64 MiB object
/// from the commit to the unmaps, so [`TOUCHING_KIB`] would be passed by
/// one job's first commit alone. One job holds one object at a time (its
/// unmaps return the pages before its next create), so 96 MiB is passed
/// only with both holding an object, both running.
const TOUCHING_COMMITTED_KIB: u64 = 96 * 1024;
/// The least of `faults-shared served=` where a committed foreground run
/// ran: half its pages (DW2 M8b §15.2 step 1). Not all of them: a touch
/// that needs a new page table still goes through the main lock, and the
/// fault after it through the exclusive fast serve, so some of every
/// committed object's pages are served those ways. Since the kernel commits
/// ahead of a stream (DW2 M8b §15.6 step 2), the ordinary runs' touches are
/// mostly served shared too, so the count holds more than the committed
/// run's; the bound and where it applies are unchanged.
pub(super) const SHARED_LEAST: u64 = TOUCH_LOOP_PAGES / 2;
/// The least of `fault-ahead frames=` in the first boot: half the pages of
/// its ordinary foreground run (DW2 M8b §15.6 step 2). That run is a
/// forward stream, so after each window's first touches the serve under the
/// main lock commits the pages ahead of it; not all of them, since each
/// round's first window, and each new page table, is served before a stream
/// is seen. The committed run commits its own objects, so it adds little.
pub(super) const AHEAD_LEAST: u64 = TOUCH_LOOP_PAGES / 2;
/// The step report lines the check prints from the second boot.
const SECOND_BOOT_PREFIXES: [&str; 14] = [
    "faults ",
    "faults-fast ",
    "faults-shared ",
    "fault-passes ",
    "fault-windows ",
    "fault-ahead ",
    "streams ",
    "fault-declines ",
    "fault-declines-shared ",
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

/// `command`'s output as [`finished`] takes it, from a `committed` run: its
/// line must also say `committed=1`, so the job ran in the mode.
fn finished_committed(output: &[u8], command: &str) -> Result<String, Failure> {
    let line = finished(output, command)?;
    if memory::line_field(line.as_bytes(), "committed") == Some(1) {
        Ok(line)
    } else {
        Err(Failure::task(format!(
            "dev-boot check: `{command}` printed a touch-loop line without committed=1: {line:?}"
        )))
    }
}

/// `line` as the check prints it: `dev-boot: touch-loop (<label>) ...`, the
/// line's own `touch-loop ` moved before the label.
fn labelled(label: &str, line: &str) -> String {
    format!(
        "touch-loop ({label}) {}",
        line.strip_prefix("touch-loop ").unwrap_or(line)
    )
}

/// The first boot's single job: `touch-loop 64 20`, alone.
pub(super) fn single(shell: &mut Shell<'_>) -> Result<(), Failure> {
    let output = shell.run(SINGLE)?;
    let line = finished(&output, SINGLE)?;
    eprintln!("dev-boot: {line}");
    Ok(())
}

/// The first boot's single committed job: `touch-loop 64 20 committed`,
/// alone (DW2 M8b §15.2 step 1).
pub(super) fn single_committed(shell: &mut Shell<'_>) -> Result<(), Failure> {
    let output = shell.run(SINGLE_COMMITTED)?;
    let line = finished_committed(&output, SINGLE_COMMITTED)?;
    eprintln!("dev-boot: {}", labelled("committed", &line));
    Ok(())
}

/// One of the second boot's three-at-once runs: its two spawned jobs, its
/// foreground run, the usage mark that says the spawned jobs are in their
/// rounds, and the label it is printed with.
pub(super) struct ThreeAtOnce {
    spawned: &'static str,
    single: &'static str,
    touching_kib: u64,
    label: &'static str,
    committed: bool,
}

/// Today's three at once: every job as it always was.
pub(super) const THREE_AT_ONCE: ThreeAtOnce = ThreeAtOnce {
    spawned: SPAWNED,
    single: SINGLE,
    touching_kib: TOUCHING_KIB,
    label: "three at once",
    committed: false,
};

/// Three at once with every job `committed` (DW2 M8b §15.2 step 1).
pub(super) const THREE_AT_ONCE_COMMITTED: ThreeAtOnce = ThreeAtOnce {
    spawned: SPAWNED_COMMITTED,
    single: SINGLE_COMMITTED,
    touching_kib: TOUCHING_COMMITTED_KIB,
    label: "three at once, committed",
    committed: true,
};

/// The second boot's three at once (under `--smp`): two spawned jobs
/// touching while the foreground run is timed, then ended; each must still
/// have been running. Usage must then return to where it started.
pub(super) fn three_at_once(shell: &mut Shell<'_>, run: &ThreeAtOnce) -> Result<(), Failure> {
    let ThreeAtOnce {
        spawned,
        single,
        touching_kib,
        label,
        committed,
    } = *run;
    // Today's run keeps its own words; the committed one names itself.
    let what = if committed {
        format!("a settled usage before `hello touch-loop` ({label})")
    } else {
        "a settled usage before `hello touch-loop`".to_owned()
    };
    let base = memory::settle(shell, &what, |_| true)?;
    let jobs = [spawn_job(shell, spawned)?, spawn_job(shell, spawned)?];
    // One read past the mark shows they are in their rounds (see
    // `TOUCHING_KIB` and `TOUCHING_COMMITTED_KIB`).
    let mut touching = false;
    for _ in 0..shell.attempts() {
        if memory::read(shell)?.jobs_used >= base.jobs_used + touching_kib {
            touching = true;
            break;
        }
        thread::sleep(Duration::from_millis(200));
    }
    if !touching {
        let failed = Err(Failure::task(format!(
            "dev-boot check: two `{spawned}` jobs never used {touching_kib} KiB above {} KiB",
            base.jobs_used
        )));
        let failed = memory::explain(shell, jobs[0], failed);
        return memory::explain(shell, jobs[1], failed);
    }
    let output = shell.run(single)?;
    let line = if committed {
        finished_committed(&output, single)?
    } else {
        finished(&output, single)?
    };
    eprintln!("dev-boot: {}", labelled(label, &line));
    for job in jobs {
        memory::end(shell, job)?;
    }
    memory::back_to(shell, &base, &format!("`hello touch-loop` {label}"))
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
/// `faults-shared`, `fault-passes`, `fault-windows`, `fault-declines`,
/// `fault-declines-shared`, `t-lock` and `p-lock` (one a CPU and source),
/// `usage-check`, `commit-steps` and `admission-waits`. Each prefix ends in
/// a space, so `faults ` does not stand for `faults-fast `, nor
/// `fault-declines ` for `fault-declines-shared `.
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

/// The kernel's `fault-windows opened=<n> closed=<n>` line in a boot's step
/// report `lines`, without its line ending: the windows the fast serve
/// opened and closed (DW2 M8 §13.16). It must be there; its counts are not
/// checked.
pub(super) fn fault_windows(lines: &[String]) -> Result<String, String> {
    required_line(lines, "fault-windows ", "fault-windows", "DW2 M8 §13.16")
}

/// The kernel's `fault-ahead commits=<n> frames=<n> us=<n>` line: the
/// serves under the main lock that committed ahead of a stream, the frames
/// they took and the microseconds they took (DW2 M8b §15.6 step 2).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FaultAhead {
    commits: u64,
    frames: u64,
    us: u64,
}

impl FaultAhead {
    /// `commit ahead: <frames> frames in <commits> holds, mean <ns> ns a
    /// frame`: the microseconds over the frames, in nanoseconds. `None`
    /// with no frame taken.
    fn mean_line(self) -> Option<String> {
        if self.frames == 0 {
            return None;
        }
        Some(format!(
            "commit ahead: {} frames in {} holds, mean {} ns a frame",
            self.frames,
            self.commits,
            u128::from(self.us) * 1000 / u128::from(self.frames)
        ))
    }
}

/// The kernel's `fault-ahead commits=<n> frames=<n> us=<n>` line in a
/// boot's step report `lines` (DW2 M8b §15.6 step 2). The kernel prints it
/// right after `fault-windows`. It must be there and parse; with `least`
/// (the first boot, [`AHEAD_LEAST`]) its `frames` must reach it, and
/// otherwise its counts are not checked. Returns
/// [`FaultAhead::mean_line`] when a frame was taken.
pub(super) fn fault_ahead(lines: &[String], least: Option<u64>) -> Result<Option<String>, String> {
    let line = required_line(lines, "fault-ahead ", "fault-ahead", "DW2 M8b §15.6 step 2")?;
    let field = |name: &str| memory::line_field(line.as_bytes(), name);
    let (Some(commits), Some(frames), Some(us)) = (field("commits"), field("frames"), field("us"))
    else {
        return Err(format!(
            "the kernel's fault-ahead line does not parse (DW2 M8b §15.6 step 2): {line:?}"
        ));
    };
    let ahead = FaultAhead {
        commits,
        frames,
        us,
    };
    if let Some(least) = least
        && frames < least
    {
        return Err(format!(
            "the kernel committed {frames} frames ahead of a stream, fewer than {least}, half \
             the pages `touch-loop 64 20` touched (DW2 M8b §15.6 step 2)"
        ));
    }
    Ok(ahead.mean_line())
}

/// The kernel's `streams started=<n> ended=<n>` line in a boot's step
/// report `lines`, without its line ending: the forward streams the fault
/// windows saw start and end (DW2 M8b §15.6 step 2). The kernel prints it
/// right after `fault-ahead`. It must be there and parse; its counts are
/// not checked.
pub(super) fn streams(lines: &[String]) -> Result<String, String> {
    let line = required_line(lines, "streams ", "streams", "DW2 M8b §15.6 step 2")?;
    let field = |name: &str| memory::line_field(line.as_bytes(), name);
    if field("started").is_none() || field("ended").is_none() {
        return Err(format!(
            "the kernel's streams line does not parse (DW2 M8b §15.6 step 2): {line:?}"
        ));
    }
    Ok(line)
}

/// The kernel's `fault-declines identity=<n> mapping=<n> tables=<n>
/// credit=<n> memory=<n> leaf=<n> return=<n>` line in a boot's step report
/// `lines`, without its line ending: why the fast serve declined a fault,
/// by reason (DW2 M8 §13.16). The kernel prints it right after
/// `fault-windows`. It must be there; its counts are not checked.
pub(super) fn fault_declines(lines: &[String]) -> Result<String, String> {
    required_line(lines, "fault-declines ", "fault-declines", "DW2 M8 §13.16")
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

/// The kernel's `faults-shared` line: faults on a page already committed,
/// served with the paging lock shared (DW2 M8b §15.2 step 1), and the
/// microseconds they took, in all and by part. A shared serve commits
/// nothing, so it has no `commit-us`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FaultsShared {
    served: u64,
    total: u64,
    check: u64,
    tables: u64,
    returning: u64,
}

impl FaultsShared {
    /// `None` without a `faults-shared` line; an error if it does not parse.
    fn parse(lines: &[String]) -> Option<Result<Self, String>> {
        let line = lines
            .iter()
            .find(|line| line.starts_with("faults-shared "))?;
        let field = |name: &str| memory::line_field(line.as_bytes(), name);
        let parsed = (|| {
            Some(Self {
                served: field("served")?,
                total: field("total-us")?,
                check: field("check-us")?,
                tables: field("tables-us")?,
                returning: field("return-us")?,
            })
        })();
        Some(parsed.ok_or_else(|| {
            format!(
                "the kernel's faults-shared line does not parse (DW2 M8b §15.2 step 1): {line:?}"
            )
        }))
    }

    /// `first touch in the kernel, shared: mean <ns> ns (check <ns>, tables
    /// <ns>, return <ns>) over <n> faults`: each microsecond sum over
    /// `served`, in nanoseconds. `None` with no fault served shared.
    fn mean_line(self) -> Option<String> {
        if self.served == 0 {
            return None;
        }
        let ns = |us: u64| u128::from(us) * 1000 / u128::from(self.served);
        Some(format!(
            "first touch in the kernel, shared: mean {} ns (check {}, tables {}, return {}) \
             over {} faults",
            ns(self.total),
            ns(self.check),
            ns(self.tables),
            ns(self.returning),
            self.served
        ))
    }
}

/// The failure of a step report without its `faults-shared` line.
const NO_FAULTS_SHARED: &str =
    "the kernel's step report has no `faults-shared` line (DW2 M8b §15.2 step 1)";

/// A boot's shared serves against its step report `lines`: the
/// `faults-shared served=<n> total-us=<n> longest-us=<n> check-us=<n>
/// tables-us=<n> return-us=<n>` line must be there and parse, and with
/// `least` (where a committed foreground run ran, [`SHARED_LEAST`]) its
/// `served` must reach it (DW2 M8b §15.2 step 1). Returns
/// [`FaultsShared::mean_line`] when a fault was served shared.
pub(super) fn shared_faults(
    lines: &[String],
    least: Option<u64>,
) -> Result<Option<String>, String> {
    let shared = FaultsShared::parse(lines).ok_or(NO_FAULTS_SHARED)??;
    if let Some(least) = least
        && shared.served < least
    {
        return Err(format!(
            "the kernel served {} faults with the paging lock shared, fewer than {least}, half \
             the pages `touch-loop 64 20 committed` touched (DW2 M8b §15.2 step 1)",
            shared.served
        ));
    }
    Ok(shared.mean_line())
}

/// The kernel's `fault-declines-shared not-committed=<n>` line in a boot's
/// step report `lines`, without its line ending: the shared serves that
/// found the page not committed and fell to the ordinary fast serve (DW2
/// M8b §15.2 step 1). The kernel prints it right after `fault-declines`. It
/// must be there and parse; its count is not checked.
pub(super) fn fault_declines_shared(lines: &[String]) -> Result<String, String> {
    let line = required_line(
        lines,
        "fault-declines-shared ",
        "fault-declines-shared",
        "DW2 M8b §15.2 step 1",
    )?;
    if memory::line_field(line.as_bytes(), "not-committed").is_none() {
        return Err(format!(
            "the kernel's fault-declines-shared line does not parse (DW2 M8b §15.2 step 1): \
             {line:?}"
        ));
    }
    Ok(line)
}

/// A boot's faults against its step report `lines`. With `least`, the
/// `faults`, `faults-fast` and `faults-shared` lines must all be there and
/// their `served` counts together reach at least `least` (a fault is served
/// under the main lock, fast, or shared: DW2 M8 §13.16, DW2 M8b §15.2 step
/// 1); without, any may be missing. A line that is there must parse.
/// Returns [`Faults::mean_line`] and then [`FaultsFast::mean_line`], each
/// when its line is there with a fault served; the shared mean is
/// [`shared_faults`]'s.
pub(super) fn first_touch(lines: &[String], least: Option<u64>) -> Result<Vec<String>, String> {
    let faults = Faults::parse(lines).transpose()?;
    let fast = FaultsFast::parse(lines).transpose()?;
    let shared = FaultsShared::parse(lines).transpose()?;
    if let Some(least) = least {
        let Some(faults) = faults else {
            return Err("the kernel's step report has no `faults` line (DW2 M8 §13.5)".into());
        };
        let Some(fast) = fast else {
            return Err(
                "the kernel's step report has no `faults-fast` line (DW2 M8 §13.16)".into(),
            );
        };
        let Some(shared) = shared else {
            return Err(NO_FAULTS_SHARED.into());
        };
        let served =
            u128::from(faults.served) + u128::from(fast.served) + u128::from(shared.served);
        if served < u128::from(least) {
            return Err(format!(
                "the kernel served {served} faults ({} under the main lock, {} fast, {} shared; \
                 DW2 M8 §13.16, M8b §15.2), fewer than the {least} pages `touch-loop 64 20` \
                 touched",
                faults.served, fast.served, shared.served
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
        [DW0][INFO][steps] faults-shared served=200000 total-us=20000 longest-us=300 \
        check-us=4000 tables-us=8000 return-us=5000\n\
        [DW0][INFO][steps] fault-passes served=399990 already-present=10 released=0 retry=0 \
        unserved=0 exhausted=0 fill-in-serves=0 fast=300000\n\
        [DW0][INFO][steps] fault-windows opened=300004 closed=300004\n\
        [DW0][INFO][steps] fault-ahead commits=7563 frames=483026 us=66822\n\
        [DW0][INFO][steps] streams started=519 ended=519\n\
        [DW0][INFO][steps] fault-declines identity=0 mapping=1 tables=99990 credit=0 \
        memory=0 leaf=3 return=0\n\
        [DW0][INFO][steps] fault-declines-shared not-committed=7\n\
        [DW0][INFO][steps] t-lock cpu=0 source=thread count=5000 wait-us=300 \
        wait-longest-us=40 held-us=9000 held-longest-us=700\n\
        [DW0][INFO][steps] t-lock cpu=1 source=idle count=4000 wait-us=200 \
        wait-longest-us=30 held-us=8000 held-longest-us=600\n\
        [DW0][INFO][steps] p-lock cpu=0 source=fault count=100000 waited=12 wait-us=40 \
        held-us=30000\n\
        [DW0][INFO][steps] p-lock cpu=1 source=usercopy count=7 waited=0 wait-us=0 held-us=2\n\
        [DW0][INFO][steps] p-lock cpu=2 source=fault-shared count=200000 waited=3 wait-us=5 \
        held-us=15000\n\
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
                "faults-shared",
                "fault-passes",
                "fault-windows",
                "fault-ahead",
                "streams",
                "fault-declines",
                "fault-declines-shared",
                "t-lock",
                "t-lock",
                "p-lock",
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
              [DW0][INFO][steps] faults-sharedx served=1\n\
              [DW0][INFO][steps] fault-windowsill opened=1\n\
              [DW0][INFO][steps] fault-declinesx identity=1\n\
              [DW0][INFO][steps] fault-declines-sharedx not-committed=1\n\
              [DW0][INFO][steps] fault-aheadx commits=1\n\
              [DW0][INFO][steps] streamsx started=1\n\
              [DW0][INFO][steps] p-locked cpu=0\n",
        );
        assert!(second_boot_lines(&lookalikes).is_empty());
        // Without `fault-declines`, `fault-declines-shared` is still printed
        // once, by its own prefix; without `faults-shared`, nothing stands
        // for it.
        let printed_names = |lines: &[String]| -> Vec<String> {
            second_boot_lines(lines)
                .iter()
                .map(|line| line.split_whitespace().next().unwrap().to_owned())
                .collect()
        };
        let names = printed_names(&without("fault-declines "));
        assert_eq!(
            names
                .iter()
                .filter(|name| *name == "fault-declines-shared")
                .count(),
            1
        );
        assert!(!names.iter().any(|name| name == "fault-declines"));
        let names = printed_names(&without("faults-shared "));
        assert!(!names.iter().any(|name| name == "faults-shared"));
        assert!(names.iter().any(|name| name == "faults-fast"));
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
            Ok("fault-windows opened=300004 closed=300004".into())
        );
        let none = report_lines(b"[DW0][INFO][steps] fault-windows opened=0 closed=0\r\n");
        assert_eq!(
            fault_windows(&none),
            Ok("fault-windows opened=0 closed=0".into())
        );
        assert_eq!(
            fault_windows(&without("fault-windows ")),
            Err("the kernel's step report has no `fault-windows` line (DW2 M8 §13.16)".into())
        );
        // `fault-passes` and `fault-declines` do not stand for it.
        let missing = without("fault-windows ");
        assert!(missing.iter().any(|line| line.starts_with("fault-passes ")));
        assert!(
            missing
                .iter()
                .any(|line| line.starts_with("fault-declines "))
        );
        assert!(fault_windows(&report_lines(b"")).is_err());
    }

    #[test]
    fn each_boot_needs_the_fault_declines_line_whatever_its_counts() {
        assert_eq!(
            fault_declines(&lines()),
            Ok(
                "fault-declines identity=0 mapping=1 tables=99990 credit=0 memory=0 leaf=3 \
                return=0"
                    .into()
            )
        );
        let none = report_lines(
            b"[DW0][INFO][steps] fault-declines identity=0 mapping=0 tables=0 credit=0 \
              memory=0 leaf=0 return=0\r\n",
        );
        assert_eq!(
            fault_declines(&none),
            Ok(
                "fault-declines identity=0 mapping=0 tables=0 credit=0 memory=0 leaf=0 return=0"
                    .into()
            )
        );
        assert_eq!(
            fault_declines(&without("fault-declines ")),
            Err("the kernel's step report has no `fault-declines` line (DW2 M8 §13.16)".into())
        );
        // `fault-windows` does not stand for it.
        assert!(
            without("fault-declines ")
                .iter()
                .any(|line| line.starts_with("fault-windows "))
        );
        assert!(fault_declines(&report_lines(b"")).is_err());
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
    fn a_boot_that_must_touch_needs_all_three_lines_and_enough_faults_between_them() {
        assert_eq!(TOUCH_LOOP_PAGES, 327_680);
        let served = |locked: u64, fast: u64, shared: u64| {
            report_lines(
                LOG.replace("faults served=100000", &format!("faults served={locked}"))
                    .replace(
                        "faults-fast served=300000",
                        &format!("faults-fast served={fast}"),
                    )
                    .replace(
                        "faults-shared served=200000",
                        &format!("faults-shared served={shared}"),
                    )
                    .as_bytes(),
            )
        };
        // Enough only with the three lines' counts together, at the edge.
        assert!(first_touch(&served(7_680, 200_000, 120_000), Some(TOUCH_LOOP_PAGES)).is_ok());
        assert!(first_touch(&served(0, 0, 327_680), Some(TOUCH_LOOP_PAGES)).is_ok());
        assert!(first_touch(&served(0, 327_680, 0), Some(TOUCH_LOOP_PAGES)).is_ok());
        assert!(first_touch(&served(327_680, 0, 0), Some(TOUCH_LOOP_PAGES)).is_ok());
        assert_eq!(
            first_touch(&served(7_679, 200_000, 120_000), Some(TOUCH_LOOP_PAGES)),
            Err(
                "the kernel served 327679 faults (7679 under the main lock, 200000 fast, \
                 120000 shared; DW2 M8 §13.16, M8b §15.2), fewer than the 327680 pages \
                 `touch-loop 64 20` touched"
                    .into()
            )
        );
        // The boot that found the gap: its shared serves make up the rest.
        assert!(first_touch(&served(9_372, 79_566, 0), Some(TOUCH_LOOP_PAGES)).is_err());
        assert!(first_touch(&served(9_372, 79_566, 238_742), Some(TOUCH_LOOP_PAGES)).is_ok());
        // No two lines alone would do here.
        assert!(first_touch(&served(200_000, 120_000, 0), Some(TOUCH_LOOP_PAGES)).is_err());
        assert!(first_touch(&served(0, 200_000, 120_000), Some(TOUCH_LOOP_PAGES)).is_err());
        assert!(first_touch(&served(200_000, 0, 120_000), Some(TOUCH_LOOP_PAGES)).is_err());
        // `faults-shared` missing: the failure `shared_faults` gives, when
        // required, even with enough faults the other ways; else nothing.
        let missing_shared: Vec<String> = served(400_000, 300_000, 0)
            .into_iter()
            .filter(|line| !line.starts_with("faults-shared "))
            .collect();
        assert_eq!(
            first_touch(&missing_shared, Some(TOUCH_LOOP_PAGES)),
            Err(NO_FAULTS_SHARED.into())
        );
        assert_eq!(
            first_touch(&missing_shared, Some(TOUCH_LOOP_PAGES)),
            shared_faults(&missing_shared, None).map(|_| Vec::new())
        );
        assert_eq!(
            first_touch(&missing_shared, None).map(|lines| lines.len()),
            Ok(2)
        );
        // A garbled `faults-shared` line fails whether required or not.
        let garbled_shared = replaced("check-us=4000", "check-us=x");
        assert!(first_touch(&garbled_shared, None).is_err());
        assert!(first_touch(&garbled_shared, Some(1)).is_err());
        // `faults` missing: required, or not.
        let missing = without("faults ");
        assert_eq!(
            first_touch(&missing, Some(TOUCH_LOOP_PAGES)),
            Err("the kernel's step report has no `faults` line (DW2 M8 §13.5)".into())
        );
        assert_eq!(first_touch(&missing, None).map(|lines| lines.len()), Ok(1));
        // `faults-fast` missing: an error when required, even with enough
        // faults under the main lock; else only its mean is left out.
        let missing_fast: Vec<String> = served(400_000, 300_000, 0)
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
        assert_eq!(first_touch(&served(0, 0, 0), None), Ok(Vec::new()));
        assert!(first_touch(&served(0, 0, 0), Some(1)).is_err());
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
    #[test]
    fn a_committed_run_must_say_committed() {
        let output = b"run bin/hello touch-loop 64 20 committed\r\njob budget-kib=524288\r\n\
            touch-loop size-mib=64 rounds=20 min-ns-per-page=90 \
            median-ns-per-page=100 max-ns-per-page=400 committed=1\r\n\
            job result job=5 classification=normal application=0 exception-class=0\r\n\
            wyrmsh> ";
        let line = "touch-loop size-mib=64 rounds=20 min-ns-per-page=90 \
                    median-ns-per-page=100 max-ns-per-page=400 committed=1";
        assert_eq!(finished_committed(output, SINGLE_COMMITTED).unwrap(), line);
        // The plain check takes the committed line too: it only adds a field.
        assert_eq!(finished(output, SINGLE_COMMITTED).unwrap(), line);
        // A run that printed the plain line did not run in the mode.
        let plain = b"touch-loop size-mib=64 rounds=20 min-ns-per-page=90 \
            median-ns-per-page=100 max-ns-per-page=400\r\n\
            job result job=5 classification=normal application=0 exception-class=0\r\n";
        assert_eq!(
            finished_committed(plain, SINGLE_COMMITTED)
                .unwrap_err()
                .message,
            "dev-boot check: `run bin/hello touch-loop 64 20 committed` printed a touch-loop \
             line without committed=1: \"touch-loop size-mib=64 rounds=20 min-ns-per-page=90 \
             median-ns-per-page=100 max-ns-per-page=400\""
        );
        let other = String::from_utf8_lossy(output).replace("committed=1", "committed=0");
        assert!(finished_committed(other.as_bytes(), SINGLE_COMMITTED).is_err());
        // A refused commit (site 68) with NO_RESOURCES after 2 rounds,
        // 0x4D02_440D, says where.
        let output = b"run bin/hello touch-loop 64 20 committed\r\njob budget-kib=524288\r\n\
            job result job=5 classification=normal application=1291994125 \
            exception-class=0\r\nwyrmsh> ";
        let failure = finished_committed(output, SINGLE_COMMITTED).unwrap_err();
        assert!(
            failure
                .message
                .ends_with("; hello failed at site 68 with kernel status -13 after 2 rounds"),
            "{}",
            failure.message
        );
    }

    #[test]
    fn the_committed_runs_print_with_their_labels() {
        let line = "touch-loop size-mib=64 rounds=20 min-ns-per-page=90 \
                    median-ns-per-page=100 max-ns-per-page=400 committed=1";
        assert_eq!(
            labelled("committed", line),
            "touch-loop (committed) size-mib=64 rounds=20 min-ns-per-page=90 \
             median-ns-per-page=100 max-ns-per-page=400 committed=1"
        );
        assert_eq!(
            labelled(THREE_AT_ONCE_COMMITTED.label, line),
            "touch-loop (three at once, committed) size-mib=64 rounds=20 \
             min-ns-per-page=90 median-ns-per-page=100 max-ns-per-page=400 committed=1"
        );
        // Today's three at once prints as it did.
        let plain = "touch-loop size-mib=64 rounds=20 min-ns-per-page=180 \
                     median-ns-per-page=205 max-ns-per-page=1234";
        assert_eq!(
            labelled(THREE_AT_ONCE.label, plain),
            "touch-loop (three at once) size-mib=64 rounds=20 min-ns-per-page=180 \
             median-ns-per-page=205 max-ns-per-page=1234"
        );
        // The two runs: today's as it was, and the committed one in the mode
        // throughout.
        assert_eq!(
            (THREE_AT_ONCE.spawned, THREE_AT_ONCE.single),
            (
                "bin/hello touch-loop 64 64",
                "run bin/hello touch-loop 64 20"
            )
        );
        assert_eq!(THREE_AT_ONCE.touching_kib, 32 * 1024);
        assert_eq!(
            (
                THREE_AT_ONCE_COMMITTED.spawned,
                THREE_AT_ONCE_COMMITTED.single
            ),
            (
                "bin/hello touch-loop 64 64 committed",
                "run bin/hello touch-loop 64 20 committed"
            )
        );
        assert_eq!(
            [THREE_AT_ONCE.committed, THREE_AT_ONCE_COMMITTED.committed],
            [false, true]
        );
        // One committed job holds 64 MiB: the committed mark, 96 MiB, needs
        // more than one, and less than two.
        assert_eq!(THREE_AT_ONCE_COMMITTED.touching_kib, 96 * 1024);
    }

    #[test]
    fn each_boot_needs_the_faults_shared_line_and_its_mean_is_printed() {
        // 20,000 us over 200,000 shared faults is 100 ns.
        assert_eq!(
            shared_faults(&lines(), None),
            Ok(Some(
                "first touch in the kernel, shared: mean 100 ns (check 20, tables 40, \
                 return 25) over 200000 faults"
                    .into()
            ))
        );
        // Rounded down.
        let odd = vec![
            "faults-shared served=3 total-us=2 longest-us=1 check-us=1 tables-us=0 return-us=0"
                .to_owned(),
        ];
        assert_eq!(
            shared_faults(&odd, None),
            Ok(Some(
                "first touch in the kernel, shared: mean 666 ns (check 333, tables 0, return 0) \
                 over 3 faults"
                    .into()
            ))
        );
        // None served: no mean, but the line is there, as a boot without a
        // committed run has it.
        let none = replaced("faults-shared served=200000", "faults-shared served=0");
        assert_eq!(shared_faults(&none, None), Ok(None));
        // Missing: an error whether a committed run ran or not.
        let missing = without("faults-shared ");
        let absent = Err(
            "the kernel's step report has no `faults-shared` line (DW2 M8b §15.2 step 1)"
                .to_owned(),
        );
        assert_eq!(shared_faults(&missing, None), absent);
        assert_eq!(shared_faults(&missing, Some(SHARED_LEAST)), absent);
        // `faults` and `faults-fast` do not stand for it.
        assert!(missing.iter().any(|line| line.starts_with("faults ")));
        assert!(missing.iter().any(|line| line.starts_with("faults-fast ")));
        // A garbled line fails whether a committed run ran or not; so does
        // one without a part.
        let garbled = replaced("check-us=4000", "check-us=x");
        let expected = Err(format!(
            "the kernel's faults-shared line does not parse (DW2 M8b §15.2 step 1): {:?}",
            garbled
                .iter()
                .find(|line| line.starts_with("faults-shared "))
                .unwrap()
        ));
        assert_eq!(shared_faults(&garbled, None), expected);
        assert_eq!(shared_faults(&garbled, Some(1)), expected);
        let no_tables = replaced("tables-us=8000 ", "");
        assert!(shared_faults(&no_tables, None).is_err());
        // `first_touch` needs it too where the foreground run ran, with the
        // same failure; elsewhere it leaves it to `shared_faults`.
        assert_eq!(
            first_touch(&missing, Some(TOUCH_LOOP_PAGES)).unwrap_err(),
            absent.clone().unwrap_err()
        );
        assert!(first_touch(&missing, None).is_ok());
    }

    #[test]
    fn a_committed_run_needs_half_its_pages_served_shared() {
        assert_eq!(SHARED_LEAST, 163_840);
        assert_eq!(SHARED_LEAST * 2, TOUCH_LOOP_PAGES);
        let served = |count: u64| {
            replaced(
                "faults-shared served=200000",
                &format!("faults-shared served={count}"),
            )
        };
        // At the bound and above it.
        assert!(shared_faults(&served(163_840), Some(SHARED_LEAST)).is_ok());
        assert!(shared_faults(&served(163_841), Some(SHARED_LEAST)).is_ok());
        assert!(shared_faults(&served(TOUCH_LOOP_PAGES), Some(SHARED_LEAST)).is_ok());
        // One below it.
        assert_eq!(
            shared_faults(&served(163_839), Some(SHARED_LEAST)),
            Err(
                "the kernel served 163839 faults with the paging lock shared, fewer than \
                 163840, half the pages `touch-loop 64 20 committed` touched (DW2 M8b §15.2 \
                 step 1)"
                    .into()
            )
        );
        assert!(shared_faults(&served(0), Some(SHARED_LEAST)).is_err());
        // Without a committed run, any count will do.
        assert!(shared_faults(&served(0), None).is_ok());
        assert!(shared_faults(&served(163_839), None).is_ok());
        // Faults served the other ways do not count toward it.
        let others = report_lines(
            LOG.replace("faults-shared served=200000", "faults-shared served=163839")
                .replace("faults served=100000", "faults served=900000")
                .replace("faults-fast served=300000", "faults-fast served=900000")
                .as_bytes(),
        );
        assert!(shared_faults(&others, Some(SHARED_LEAST)).is_err());
    }

    #[test]
    fn each_boot_needs_the_fault_declines_shared_line_whatever_its_count() {
        assert_eq!(
            fault_declines_shared(&lines()),
            Ok("fault-declines-shared not-committed=7".into())
        );
        let none = report_lines(b"[DW0][INFO][steps] fault-declines-shared not-committed=0\r\n");
        assert_eq!(
            fault_declines_shared(&none),
            Ok("fault-declines-shared not-committed=0".into())
        );
        let missing = without("fault-declines-shared ");
        assert_eq!(
            fault_declines_shared(&missing),
            Err(
                "the kernel's step report has no `fault-declines-shared` line (DW2 M8b §15.2 \
                 step 1)"
                    .into()
            )
        );
        // `fault-declines` does not stand for it, nor it for `fault-declines`.
        assert!(
            missing
                .iter()
                .any(|line| line.starts_with("fault-declines "))
        );
        assert_eq!(
            fault_declines(&without("fault-declines ")),
            Err("the kernel's step report has no `fault-declines` line (DW2 M8 §13.16)".into())
        );
        // A line that does not parse.
        for garbled in [
            "fault-declines-shared not-committed=x",
            "fault-declines-shared not-committed=",
            "fault-declines-shared committed=3",
        ] {
            assert_eq!(
                fault_declines_shared(&[garbled.to_owned()]),
                Err(format!(
                    "the kernel's fault-declines-shared line does not parse (DW2 M8b §15.2 \
                     step 1): {garbled:?}"
                )),
                "{garbled}"
            );
        }
        // The name alone, without its fields, is not the line.
        assert!(fault_declines_shared(&["fault-declines-shared".to_owned()]).is_err());
        assert!(fault_declines_shared(&report_lines(b"")).is_err());
    }
    #[test]
    fn each_boot_needs_the_fault_ahead_line_and_its_mean_is_printed() {
        // 66,822 us over 483,026 frames is 138.3 ns, rounded down.
        let mean = "commit ahead: 483026 frames in 7563 holds, mean 138 ns a frame";
        assert_eq!(fault_ahead(&lines(), None), Ok(Some(mean.into())));
        assert_eq!(
            fault_ahead(&lines(), Some(AHEAD_LEAST)),
            Ok(Some(mean.into()))
        );
        let odd = vec!["fault-ahead commits=1 frames=3 us=2".to_owned()];
        assert_eq!(
            fault_ahead(&odd, None),
            Ok(Some(
                "commit ahead: 3 frames in 1 holds, mean 666 ns a frame".into()
            ))
        );
        // No frame taken: no line, but the line must still be there.
        let none = vec!["fault-ahead commits=0 frames=0 us=0".to_owned()];
        assert_eq!(fault_ahead(&none, None), Ok(None));
        // Missing.
        let missing = without("fault-ahead ");
        let absent = Err(
            "the kernel's step report has no `fault-ahead` line (DW2 M8b §15.6 step 2)".to_owned(),
        );
        assert_eq!(fault_ahead(&missing, None), absent);
        assert_eq!(fault_ahead(&missing, Some(AHEAD_LEAST)), absent);
        assert!(fault_ahead(&report_lines(b""), None).is_err());
        // `fault-windows` and `streams` do not stand for it.
        assert!(
            missing
                .iter()
                .any(|line| line.starts_with("fault-windows "))
        );
        assert!(missing.iter().any(|line| line.starts_with("streams ")));
        // Malformed, whether a floor applies or not.
        for garbled in [
            "fault-ahead commits=x frames=483026 us=66822",
            "fault-ahead commits=7563 frames= us=66822",
            "fault-ahead commits=7563 frames=483026",
            "fault-ahead frames=483026 us=66822",
        ] {
            let expected = Err(format!(
                "the kernel's fault-ahead line does not parse (DW2 M8b §15.6 step 2): {garbled:?}"
            ));
            assert_eq!(fault_ahead(&[garbled.to_owned()], None), expected);
            assert_eq!(
                fault_ahead(&[garbled.to_owned()], Some(AHEAD_LEAST)),
                expected
            );
        }
    }

    #[test]
    fn the_first_boot_needs_half_its_ordinary_pages_committed_ahead() {
        assert_eq!(AHEAD_LEAST, 163_840);
        assert_eq!(AHEAD_LEAST * 2, TOUCH_LOOP_PAGES);
        let frames = |count: u64| vec![format!("fault-ahead commits=10 frames={count} us=1000")];
        // At the floor and above it.
        assert!(fault_ahead(&frames(163_840), Some(AHEAD_LEAST)).is_ok());
        assert!(fault_ahead(&frames(163_841), Some(AHEAD_LEAST)).is_ok());
        // One below it.
        assert_eq!(
            fault_ahead(&frames(163_839), Some(AHEAD_LEAST)),
            Err(
                "the kernel committed 163839 frames ahead of a stream, fewer than 163840, half \
                 the pages `touch-loop 64 20` touched (DW2 M8b §15.6 step 2)"
                    .into()
            )
        );
        assert!(fault_ahead(&frames(0), Some(AHEAD_LEAST)).is_err());
        // The second boot has no floor.
        assert_eq!(fault_ahead(&frames(0), None), Ok(None));
        assert!(fault_ahead(&frames(163_839), None).is_ok());
    }

    #[test]
    fn each_boot_needs_the_streams_line_whatever_its_counts() {
        assert_eq!(
            streams(&lines()),
            Ok("streams started=519 ended=519".into())
        );
        let none = report_lines(b"[DW0][INFO][steps] streams started=0 ended=0\r\n");
        assert_eq!(streams(&none), Ok("streams started=0 ended=0".into()));
        // Unequal counts are not checked.
        assert_eq!(
            streams(&["streams started=5 ended=2".to_owned()]),
            Ok("streams started=5 ended=2".into())
        );
        let missing = without("streams ");
        assert_eq!(
            streams(&missing),
            Err("the kernel's step report has no `streams` line (DW2 M8b §15.6 step 2)".into())
        );
        // `fault-ahead` does not stand for it.
        assert!(missing.iter().any(|line| line.starts_with("fault-ahead ")));
        assert!(streams(&report_lines(b"")).is_err());
        for garbled in [
            "streams started=x ended=519",
            "streams started=519",
            "streams ended=519",
            "streams started=519 ended=",
        ] {
            assert_eq!(
                streams(&[garbled.to_owned()]),
                Err(format!(
                    "the kernel's streams line does not parse (DW2 M8b §15.6 step 2): \
                     {garbled:?}"
                )),
                "{garbled}"
            );
        }
        // The name alone is not the line.
        assert!(streams(&["streams".to_owned()]).is_err());
    }
}
