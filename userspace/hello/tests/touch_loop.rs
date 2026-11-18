//! `hello touch-loop` (Deepwyrm DW2 M8 §13.5) driven against a recording
//! system: its calls, its figures and its failures.

use std::collections::VecDeque;

use deepwyrm_syscall::{
    DW_MEMORY_OBJECT_CREATE_FLAG_ON_DEMAND, DW_STATUS_NO_MEMORY, DW_STATUS_NO_RESOURCES,
    DW_STATUS_SUCCESS, DwHandle, DwMemoryObjectCreateFlags, DwStatus,
};
use wyrmroot_hello::probe::{PAGE, TouchSummary, spread, touch_loop, touch_loop_arguments};
use wyrmroot_hello::{ChurnCalls, ProbeSite, TouchCalls, decode_probe_failure};
use wyrmroot_loader as _;
use wyrmroot_runtime as _;
use wyrmroot_stream_proto as _;

const MIB: u64 = 1 << 20;

/// One recorded call.
#[derive(Clone, Debug, Eq, PartialEq)]
enum Call {
    Create(u64, u32),
    Map(DwHandle, u64),
    Close(DwHandle),
    Clock,
    Touch(u64, u64),
    Unmap(u64, u64),
}

/// Which call fails, and with what: the `n`th call of that kind (0 is the
/// first).
#[derive(Clone, Copy, Debug)]
enum Fail {
    Map(usize, DwStatus),
    Close(usize, DwStatus),
    Clock(usize, DwStatus),
    UnmapMost(usize, DwStatus),
    UnmapLast(usize, DwStatus),
}

struct Recorder {
    calls: Vec<Call>,
    /// Creates answered first, in order: refused with the status, or
    /// accepted (`None`); after them every create is accepted.
    creates: VecDeque<Option<DwStatus>>,
    /// The clock's readings, in order; after them it reads 0.
    clock: VecDeque<u64>,
    fail: Option<Fail>,
    next: u64,
    maps: usize,
    closes: usize,
    clocks: usize,
    unmaps: usize,
    lines: Vec<Vec<u8>>,
}

impl Recorder {
    fn new() -> Self {
        Self {
            calls: Vec::new(),
            creates: VecDeque::new(),
            clock: VecDeque::new(),
            fail: None,
            next: 100,
            maps: 0,
            closes: 0,
            clocks: 0,
            unmaps: 0,
            lines: Vec::new(),
        }
    }

    /// The clock read `start` and then `start + elapsed` in each round.
    fn rounds_taking(mut self, elapsed: &[u64]) -> Self {
        let mut now = 1_000;
        for &taken in elapsed {
            self.clock.push_back(now);
            self.clock.push_back(now + taken);
            now += taken + 7;
        }
        self
    }

    fn run(&mut self, size_mib: u64, rounds: u32) -> u32 {
        let mut lines = Vec::new();
        let status = touch_loop(self, size_mib, rounds, &mut |line| {
            lines.push(line.to_vec());
            true
        });
        self.lines = lines;
        status
    }
}

impl ChurnCalls for Recorder {
    fn create(
        &mut self,
        size: u64,
        flags: DwMemoryObjectCreateFlags,
    ) -> Result<DwHandle, DwStatus> {
        self.calls.push(Call::Create(size, flags.0));
        if let Some(Some(refusal)) = self.creates.pop_front() {
            return Err(refusal);
        }
        self.next += 1;
        Ok(DwHandle(self.next))
    }

    fn commit(&mut self, _: DwHandle, _: u64) -> DwStatus {
        unreachable!("touch-loop commits nothing")
    }

    fn map(&mut self, object: DwHandle, size: u64) -> Result<u64, DwStatus> {
        self.calls.push(Call::Map(object, size));
        let index = self.maps;
        self.maps += 1;
        if let Some(Fail::Map(at, status)) = self.fail
            && at == index
        {
            return Err(status);
        }
        Ok(object.0 << 32)
    }

    fn unmap(&mut self, at: u64, size: u64) -> Result<(), DwStatus> {
        self.calls.push(Call::Unmap(at, size));
        let index = self.unmaps;
        self.unmaps += 1;
        match self.fail {
            Some(Fail::UnmapMost(round, status)) if index == round * 2 => Err(status),
            Some(Fail::UnmapLast(round, status)) if index == round * 2 + 1 => Err(status),
            _ => Ok(()),
        }
    }

    fn close(&mut self, handle: DwHandle) -> DwStatus {
        self.calls.push(Call::Close(handle));
        let index = self.closes;
        self.closes += 1;
        match self.fail {
            Some(Fail::Close(at, status)) if at == index => status,
            _ => DW_STATUS_SUCCESS,
        }
    }
}

impl TouchCalls for Recorder {
    fn now_ns(&mut self) -> Result<u64, DwStatus> {
        self.calls.push(Call::Clock);
        let index = self.clocks;
        self.clocks += 1;
        if let Some(Fail::Clock(at, status)) = self.fail
            && at == index
        {
            return Err(status);
        }
        Ok(self.clock.pop_front().unwrap_or(0))
    }

    fn touch(&mut self, base: u64, size: u64) {
        self.calls.push(Call::Touch(base, size));
    }
}

const ON_DEMAND: u32 = DW_MEMORY_OBJECT_CREATE_FLAG_ON_DEMAND.0;

/// The calls of one round on object `handle` of `size_mib` MiB.
fn round(handle: u64, size_mib: u64) -> Vec<Call> {
    let size = size_mib * MIB;
    let base = handle << 32;
    vec![
        Call::Create(size, ON_DEMAND),
        Call::Map(DwHandle(handle), size),
        Call::Close(DwHandle(handle)),
        Call::Clock,
        Call::Touch(base, size),
        Call::Clock,
        Call::Unmap(base, size - PAGE),
        Call::Unmap(base + size - PAGE, PAGE),
    ]
}

#[test]
fn one_round_creates_maps_closes_times_a_touch_and_unmaps_in_two() {
    let mut recorder = Recorder::new().rounds_taking(&[16_384 * 250]);
    assert_eq!(recorder.run(64, 1), 0);
    assert_eq!(recorder.calls, round(101, 64));
    let mut recorder = Recorder::new().rounds_taking(&[1, 2, 3]);
    assert_eq!(recorder.run(1, 3), 0);
    let expected: Vec<Call> = [101, 102, 103]
        .into_iter()
        .flat_map(|h| round(h, 1))
        .collect();
    assert_eq!(recorder.calls, expected);
}

#[test]
fn a_round_figure_is_elapsed_nanoseconds_over_pages() {
    // 64 MiB is 16,384 pages: 4,096,000 ns is 250 ns a page, and the
    // division rounds down.
    let mut recorder = Recorder::new().rounds_taking(&[4_096_000 + 16_383]);
    assert_eq!(recorder.run(64, 1), 0);
    let line = String::from_utf8(recorder.lines[0].clone()).unwrap();
    assert!(line.contains(" min-ns-per-page=250 "), "{line}");
    // 1 MiB is 256 pages.
    let mut recorder = Recorder::new().rounds_taking(&[256 * 9_000]);
    assert_eq!(recorder.run(1, 1), 0);
    let line = String::from_utf8(recorder.lines[0].clone()).unwrap();
    assert!(line.contains(" median-ns-per-page=9000 "), "{line}");
}

#[test]
fn the_spread_is_min_lower_median_and_max() {
    assert_eq!(spread(&[5]), Some((5, 5, 5)));
    // Odd: the middle.
    assert_eq!(spread(&[9, 1, 5, 7, 3]), Some((1, 5, 9)));
    // Even: the lower middle.
    assert_eq!(spread(&[40, 10, 30, 20]), Some((10, 20, 40)));
    assert_eq!(spread(&[2, 1]), Some((1, 1, 2)));
    assert_eq!(spread(&[]), None);
    assert_eq!(spread(&[0; 65]), None);
    let many: Vec<u64> = (1..=64).rev().collect();
    assert_eq!(spread(&many), Some((1, 32, 64)));
}

#[test]
fn the_line_carries_the_spread_of_the_rounds() {
    // Per-page figures 30, 10, 20, 40 over 1 MiB (256 pages).
    let per_page = [30_u64, 10, 20, 40];
    let elapsed: Vec<u64> = per_page.iter().map(|ns| ns * 256).collect();
    let mut recorder = Recorder::new().rounds_taking(&elapsed);
    assert_eq!(recorder.run(1, 4), 0);
    assert_eq!(
        recorder.lines,
        [b"touch-loop size-mib=1 rounds=4 min-ns-per-page=10 \
           median-ns-per-page=20 max-ns-per-page=40\n"
            .to_vec()]
    );
    // An odd count: the middle one.
    let elapsed: Vec<u64> = [7_u64, 3, 5].iter().map(|ns| ns * 256).collect();
    let mut recorder = Recorder::new().rounds_taking(&elapsed);
    assert_eq!(recorder.run(1, 3), 0);
    assert_eq!(
        recorder.lines,
        [b"touch-loop size-mib=1 rounds=3 min-ns-per-page=3 \
           median-ns-per-page=5 max-ns-per-page=7\n"
            .to_vec()]
    );
}

#[test]
fn the_line_text_is_exact() {
    let summary = TouchSummary {
        size_mib: 64,
        rounds: 20,
        min: 180,
        median: 205,
        max: 1_234,
    };
    assert_eq!(
        summary.line().as_bytes(),
        b"touch-loop size-mib=64 rounds=20 min-ns-per-page=180 \
          median-ns-per-page=205 max-ns-per-page=1234\n"
    );
    // The widest numbers fit.
    let widest = TouchSummary {
        size_mib: u64::MAX,
        rounds: u32::MAX,
        min: u64::MAX,
        median: u64::MAX,
        max: u64::MAX,
    };
    let text = String::from_utf8(widest.line().as_bytes().to_vec()).unwrap();
    assert!(
        text.ends_with(" max-ns-per-page=18446744073709551615\n"),
        "{text}"
    );
}

#[test]
fn a_refused_create_ends_the_job_at_its_site_after_the_rounds_done() {
    // NO_RESOURCES is not waited out: the kernel waits for owed work inside
    // the call (DW2 M8 §13.12 part b), so a refusal ends the job like any
    // other failed call.
    for (refusal, code) in [(DW_STATUS_NO_RESOURCES, 13), (DW_STATUS_NO_MEMORY, 12)] {
        for completed in [0_u64, 1, 2] {
            let mut recorder = Recorder::new().rounds_taking(&[256; 3]);
            recorder.creates = std::iter::repeat_n(None, completed as usize)
                .chain([Some(refusal)])
                .collect();
            let status = recorder.run(1, 5);
            assert_eq!(
                status,
                ProbeSite::TouchLoopCreate.after(refusal, completed as u32)
            );
            assert_eq!(
                decode_probe_failure(status),
                Some((61, code, completed as u8)),
                "{refusal:?} {completed}"
            );
            // The completed rounds, then the refused create, which is the
            // last call: nothing is retried, and nothing written.
            let mut expected: Vec<Call> = (0..completed).flat_map(|n| round(101 + n, 1)).collect();
            expected.push(Call::Create(MIB, ON_DEMAND));
            assert_eq!(recorder.calls, expected, "{refusal:?} {completed}");
            assert!(recorder.lines.is_empty());
        }
    }
}

#[test]
fn each_failed_call_ends_the_job_with_its_site_status_and_rounds() {
    let status = DwStatus(-7);
    // Each fails in the third round (two completed), except the clock,
    // whose two reads a round are failed one in each place.
    for (fail, site, last) in [
        (
            Fail::Map(2, status),
            ProbeSite::TouchLoopMap,
            Call::Map(DwHandle(103), MIB),
        ),
        (
            Fail::Close(2, status),
            ProbeSite::TouchLoopClose,
            Call::Close(DwHandle(103)),
        ),
        (
            Fail::Clock(4, status),
            ProbeSite::TouchLoopClock,
            Call::Clock,
        ),
        (
            Fail::Clock(5, status),
            ProbeSite::TouchLoopClock,
            Call::Clock,
        ),
        (
            Fail::UnmapMost(2, status),
            ProbeSite::TouchLoopUnmapMost,
            Call::Unmap(103 << 32, MIB - PAGE),
        ),
        (
            Fail::UnmapLast(2, status),
            ProbeSite::TouchLoopUnmapLast,
            Call::Unmap((103 << 32) + MIB - PAGE, PAGE),
        ),
    ] {
        let mut recorder = Recorder::new().rounds_taking(&[256; 5]);
        recorder.fail = Some(fail);
        let ended = recorder.run(1, 5);
        assert_eq!(ended, site.after(status, 2), "{fail:?}");
        assert_eq!(
            decode_probe_failure(ended),
            Some((site as u8, 7, 2)),
            "{fail:?}"
        );
        // Nothing was called after the failed call, and nothing written.
        assert_eq!(recorder.calls.last(), Some(&last), "{fail:?}");
        assert!(recorder.lines.is_empty(), "{fail:?}");
    }
    // A failure in the first round says round 0.
    let mut recorder = Recorder::new();
    recorder.fail = Some(Fail::Map(0, DW_STATUS_NO_RESOURCES));
    assert_eq!(
        decode_probe_failure(recorder.run(64, 20)),
        Some((63, 13, 0))
    );
}

#[test]
fn bad_arguments_fail_with_their_site() {
    assert_eq!(touch_loop_arguments(Some("64"), Some("20")), Ok((64, 20)));
    assert_eq!(touch_loop_arguments(Some("1"), Some("1")), Ok((1, 1)));
    assert_eq!(touch_loop_arguments(Some("256"), Some("64")), Ok((256, 64)));
    let bad = ProbeSite::TouchLoopArgument.alone();
    assert_eq!(decode_probe_failure(bad), Some((59, 0, 0)));
    for (size, rounds) in [
        (None, None),
        (Some("64"), None),
        (None, Some("20")),
        (Some("0"), Some("20")),
        (Some("257"), Some("20")),
        (Some("64"), Some("0")),
        (Some("64"), Some("65")),
        (Some(""), Some("20")),
        (Some("6x"), Some("20")),
        (Some("-1"), Some("20")),
        (Some("+64"), Some("20")),
        (Some("64"), Some("2 0")),
        (Some("1234567"), Some("20")),
    ] {
        assert_eq!(
            touch_loop_arguments(size, rounds),
            Err(bad),
            "{size:?} {rounds:?}"
        );
    }
    // The loop itself refuses what the arguments would, before any call.
    for (size, rounds) in [(0, 1), (257, 1), (1, 0), (1, 65)] {
        let mut recorder = Recorder::new();
        assert_eq!(recorder.run(size, rounds), bad);
        assert!(recorder.calls.is_empty());
    }
}

#[test]
fn sixty_four_rounds_fit_on_the_stack() {
    let mut recorder = Recorder::new().rounds_taking(&[256; 64]);
    assert_eq!(recorder.run(1, 64), 0);
    assert_eq!(recorder.calls.len(), 64 * 8);
}
