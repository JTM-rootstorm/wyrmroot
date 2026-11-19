//! How `hello`'s memory probes report a failure (Deepwyrm DW2 M8 §13.4
//! item 2), the three churn probes, which run against [`ChurnCalls`] so a
//! host test can drive them, and `touch-loop` (DW2 M8 §13.5), which runs
//! against [`TouchCalls`].
//!
//! A probe that fails ends its job with [`probe_failure_after`]'s status:
//! `0x4D00_0000 | (round << 16) | (site << 8) | code`, where `site` is the
//! [`ProbeSite`] that failed and `code` is the low byte of the negated kernel
//! status of the call that failed (`DW_STATUS_NO_RESOURCES`, −13, gives 13),
//! or 0 when the failure was not a kernel status (a data check, a bad
//! argument, an unknown mode). `round` is how far a churn probe or
//! `touch-loop` got (see each function), saturating at 255, and 0 for
//! every other site. A spawned job has no streams, so this status is all it can say.
//! A probe's own success (0) and its deliberate ends (1) never carry the
//! `0x4D` top byte.
//!
//! No probe waits out a refused call. The kernel refuses a create or a
//! commit only when no owed work could admit it, and waits for that work
//! inside the call itself (DW2 M8 §13.12 part b), so a refused create ends
//! `churn-create`, `churn-commit` and `touch-loop` like any other failed
//! call: they are the regression test of that wait.

use deepwyrm_syscall::{
    DW_MEMORY_OBJECT_CREATE_FLAG_ON_DEMAND, DW_STATUS_SUCCESS, DwHandle, DwMemoryObjectCreateFlags,
    DwStatus,
};

/// The top byte of every probe failure status.
pub const PROBE_FAILURE_PREFIX: u32 = 0x4D00_0000;

/// Where a memory probe failed. The numbers are fixed so a status read
/// from an old log names the same place; a retired site's number (56, 57,
/// 58, 60 and 62, which the waits for a refused create used) is never
/// reused. Unless a variant says otherwise, the code is the named call's
/// kernel status.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum ProbeSite {
    /// `on-demand`: `memory_object_create` of the 64 MiB object.
    OnDemandCreate = 1,
    /// `on-demand`: `object_get_memory_object_info_v1`; code 0 when the call
    /// succeeded and the info was not the object's.
    OnDemandInfo = 2,
    /// `on-demand`: `address_region_map` of the object.
    OnDemandMap = 3,
    /// `on-demand`: the first read was not zero (code 0).
    OnDemandFirstRead = 4,
    /// `on-demand`: the touched words did not read back (code 0).
    OnDemandTouch = 5,
    /// `on-demand`: `clock_get` into an untouched page; code 0 when it
    /// succeeded and left the word zero.
    OnDemandFillIn = 6,
    /// `on-demand`: `memory_object_commit` of one page; code 0 when it
    /// succeeded and the page did not read zero.
    OnDemandCommit = 7,
    /// `on-demand`: `channel_create` for the read fill-in.
    OnDemandChannel = 8,
    /// `on-demand`: `channel_send` from an untouched page.
    OnDemandSend = 9,
    /// `on-demand`: `channel_receive` of that message.
    OnDemandReceive = 10,
    /// `on-demand`: `handle_close` of the sender.
    OnDemandCloseSender = 11,
    /// `on-demand`: `handle_close` of the receiver.
    OnDemandCloseReceiver = 12,
    /// `on-demand`: the read fill-in's bytes were not zero (code 0).
    OnDemandReadFillIn = 13,
    /// `on-demand`: `address_region_unmap` at teardown.
    OnDemandUnmap = 14,
    /// `on-demand`: `handle_close` of the object at teardown.
    OnDemandClose = 15,
    /// `on-demand-exhaust`: four times the budget overflows (code 0).
    ExhaustSize = 16,
    /// `on-demand-exhaust`: `memory_object_create` of the oversized object.
    ExhaustCreate = 17,
    /// `on-demand-exhaust`: `memory_object_commit` was not refused with
    /// `NO_RESOURCES`; the code is what it returned (0 for success).
    ExhaustCommit = 18,
    /// `eager`, `fragmented`, `unfragmented`: `memory_object_create`.
    EagerCreate = 19,
    /// `eager`, `fragmented`, `unfragmented`: `address_region_map`.
    EagerMap = 20,
    /// `eager`, `fragmented`, `unfragmented`: a page did not read zero
    /// before its touch (code 0).
    EagerTouch = 21,
    /// `eager`, `fragmented`, `unfragmented`: `address_region_protect`.
    EagerProtect = 22,
    /// `eager`, `fragmented`, `unfragmented`: the touched words did not read
    /// back (code 0).
    EagerReadBack = 23,
    /// `eager`, `fragmented`, `unfragmented`: `address_region_unmap`.
    EagerUnmap = 24,
    /// `eager`, `fragmented`, `unfragmented`: `handle_close` of the object.
    EagerClose = 25,
    /// `fragmented`: `memory_object_create` of the top-up.
    MeasureTopUp = 26,
    /// `fragmented`: `handle_close` of the top-up.
    MeasureTopUpClose = 27,
    /// `hold-*`: `memory_object_create` of the 64 MiB object.
    HoldCreate = 28,
    /// `hold-*`: `address_region_map` of it.
    HoldMap = 29,
    /// `hold-*`: `handle_close` of its handle.
    HoldClose = 30,
    /// `hold-*`: a page did not read zero before its touch (code 0).
    HoldTouch = 31,
    /// `hold-released`: `address_region_unmap` of the top half.
    HoldUnmap = 32,
    /// `hold-*`: `channel_create` for the wait that never ends.
    HoldSleeper = 33,
    /// `churn-map`: `memory_object_create` of the 256 MiB object.
    ChurnMapCreate = 34,
    /// `churn-map`: `address_region_unmap` of a mapping past the 64 kept.
    ChurnMapUnmapExtra = 35,
    /// `churn-map`: `address_region_unmap` of a kept mapping after a map
    /// was refused.
    ChurnMapUnmapAll = 36,
    /// `churn-map`: `address_region_map` refused with no mapping kept.
    ChurnMapRefused = 37,
    /// `churn-create`: `memory_object_create` of a 256 MiB eager object.
    ChurnCreate = 38,
    /// `churn-commit`: `memory_object_create` of a 256 MiB on-demand
    /// object (its commit's status is ignored, as before).
    ChurnCommitCreate = 39,
    /// `close-spin`: `memory_object_create` of the 512 MiB object.
    CloseSpinCreate = 40,
    /// `close-spin`: `memory_object_commit` failed other than at the quota.
    CloseSpinCommit = 41,
    /// `close-spin`: `handle_close` of the object.
    CloseSpinClose = 42,
    /// `fragment`: no size argument (code 0).
    FragmentArgument = 43,
    /// `fragment`: `memory_object_create` of the filler.
    FragmentFillerCreate = 44,
    /// `fragment`: `memory_object_commit` of the filler.
    FragmentFillerCommit = 45,
    /// `fragment`: `memory_object_create` of the pins.
    FragmentPinsCreate = 46,
    /// `fragment`: `memory_object_create` of the holes.
    FragmentHolesCreate = 47,
    /// `fragment`: `memory_object_commit` of a pinned page.
    FragmentPinCommit = 48,
    /// `fragment`: `memory_object_commit` of a group's holes.
    FragmentHoleCommit = 49,
    /// `fragment`: `handle_close` of the filler.
    FragmentFillerClose = 50,
    /// `fragment`: `handle_close` of the holes.
    FragmentHolesClose = 51,
    /// `fragment`: `channel_create` for its sleeps.
    FragmentSleeper = 52,
    /// `fragment`: `memory_object_create` of the final object failed other
    /// than with `NO_RESOURCES`.
    FragmentFinalCreate = 53,
    /// `hold-*`, `fragment`: the `wait_one` that waits forever returned.
    WaitEnded = 54,
    /// An unknown mode (code 0).
    UnknownMode = 55,
    /// `touch-loop`: the size or the rounds argument is missing or out of
    /// range (code 0).
    TouchLoopArgument = 59,
    /// `touch-loop`: `memory_object_create` of the object.
    TouchLoopCreate = 61,
    /// `touch-loop`: `address_region_map` of the object.
    TouchLoopMap = 63,
    /// `touch-loop`: `handle_close` of the object once it is mapped.
    TouchLoopClose = 64,
    /// `touch-loop`: `clock_get` before or after the touch pass.
    TouchLoopClock = 65,
    /// `touch-loop`: `address_region_unmap` of all but the last page.
    TouchLoopUnmapMost = 66,
    /// `touch-loop`: `address_region_unmap` of the last page.
    TouchLoopUnmapLast = 67,
    /// `touch-loop … committed`: `memory_object_commit` of the whole object
    /// before it is mapped.
    TouchLoopCommit = 68,
}

impl ProbeSite {
    /// Every site, for tests and decoders.
    pub const ALL: [Self; 63] = [
        Self::OnDemandCreate,
        Self::OnDemandInfo,
        Self::OnDemandMap,
        Self::OnDemandFirstRead,
        Self::OnDemandTouch,
        Self::OnDemandFillIn,
        Self::OnDemandCommit,
        Self::OnDemandChannel,
        Self::OnDemandSend,
        Self::OnDemandReceive,
        Self::OnDemandCloseSender,
        Self::OnDemandCloseReceiver,
        Self::OnDemandReadFillIn,
        Self::OnDemandUnmap,
        Self::OnDemandClose,
        Self::ExhaustSize,
        Self::ExhaustCreate,
        Self::ExhaustCommit,
        Self::EagerCreate,
        Self::EagerMap,
        Self::EagerTouch,
        Self::EagerProtect,
        Self::EagerReadBack,
        Self::EagerUnmap,
        Self::EagerClose,
        Self::MeasureTopUp,
        Self::MeasureTopUpClose,
        Self::HoldCreate,
        Self::HoldMap,
        Self::HoldClose,
        Self::HoldTouch,
        Self::HoldUnmap,
        Self::HoldSleeper,
        Self::ChurnMapCreate,
        Self::ChurnMapUnmapExtra,
        Self::ChurnMapUnmapAll,
        Self::ChurnMapRefused,
        Self::ChurnCreate,
        Self::ChurnCommitCreate,
        Self::CloseSpinCreate,
        Self::CloseSpinCommit,
        Self::CloseSpinClose,
        Self::FragmentArgument,
        Self::FragmentFillerCreate,
        Self::FragmentFillerCommit,
        Self::FragmentPinsCreate,
        Self::FragmentHolesCreate,
        Self::FragmentPinCommit,
        Self::FragmentHoleCommit,
        Self::FragmentFillerClose,
        Self::FragmentHolesClose,
        Self::FragmentSleeper,
        Self::FragmentFinalCreate,
        Self::WaitEnded,
        Self::UnknownMode,
        Self::TouchLoopArgument,
        Self::TouchLoopCreate,
        Self::TouchLoopMap,
        Self::TouchLoopClose,
        Self::TouchLoopClock,
        Self::TouchLoopUnmapMost,
        Self::TouchLoopUnmapLast,
        Self::TouchLoopCommit,
    ];

    /// This site's failure with the kernel status of its call.
    #[must_use]
    pub const fn with(self, status: DwStatus) -> u32 {
        probe_failure(self, status)
    }

    /// This site's failure with the kernel status of its call, after
    /// `rounds` rounds of a churn probe.
    #[must_use]
    pub const fn after(self, status: DwStatus, rounds: u32) -> u32 {
        probe_failure_after(self, status, rounds)
    }

    /// This site's failure with no kernel status (code 0).
    #[must_use]
    pub const fn alone(self) -> u32 {
        probe_failure(self, DW_STATUS_SUCCESS)
    }
}

/// The most rounds a status can say; more are reported as this many.
pub const MAX_ROUNDS: u32 = 255;

/// The job status of a probe that failed at `site` with the kernel's
/// `status` (`DW_STATUS_SUCCESS` when the failure was not a kernel status)
/// after `rounds` rounds of a churn probe: `0x4D00_0000 | (round << 16) |
/// (site << 8) | code`, `round` being `rounds` saturated at [`MAX_ROUNDS`]
/// and `code` the low byte of the negated status.
#[must_use]
pub const fn probe_failure_after(site: ProbeSite, status: DwStatus, rounds: u32) -> u32 {
    let round = if rounds > MAX_ROUNDS {
        MAX_ROUNDS
    } else {
        rounds
    };
    PROBE_FAILURE_PREFIX
        | (round << 16)
        | ((site as u32) << 8)
        | ((status.0.wrapping_neg() as u32) & 0xff)
}

/// [`probe_failure_after`] with round 0, for every site but the churn
/// probes'.
#[must_use]
pub const fn probe_failure(site: ProbeSite, status: DwStatus) -> u32 {
    probe_failure_after(site, status, 0)
}

/// The site number, code and round of a probe failure status; `None` for
/// any status without the `0x4D` top byte.
#[must_use]
pub const fn decode_probe_failure(status: u32) -> Option<(u8, u8, u8)> {
    if status & 0xff00_0000 != PROBE_FAILURE_PREFIX {
        return None;
    }
    Some(((status >> 8) as u8, status as u8, (status >> 16) as u8))
}

const MIB: u64 = 1 << 20;
/// What each churn probe maps, creates or commits per round.
pub const CHURN: u64 = 256 * MIB;
/// How many `churn-map` mappings are kept before an extra one is unmapped
/// at once.
const CHURN_MAPS_KEPT: usize = 64;

/// The kernel calls the churn probes make, each returning the kernel's
/// status on failure. The guest's implementation makes the raw syscalls
/// and nothing else.
pub trait ChurnCalls {
    /// `memory_object_create` of `size` bytes with `flags`.
    fn create(&mut self, size: u64, flags: DwMemoryObjectCreateFlags)
    -> Result<DwHandle, DwStatus>;
    /// `memory_object_commit` of `[0, size)` of `object`.
    fn commit(&mut self, object: DwHandle, size: u64) -> DwStatus;
    /// `address_region_map` of `[0, size)` of `object`, read-write; the
    /// address.
    fn map(&mut self, object: DwHandle, size: u64) -> Result<u64, DwStatus>;
    /// `address_region_unmap` of `[at, at + size)`.
    fn unmap(&mut self, at: u64, size: u64) -> Result<(), DwStatus>;
    /// `handle_close`.
    fn close(&mut self, handle: DwHandle) -> DwStatus;
}

/// An on-demand object of `size` created, committed whole and closed; the
/// commit's and the close's statuses are not looked at. The create's
/// status if it was refused.
pub fn commit_once(calls: &mut impl ChurnCalls, size: u64) -> Result<(), DwStatus> {
    let object = calls.create(size, DW_MEMORY_OBJECT_CREATE_FLAG_ON_DEMAND)?;
    let _ = calls.commit(object, size);
    calls.close(object);
    Ok(())
}

/// `churn-create`: a [`CHURN`] eager object created and closed, forever
/// (see [`churn`] for a refused create).
pub fn churn_create(calls: &mut impl ChurnCalls) -> u32 {
    churn(calls, ProbeSite::ChurnCreate, |calls| {
        let object = calls.create(CHURN, DwMemoryObjectCreateFlags(0))?;
        calls.close(object);
        Ok(())
    })
}

/// `churn-commit`: [`commit_once`] of [`CHURN`], forever (see [`churn`]
/// for a refused create).
pub fn churn_commit(calls: &mut impl ChurnCalls) -> u32 {
    churn(calls, ProbeSite::ChurnCommitCreate, |calls| {
        commit_once(calls, CHURN)
    })
}

/// Runs `round` forever. The first round whose create is refused, with
/// any status, ends the job at `refused` with that status and the rounds
/// completed before it; nothing is retried.
fn churn<C: ChurnCalls>(
    calls: &mut C,
    refused: ProbeSite,
    round: impl Fn(&mut C) -> Result<(), DwStatus>,
) -> u32 {
    let mut rounds: u32 = 0;
    loop {
        if let Err(status) = round(calls) {
            return refused.after(status, rounds);
        }
        rounds = rounds.saturating_add(1);
    }
}

/// `churn-map`: one [`CHURN`] eager object mapped again and again at new
/// addresses, forever. A failure after the create carries the number of
/// maps that succeeded since the job started.
pub fn churn_map(calls: &mut impl ChurnCalls) -> u32 {
    let object = match calls.create(CHURN, DwMemoryObjectCreateFlags(0)) {
        Ok(object) => object,
        Err(status) => return ProbeSite::ChurnMapCreate.with(status),
    };
    // The object is mapped again and again at new addresses and the
    // mappings are kept, so the job is almost always inside a map's steps
    // when it is stopped (probe 15). Only when a map is refused (slots,
    // room or page-table quota) are they all unmapped.
    let mut bases = [0_u64; CHURN_MAPS_KEPT];
    let mut count = 0;
    let mut maps: u32 = 0;
    loop {
        let mapped = calls.map(object, CHURN);
        if mapped.is_ok() {
            maps = maps.saturating_add(1);
        }
        match mapped {
            Ok(base) if count < bases.len() => {
                bases[count] = base;
                count += 1;
            }
            Ok(base) => {
                if let Err(status) = calls.unmap(base, CHURN) {
                    return ProbeSite::ChurnMapUnmapExtra.after(status, maps);
                }
            }
            Err(_) if count > 0 => {
                for &base in &bases[..count] {
                    if let Err(status) = calls.unmap(base, CHURN) {
                        return ProbeSite::ChurnMapUnmapAll.after(status, maps);
                    }
                }
                count = 0;
            }
            Err(status) => return ProbeSite::ChurnMapRefused.after(status, maps),
        }
    }
}

/// The page `touch-loop` touches one word of.
pub const PAGE: u64 = 4096;
/// The largest object `touch-loop` takes, in MiB.
pub const TOUCH_MIB_MAX: u64 = 256;
/// The most rounds `touch-loop` runs: its figures are kept on the stack.
pub const TOUCH_ROUNDS_MAX: u32 = 64;

/// The calls `touch-loop` makes besides the churn probes': the monotonic
/// clock and the touch pass. The guest's implementation makes the raw
/// syscall and the writes and nothing else.
pub trait TouchCalls: ChurnCalls {
    /// `clock_get` of the monotonic active clock, in nanoseconds.
    fn now_ns(&mut self) -> Result<u64, DwStatus>;
    /// Writes one word to every page of `[base, base + size)`, with no
    /// read first, so every write is a first touch.
    fn touch(&mut self, base: u64, size: u64);
}

/// `touch-loop <MiB> <rounds> [committed]`'s arguments: the object's size
/// in MiB (1..=[`TOUCH_MIB_MAX`]) and the rounds (1..=[`TOUCH_ROUNDS_MAX`]),
/// each in decimal digits alone, and whether the third argument, exactly
/// `committed`, asks each round to commit its object before touching it
/// (Deepwyrm DW2 M8b §15.2 step 1). A missing or bad size or rounds, or a
/// third argument other than `committed`, is the job status
/// [`ProbeSite::TouchLoopArgument`] with code 0.
pub fn touch_loop_arguments(
    size: Option<&str>,
    rounds: Option<&str>,
    mode: Option<&str>,
) -> Result<(u64, u32, bool), u32> {
    let bad = ProbeSite::TouchLoopArgument.alone();
    let size = size.and_then(decimal).ok_or(bad)?;
    let rounds = rounds.and_then(decimal).ok_or(bad)?;
    if !(1..=TOUCH_MIB_MAX).contains(&size) || !(1..=u64::from(TOUCH_ROUNDS_MAX)).contains(&rounds)
    {
        return Err(bad);
    }
    let committed = match mode {
        None => false,
        Some("committed") => true,
        Some(_) => return Err(bad),
    };
    // In range, so it fits.
    Ok((size, rounds as u32, committed))
}

/// A short decimal number: one to six digits and nothing else.
fn decimal(text: &str) -> Option<u64> {
    if text.is_empty() || text.len() > 6 {
        return None;
    }
    text.bytes().try_fold(0_u64, |value, digit| {
        digit
            .is_ascii_digit()
            .then(|| value * 10 + u64::from(digit - b'0'))
    })
}

/// What `touch-loop` found: the least, the median (the lower middle of an
/// even count) and the greatest of its rounds' nanoseconds a page, and
/// whether each round committed its object before touching it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TouchSummary {
    pub size_mib: u64,
    pub rounds: u32,
    pub min: u64,
    pub median: u64,
    pub max: u64,
    pub committed: bool,
}

impl TouchSummary {
    /// `touch-loop size-mib=<n> rounds=<n> min-ns-per-page=<n>
    /// median-ns-per-page=<n> max-ns-per-page=<n>`, then ` committed=1` when
    /// the rounds committed their objects (nothing otherwise), and a
    /// newline.
    #[must_use]
    pub fn line(&self) -> TouchLine {
        let mut line = TouchLine {
            bytes: [0; TOUCH_LINE_BYTES],
            len: 0,
        };
        for (name, value) in [
            ("touch-loop size-mib=", self.size_mib),
            (" rounds=", u64::from(self.rounds)),
            (" min-ns-per-page=", self.min),
            (" median-ns-per-page=", self.median),
            (" max-ns-per-page=", self.max),
        ] {
            line.text(name);
            line.number(value);
        }
        if self.committed {
            line.text(" committed=1");
        }
        line.text("\n");
        line
    }
}

/// The longest [`TouchSummary::line`]: its names, five numbers of up to
/// twenty digits each and ` committed=1`.
const TOUCH_LINE_BYTES: usize = 224;

/// A [`TouchSummary`]'s line, built without allocation.
pub struct TouchLine {
    bytes: [u8; TOUCH_LINE_BYTES],
    len: usize,
}

impl TouchLine {
    fn text(&mut self, text: &str) {
        for &byte in text.as_bytes() {
            self.bytes[self.len] = byte;
            self.len += 1;
        }
    }

    fn number(&mut self, mut value: u64) {
        let mut digits = [0_u8; 20];
        let mut count = 0;
        loop {
            digits[count] = b'0' + (value % 10) as u8;
            count += 1;
            value /= 10;
            if value == 0 {
                break;
            }
        }
        for &digit in digits[..count].iter().rev() {
            self.bytes[self.len] = digit;
            self.len += 1;
        }
    }

    /// The line's bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}

/// The least, the median (the lower middle of an even count) and the
/// greatest of `times`; `None` for none or more than
/// [`TOUCH_ROUNDS_MAX`]. Sorts a copy on the stack.
#[must_use]
pub fn spread(times: &[u64]) -> Option<(u64, u64, u64)> {
    if times.is_empty() || times.len() > TOUCH_ROUNDS_MAX as usize {
        return None;
    }
    let mut sorted = [0_u64; TOUCH_ROUNDS_MAX as usize];
    let sorted = &mut sorted[..times.len()];
    sorted.copy_from_slice(times);
    sorted.sort_unstable();
    Some((
        sorted[0],
        sorted[(sorted.len() - 1) / 2],
        sorted[sorted.len() - 1],
    ))
}

/// `touch-loop <MiB> <rounds> [committed]` (Deepwyrm DW2 M8 §13.5): each
/// round creates an on-demand object of `size_mib`, with `committed`
/// commits it whole (outside the timed pass, so every touch is of a page
/// already committed: DW2 M8b §15.2 step 1), maps it whole read-write,
/// closes its handle so only the mapping holds it, times one write to every
/// page (each a first touch of the mapping) with the monotonic clock, and
/// unmaps all but the last page and then the last page. With no handle left, the first unmap's steps
/// return the pages they remove, and the object's own finalization, owed
/// after the second, has one page left. A round's figure is the touch
/// pass's nanoseconds divided by its pages.
///
/// Any failed call, a refused create included, ends the job at its own
/// site with its kernel status, its round being the rounds completed;
/// nothing is retried. At the end `write` gets the summary's line
/// ([`TouchSummary::line`]) and the job status is 0. Sizes and rounds
/// outside [`touch_loop_arguments`]'s ranges fail at
/// [`ProbeSite::TouchLoopArgument`] before any call. A commit that does not
/// succeed ends the job at [`ProbeSite::TouchLoopCommit`].
pub fn touch_loop(
    calls: &mut impl TouchCalls,
    size_mib: u64,
    rounds: u32,
    committed: bool,
    write: &mut dyn FnMut(&[u8]) -> bool,
) -> u32 {
    if !(1..=TOUCH_MIB_MAX).contains(&size_mib) || !(1..=TOUCH_ROUNDS_MAX).contains(&rounds) {
        return ProbeSite::TouchLoopArgument.alone();
    }
    let size = size_mib * MIB;
    let pages = size / PAGE;
    let mut figures = [0_u64; TOUCH_ROUNDS_MAX as usize];
    let mut done: u32 = 0;
    while done < rounds {
        let object = match calls.create(size, DW_MEMORY_OBJECT_CREATE_FLAG_ON_DEMAND) {
            Ok(object) => object,
            Err(status) => return ProbeSite::TouchLoopCreate.after(status, done),
        };
        if committed {
            let status = calls.commit(object, size);
            if status != DW_STATUS_SUCCESS {
                return ProbeSite::TouchLoopCommit.after(status, done);
            }
        }
        let base = match calls.map(object, size) {
            Ok(base) => base,
            Err(status) => return ProbeSite::TouchLoopMap.after(status, done),
        };
        let status = calls.close(object);
        if status != DW_STATUS_SUCCESS {
            return ProbeSite::TouchLoopClose.after(status, done);
        }
        let start = match calls.now_ns() {
            Ok(now) => now,
            Err(status) => return ProbeSite::TouchLoopClock.after(status, done),
        };
        calls.touch(base, size);
        let end = match calls.now_ns() {
            Ok(now) => now,
            Err(status) => return ProbeSite::TouchLoopClock.after(status, done),
        };
        if let Err(status) = calls.unmap(base, size - PAGE) {
            return ProbeSite::TouchLoopUnmapMost.after(status, done);
        }
        if let Err(status) = calls.unmap(base + size - PAGE, PAGE) {
            return ProbeSite::TouchLoopUnmapLast.after(status, done);
        }
        figures[done as usize] = end.saturating_sub(start) / pages;
        done += 1;
    }
    // `rounds` is 1..=64, so the spread is there.
    let (min, median, max) = spread(&figures[..rounds as usize]).unwrap_or((0, 0, 0));
    let summary = TouchSummary {
        size_mib,
        rounds,
        min,
        median,
        max,
        committed,
    };
    write(summary.line().as_bytes());
    0
}
