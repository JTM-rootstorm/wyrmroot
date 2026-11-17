//! How `hello`'s memory probes report a failure (Deepwyrm DW2 M8 §13.4
//! item 2), and the three churn probes, which run against [`ChurnCalls`] so
//! a host test can drive them.
//!
//! A probe that fails ends its job with [`probe_failure`]'s status:
//! `0x4D00_0000 | (site << 8) | code`, where `site` is the [`ProbeSite`] that
//! failed and `code` is the low byte of the negated kernel status of the
//! call that failed (`DW_STATUS_NO_RESOURCES`, −13, gives 13), or 0 when the
//! failure was not a kernel status (a data check, a bad argument, an unknown
//! mode). A spawned job has no streams, so this status is all it can say.
//! A probe's own success (0) and its deliberate ends (1) never carry the
//! `0x4D` top byte.

use deepwyrm_syscall::{
    DW_MEMORY_OBJECT_CREATE_FLAG_ON_DEMAND, DW_STATUS_SUCCESS, DwHandle, DwMemoryObjectCreateFlags,
    DwStatus,
};

/// The top byte of every probe failure status.
pub const PROBE_FAILURE_PREFIX: u32 = 0x4D00_0000;

/// Where a memory probe failed. The numbers are fixed so a status read
/// from an old log names the same place. Unless a variant says otherwise,
/// the code is the named call's kernel status.
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
}

impl ProbeSite {
    /// Every site, for tests and decoders.
    pub const ALL: [Self; 55] = [
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
    ];

    /// This site's failure with the kernel status of its call.
    #[must_use]
    pub const fn with(self, status: DwStatus) -> u32 {
        probe_failure(self, status)
    }

    /// This site's failure with no kernel status (code 0).
    #[must_use]
    pub const fn alone(self) -> u32 {
        probe_failure(self, DW_STATUS_SUCCESS)
    }
}

/// The job status of a probe that failed at `site` with the kernel's
/// `status` (`DW_STATUS_SUCCESS` when the failure was not a kernel status):
/// `0x4D00_0000 | (site << 8) | code`, `code` being the low byte of the
/// negated status.
#[must_use]
pub const fn probe_failure(site: ProbeSite, status: DwStatus) -> u32 {
    PROBE_FAILURE_PREFIX | ((site as u32) << 8) | ((status.0.wrapping_neg() as u32) & 0xff)
}

/// The site number and code of a probe failure status; `None` for any
/// status without the `0x4D` top byte.
#[must_use]
pub const fn decode_probe_failure(status: u32) -> Option<(u8, u8)> {
    if status & 0xff00_0000 != PROBE_FAILURE_PREFIX {
        return None;
    }
    Some(((status >> 8) as u8, status as u8))
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

/// `churn-create`: a [`CHURN`] eager object created and closed, forever;
/// returns only when a create is refused.
pub fn churn_create(calls: &mut impl ChurnCalls) -> u32 {
    loop {
        match calls.create(CHURN, DwMemoryObjectCreateFlags(0)) {
            Ok(object) => {
                calls.close(object);
            }
            Err(status) => return ProbeSite::ChurnCreate.with(status),
        }
    }
}

/// `churn-commit`: [`commit_once`] of [`CHURN`], forever; returns only
/// when a create is refused.
pub fn churn_commit(calls: &mut impl ChurnCalls) -> u32 {
    loop {
        if let Err(status) = commit_once(calls, CHURN) {
            return ProbeSite::ChurnCommitCreate.with(status);
        }
    }
}

/// `churn-map`: one [`CHURN`] eager object mapped again and again at new
/// addresses, forever.
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
    loop {
        match calls.map(object, CHURN) {
            Ok(base) if count < bases.len() => {
                bases[count] = base;
                count += 1;
            }
            Ok(base) => {
                if let Err(status) = calls.unmap(base, CHURN) {
                    return ProbeSite::ChurnMapUnmapExtra.with(status);
                }
            }
            Err(_) if count > 0 => {
                for &base in &bases[..count] {
                    if let Err(status) = calls.unmap(base, CHURN) {
                        return ProbeSite::ChurnMapUnmapAll.with(status);
                    }
                }
                count = 0;
            }
            Err(status) => return ProbeSite::ChurnMapRefused.with(status),
        }
    }
}
