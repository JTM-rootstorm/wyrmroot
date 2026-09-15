//! Persistent launch-transaction storage, reset card R6A.
//!
//! # Why this exists
//!
//! Reset plan §7 requires that a dynamic launch stop holding the resident
//! dispatcher while it waits for child READY. Today it does: everything from
//! `JobController::begin_reserved_launch` through `publish_launch_accepted`
//! lives in one `accept_reserved_launch` stack frame in `wyr1b_native.rs`, and
//! the blocking observation sits in the middle of it --
//!
//! ```text
//! let observation = observe_prepared_ready(waits, &prepared, deadline);
//! ```
//!
//! -- so every fact the launch still needs is a local of a frame that cannot
//! return until the child answers or the deadline expires. §3's invariant 6
//! says one child failing to reach READY must not block the supervisor from
//! servicing unrelated control traffic, and a stack frame is the reason it
//! does.
//!
//! Returning to the event loop mid-launch means those facts have to live
//! somewhere that outlives the dispatch. This module is that somewhere. R6A
//! added it and changed no behaviour; R6B-1 split construction from the READY
//! observation; R6B-2 wired the arena into `JobDispatcher` and moved the
//! resident dispatcher onto it, so a launch really does return to the event
//! loop between the two halves. R6C drives the remaining events -- EXITED,
//! deadline, cancel, cleanup -- from ordinary dispatch, and they are still the
//! reason a `Failing` slot can be reached from three stages.
//!
//! What R6B-2 does *not* move is the console launcher's ShellV1 wire, which has
//! its own `accept_reserved_shell` and was never split by R6B-1. Its launch
//! still publishes in the frame that read it.
//!
//! # Why these fields
//!
//! The wire semantics must not change, which fixes most of the record.
//! §9 of `Plans/WYR1_B_REGISTRY_LAUNCH_CONTRACT.md` requires every response to
//! repeat the request's connection ID, connection generation and transaction
//! ID, and §9.5 requires that only a fresh request transaction receive one
//! response. A reply written minutes after the request that provoked it can
//! only satisfy that if the envelope it must echo was kept: hence
//! [`Reservation`] and the session Channel, stored at open and never
//! recomputed.
//!
//! The three handles are the other half. `rollback_prepared_job` and
//! `cleanup_loaded` close the child Process, its launch Channel and its
//! TaskGroup; in the synchronous path they are reachable because `prepared` is
//! still in scope. Deferred, they are reachable only from here, and a slot that
//! could be freed while still holding them would leak exactly the three handles
//! nothing else has a name for.
//!
//! # Losing a child is impossible here
//!
//! A slot cannot close while it holds resources. [`LaunchTransactions::close`]
//! refuses with [`LaunchTransactionError::ResourcesHeld`], and the only way to
//! empty a slot is [`LaunchTransactions::take_resources`], which hands the
//! handles to a caller that can close them. This is the same rule the
//! termination arena applies to finalizers in `deepwyrm` card R5A, for the same
//! reason: an obligation dropped inside the arena is one nothing would report.
//!
//! # Why the stage is a graph and not a counter
//!
//! §7 draws the state machine as
//!
//! ```text
//! Reserved -> Constructed -> AwaitingReady -> Published
//!               |               |              |
//!               +-> Failing ----+--------------+
//!                               |
//!                               +-> Cleanup -> Complete
//! ```
//!
//! which is not a total order: `Failing` is reachable from three stages and
//! `Cleanup` from two. A monotone ordinal would admit `Constructed ->
//! Published`, skipping the READY observation that §9.5 makes the precondition
//! for `LAUNCH_ACCEPTED`. [`LaunchStage::may_advance_to`] is therefore an
//! explicit edge set, and the edges are the diagram's.
//!
//! `Reserved -> Failing` is the one edge not drawn. The current dispatcher
//! reaches it: a request whose moved handles fail `validate_controller_channel`,
//! or whose TaskGroup cannot be created, is rejected after the reservation and
//! before any construction. Every transaction leaves through `Complete`, so
//! that path needs the edge.
//!
//! # Capacity
//!
//! One slot per launch session. WRLJ is request/response over a session and the
//! dispatcher reads one request from a session at a time, so a session cannot
//! have two launches in flight; [`LaunchTransactions::open`] enforces that
//! rather than assuming it, which is what makes `MAX_SESSIONS` a bound and not
//! a hope. Each open transaction also holds one reservation in the
//! `JobController`, so the arena must not outnumber the live-job table: 16
//! sessions against `MAX_LIVE_JOBS` 32, asserted below.

#![allow(
    dead_code,
    reason = "R6B-2 uses most of this; `fail`, `failure` and `job_transaction` \
              are the disposition and cancel surface R6C drives from ordinary \
              dispatch, and are kept rather than removed and rewritten"
)]

use deepwyrm_syscall::{DwDeadline, DwHandle};
use wyrmroot_launch_proto::{MAX_LIVE_JOBS, Reservation};
use wyrmroot_loader::launch::LaunchProfile;

use crate::wyr1b::EndpointGrant;
use crate::wyr1b_job::{LaunchSessionScope, MAX_SESSIONS};

/// Concurrent launch transactions the arena can hold.
///
/// R6A sized this at `MAX_SESSIONS`, one per launch session, on the reasoning
/// that WRLJ is request/response over a session so a session cannot have two
/// launches in flight. That bound is still correct and [`LaunchTransactions::open`]
/// still enforces it. It is not the binding one.
///
/// R6B measured the arena inside the resident. `JobDispatcher` lives in
/// `ResidentSystemInit`, which `resident_fits_locked_native_stack_partition`
/// locks to a 20,480-byte partition of init's 108 KiB execution stack, and
/// which measured 19,496 bytes without this arena. Sixteen slots cost 2,704
/// bytes against 984 of headroom, so the session bound cannot be the slot
/// count.
///
/// Five is the concurrency this buys, and the arithmetic is:
///
/// | | Bytes |
/// | --- | ---: |
/// | Resident partition | 20,480 |
/// | Resident without the arena | 19,496 |
/// | Headroom | 984 |
/// | Per slot | 169 |
/// | Five slots plus the arena's own cursors | see [`LAUNCH_ARENA_BUDGET_BYTES`] |
///
/// A sixth concurrent launch is not silently dropped. It fails to reserve and
/// the session receives `ERROR` code 6, capacity, which §9.5 of
/// `Plans/WYR1_B_REGISTRY_LAUNCH_CONTRACT.md` already defines -- so the cap is
/// a stated wire outcome rather than an invisible limit.
///
/// Five also sits above every topology the reset has exercised: the console
/// launcher, the shell-jobs session and the R1 probe's session give a peak of
/// three simultaneous in-flight launches. This is an interim figure. §10's
/// generated resource-budget record is what should own it, and that record
/// still does not exist.
///
/// **Corrected at R6E, 2026-09-15.** The table above is one tier's, and the
/// arithmetic it supports was generalised to builds that do not share it.
/// `resident_fits_locked_native_stack_partition` selects three budgets: 40 KiB
/// under `wyr1d-selector32` or `wyr1e-production`, 22 KiB under
/// `wyr1c6-selector29`, 20 KiB otherwise. 20,480 and 984 are the last of those.
/// Measured with this arena wired in, the spare left after it is 144 bytes on
/// the default tier, 840 on selector 29, and 4,832 to 7,552 on the 40 KiB
/// builds -- so five slots fit everywhere, and the tier that binds is the one
/// with no evidence surface, which is also the one that pays least for a slot.
/// R6B-2 relies on that: the per-slot request facts are gated with the evidence
/// features, so the tier with 144 bytes of headroom carries none of them.
pub(crate) const LAUNCH_TRANSACTION_SLOTS: usize = 5;

/// What the arena's ungated part may cost on the tightest resident tier.
///
/// Measured, not assumed: `resident_fits_locked_native_stack_partition` locks
/// the default tier to 20,480 bytes and the resident measured 19,496 without
/// the arena. This is that tier's headroom and no other's -- see
/// [`LAUNCH_TRANSACTION_SLOTS`] for why the distinction matters. Since R6B-2
/// wired the arena into `JobDispatcher`, the resident gate measures the real
/// total in every tier and is the one that binds; this stays as the named cost
/// of the storage itself.
pub(crate) const LAUNCH_ARENA_BUDGET_BYTES: usize = 20_480 - 19_496;

const _: () = assert!(
    LAUNCH_TRANSACTION_SLOTS <= MAX_SESSIONS,
    "a session may hold one launch in flight, so more slots than sessions cannot all be used"
);

const _: () = assert!(
    LAUNCH_TRANSACTION_SLOTS <= MAX_LIVE_JOBS,
    "every open transaction holds a live-job reservation, so the arena cannot outnumber the job table"
);

/// How far one launch has got, as reset plan §7 draws it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum LaunchStage {
    /// The request reserved a transaction and a job slot. Nothing is loaded.
    Reserved,
    /// The loader committed; the child exists but is not visible to its owner.
    Constructed,
    /// Waiting for the exact profile/transaction READY record.
    AwaitingReady,
    /// READY observed and `LAUNCH_ACCEPTED` sent.
    Published,
    /// A disposition is fixed and the launch will not be accepted.
    Failing,
    /// Releasing whatever the transaction still holds.
    Cleanup,
    /// Nothing is held; the slot may close.
    Complete,
}

impl LaunchStage {
    /// The edge set of §7's diagram, plus `Reserved -> Failing`.
    pub(crate) const fn may_advance_to(self, next: Self) -> bool {
        matches!(
            (self, next),
            (Self::Reserved, Self::Constructed)
                | (Self::Reserved, Self::Failing)
                | (Self::Constructed, Self::AwaitingReady)
                | (Self::Constructed, Self::Failing)
                | (Self::AwaitingReady, Self::Published)
                | (Self::AwaitingReady, Self::Failing)
                | (Self::Published, Self::Cleanup)
                | (Self::Failing, Self::Cleanup)
                | (Self::Cleanup, Self::Complete)
        )
    }
}

/// The handles one launch owns until it hands them on or closes them.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct LaunchResources {
    pub(crate) process: DwHandle,
    pub(crate) launch_channel: DwHandle,
    pub(crate) task_group: DwHandle,
}

/// The disposition a failing transaction will report.
///
/// `code` is a WRLJ `ERROR` code from §9.5's stable list, kept as the wire
/// value so the deferred response cannot be reclassified between the failure
/// and the reply.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct LaunchFailure {
    pub(crate) code: u32,
    pub(crate) cleanup_failed: bool,
}

/// §9.5's `ERROR` codes run 1 through 10.
const MIN_ERROR_CODE: u32 = 1;
const MAX_ERROR_CODE: u32 = 10;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum LaunchTransactionError {
    /// Every slot is occupied.
    Capacity,
    /// The token names a slot whose generation has moved on.
    Stale,
    /// That session already has a launch in flight.
    SessionBusy,
    /// §7's diagram has no such edge.
    StageTransition,
    /// The slot still owns handles. Take them before closing.
    ResourcesHeld,
    /// A zero handle, a zero job ID, or resources attached twice.
    ResourceIdentity,
    /// The transaction has not reached `Complete`.
    Incomplete,
    /// Not a §9.5 `ERROR` code.
    ErrorCode,
    /// A slot's generation is exhausted; it retires rather than reuses,
    /// because a reused generation cannot be told from a stale token.
    GenerationExhausted,
}

/// Exact identity of one open transaction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct LaunchToken {
    slot: usize,
    generation: u64,
}

impl LaunchToken {
    pub(crate) const fn slot(self) -> usize {
        self.slot
    }
    pub(crate) const fn generation(self) -> u64 {
        self.generation
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct LaunchSlot {
    generation: u64,
    open: bool,
    grant: EndpointGrant,
    session: DwHandle,
    scope: LaunchSessionScope,
    reservation: Reservation,
    stage: LaunchStage,
    job_id: u64,
    profile: Option<LaunchProfile>,
    resources: Option<LaunchResources>,
    ready_deadline: Option<DwDeadline>,
    failure: Option<LaunchFailure>,
    /// The request's contribution to the evidence record, taken while the
    /// request bytes were still in hand.
    ///
    /// R6B-2. A deferred reply cannot re-read the request, and cannot keep it:
    /// `MAX_LAUNCH_MESSAGE_BYTES` is 17,760 and §7.1 of the reset plan measured
    /// that out. Two digests and a reservation are the whole of what the join
    /// needs from it. Gated with the evidence, because a build with no evidence
    /// surface has nothing to record and should not pay 88 bytes a slot to
    /// carry it -- the default resident tier has 144 bytes of headroom in
    /// total.
    #[cfg(any(feature = "wyr1e-selector33", feature = "wyr1e8-selector33"))]
    request_facts: Option<crate::launch_request_facts::LaunchRequestFacts>,
    /// Which recovery leg this launch was classified as, if it was one.
    ///
    /// Its reservation is the slot's, so only the action has to be carried.
    #[cfg(feature = "wyr1e8-selector33")]
    trigger_action: Option<crate::wyr1b_native::E8RecoveryAction>,
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct LaunchTransactions {
    slots: [Option<LaunchSlot>; LAUNCH_TRANSACTION_SLOTS],
    retired: [bool; LAUNCH_TRANSACTION_SLOTS],
    generations: [u64; LAUNCH_TRANSACTION_SLOTS],
}

impl LaunchTransactions {
    pub(crate) const fn new() -> Self {
        Self {
            slots: [None; LAUNCH_TRANSACTION_SLOTS],
            retired: [false; LAUNCH_TRANSACTION_SLOTS],
            generations: [0; LAUNCH_TRANSACTION_SLOTS],
        }
    }

    /// Opens a transaction for one session's in-flight launch request.
    pub(crate) fn open(
        &mut self,
        grant: EndpointGrant,
        session: DwHandle,
        scope: LaunchSessionScope,
        reservation: Reservation,
    ) -> Result<LaunchToken, LaunchTransactionError> {
        if session.0 == 0
            || reservation.connection_id == 0
            || reservation.generation == 0
            || reservation.transaction_id == 0
        {
            return Err(LaunchTransactionError::ResourceIdentity);
        }
        if self
            .slots
            .iter()
            .flatten()
            .any(|slot| slot.open && slot.grant == grant)
        {
            return Err(LaunchTransactionError::SessionBusy);
        }
        let index = self
            .slots
            .iter()
            .enumerate()
            .position(|(index, slot)| slot.is_none() && !self.retired[index])
            .ok_or(LaunchTransactionError::Capacity)?;
        let generation = self.generations[index]
            .checked_add(1)
            .ok_or(LaunchTransactionError::GenerationExhausted)?;
        self.generations[index] = generation;
        self.slots[index] = Some(LaunchSlot {
            generation,
            open: true,
            grant,
            session,
            scope,
            reservation,
            stage: LaunchStage::Reserved,
            job_id: 0,
            profile: None,
            resources: None,
            ready_deadline: None,
            failure: None,
            #[cfg(any(feature = "wyr1e-selector33", feature = "wyr1e8-selector33"))]
            request_facts: None,
            #[cfg(feature = "wyr1e8-selector33")]
            trigger_action: None,
        });
        Ok(LaunchToken {
            slot: index,
            generation,
        })
    }

    fn slot(&self, token: LaunchToken) -> Result<&LaunchSlot, LaunchTransactionError> {
        let slot = self
            .slots
            .get(token.slot)
            .and_then(Option::as_ref)
            .ok_or(LaunchTransactionError::Stale)?;
        if !slot.open || slot.generation != token.generation {
            return Err(LaunchTransactionError::Stale);
        }
        Ok(slot)
    }

    fn slot_mut(&mut self, token: LaunchToken) -> Result<&mut LaunchSlot, LaunchTransactionError> {
        let slot = self
            .slots
            .get_mut(token.slot)
            .and_then(Option::as_mut)
            .ok_or(LaunchTransactionError::Stale)?;
        if !slot.open || slot.generation != token.generation {
            return Err(LaunchTransactionError::Stale);
        }
        Ok(slot)
    }

    pub(crate) fn stage(&self, token: LaunchToken) -> Result<LaunchStage, LaunchTransactionError> {
        self.slot(token).map(|slot| slot.stage)
    }

    pub(crate) fn scope(
        &self,
        token: LaunchToken,
    ) -> Result<LaunchSessionScope, LaunchTransactionError> {
        self.slot(token).map(|slot| slot.scope)
    }

    /// The envelope a deferred response must echo: the session Channel to send
    /// on, and the request's exact connection/generation/transaction triple.
    pub(crate) fn response_envelope(
        &self,
        token: LaunchToken,
    ) -> Result<(DwHandle, Reservation), LaunchTransactionError> {
        self.slot(token)
            .map(|slot| (slot.session, slot.reservation))
    }

    pub(crate) fn grant(
        &self,
        token: LaunchToken,
    ) -> Result<EndpointGrant, LaunchTransactionError> {
        self.slot(token).map(|slot| slot.grant)
    }

    pub(crate) fn advance(
        &mut self,
        token: LaunchToken,
        next: LaunchStage,
    ) -> Result<(), LaunchTransactionError> {
        let slot = self.slot_mut(token)?;
        if !slot.stage.may_advance_to(next) {
            return Err(LaunchTransactionError::StageTransition);
        }
        slot.stage = next;
        Ok(())
    }

    pub(crate) fn attach_job(
        &mut self,
        token: LaunchToken,
        job_id: u64,
    ) -> Result<(), LaunchTransactionError> {
        if job_id == 0 {
            return Err(LaunchTransactionError::ResourceIdentity);
        }
        let slot = self.slot_mut(token)?;
        if slot.job_id != 0 {
            return Err(LaunchTransactionError::ResourceIdentity);
        }
        slot.job_id = job_id;
        Ok(())
    }

    pub(crate) fn job_id(&self, token: LaunchToken) -> Result<u64, LaunchTransactionError> {
        self.slot(token).map(|slot| slot.job_id)
    }

    /// Records the constructed child. Attaching twice is refused rather than
    /// overwriting, because the overwritten handles would be unreachable.
    pub(crate) fn attach_resources(
        &mut self,
        token: LaunchToken,
        profile: LaunchProfile,
        resources: LaunchResources,
    ) -> Result<(), LaunchTransactionError> {
        if resources.process.0 == 0
            || resources.launch_channel.0 == 0
            || resources.task_group.0 == 0
        {
            return Err(LaunchTransactionError::ResourceIdentity);
        }
        let slot = self.slot_mut(token)?;
        if slot.resources.is_some() {
            return Err(LaunchTransactionError::ResourceIdentity);
        }
        slot.profile = Some(profile);
        slot.resources = Some(resources);
        Ok(())
    }

    pub(crate) fn resources(
        &self,
        token: LaunchToken,
    ) -> Result<Option<LaunchResources>, LaunchTransactionError> {
        self.slot(token).map(|slot| slot.resources)
    }

    pub(crate) fn profile(
        &self,
        token: LaunchToken,
    ) -> Result<Option<LaunchProfile>, LaunchTransactionError> {
        self.slot(token).map(|slot| slot.profile)
    }

    /// Hands the handles to a caller that can close or publish them. This is
    /// the only way to empty a slot, and the only way to reach `close`.
    pub(crate) fn take_resources(
        &mut self,
        token: LaunchToken,
    ) -> Result<Option<LaunchResources>, LaunchTransactionError> {
        let slot = self.slot_mut(token)?;
        Ok(slot.resources.take())
    }

    /// Records the request-derived half of the evidence record.
    ///
    /// R6B-2. Refuses a second attach rather than overwriting: two different
    /// requests cannot both be the one this transaction answers, and silently
    /// keeping the later one would put a digest in the record that no reader
    /// could reproduce.
    #[cfg(any(feature = "wyr1e-selector33", feature = "wyr1e8-selector33"))]
    pub(crate) fn attach_request_facts(
        &mut self,
        token: LaunchToken,
        facts: crate::launch_request_facts::LaunchRequestFacts,
    ) -> Result<(), LaunchTransactionError> {
        if facts.reservation() != self.slot(token)?.reservation {
            return Err(LaunchTransactionError::ResourceIdentity);
        }
        let slot = self.slot_mut(token)?;
        if slot.request_facts.is_some() {
            return Err(LaunchTransactionError::ResourceIdentity);
        }
        slot.request_facts = Some(facts);
        Ok(())
    }

    #[cfg(any(feature = "wyr1e-selector33", feature = "wyr1e8-selector33"))]
    pub(crate) fn request_facts(
        &self,
        token: LaunchToken,
    ) -> Result<Option<crate::launch_request_facts::LaunchRequestFacts>, LaunchTransactionError>
    {
        self.slot(token).map(|slot| slot.request_facts)
    }

    #[cfg(feature = "wyr1e8-selector33")]
    pub(crate) fn attach_trigger_action(
        &mut self,
        token: LaunchToken,
        action: crate::wyr1b_native::E8RecoveryAction,
    ) -> Result<(), LaunchTransactionError> {
        let slot = self.slot_mut(token)?;
        if slot.trigger_action.is_some() {
            return Err(LaunchTransactionError::ResourceIdentity);
        }
        slot.trigger_action = Some(action);
        Ok(())
    }

    #[cfg(feature = "wyr1e8-selector33")]
    pub(crate) fn trigger_action(
        &self,
        token: LaunchToken,
    ) -> Result<Option<crate::wyr1b_native::E8RecoveryAction>, LaunchTransactionError> {
        self.slot(token).map(|slot| slot.trigger_action)
    }

    pub(crate) fn arm_ready_deadline(
        &mut self,
        token: LaunchToken,
        deadline: DwDeadline,
    ) -> Result<(), LaunchTransactionError> {
        let slot = self.slot_mut(token)?;
        slot.ready_deadline = Some(deadline);
        Ok(())
    }

    pub(crate) fn ready_deadline(
        &self,
        token: LaunchToken,
    ) -> Result<Option<DwDeadline>, LaunchTransactionError> {
        self.slot(token).map(|slot| slot.ready_deadline)
    }

    /// Fixes the disposition. The first failure wins: a cleanup error that
    /// happens while reporting a loader error must not relabel the reply.
    pub(crate) fn fail(
        &mut self,
        token: LaunchToken,
        failure: LaunchFailure,
    ) -> Result<LaunchFailure, LaunchTransactionError> {
        if !(MIN_ERROR_CODE..=MAX_ERROR_CODE).contains(&failure.code) {
            return Err(LaunchTransactionError::ErrorCode);
        }
        let slot = self.slot_mut(token)?;
        match slot.failure.as_mut() {
            Some(existing) => {
                existing.cleanup_failed |= failure.cleanup_failed;
                Ok(*existing)
            }
            None => {
                slot.failure = Some(failure);
                Ok(failure)
            }
        }
    }

    pub(crate) fn failure(
        &self,
        token: LaunchToken,
    ) -> Result<Option<LaunchFailure>, LaunchTransactionError> {
        self.slot(token).map(|slot| slot.failure)
    }

    /// The open transaction for one session, if it has one.
    pub(crate) fn session_transaction(&self, grant: EndpointGrant) -> Option<LaunchToken> {
        self.slots
            .iter()
            .enumerate()
            .find_map(|(index, slot)| match slot {
                Some(slot) if slot.open && slot.grant == grant => Some(LaunchToken {
                    slot: index,
                    generation: slot.generation,
                }),
                _ => None,
            })
    }

    /// The first transaction at [`LaunchStage::AwaitingReady`] at or after
    /// `start`, wrapping once. Callers advance `start` past the slot they were
    /// handed so a child that never answers cannot starve its neighbours.
    pub(crate) fn awaiting_ready_from(&self, start: usize) -> Option<LaunchToken> {
        let start = start.checked_rem(LAUNCH_TRANSACTION_SLOTS).unwrap_or(0);
        (0..LAUNCH_TRANSACTION_SLOTS).find_map(|offset| {
            let index = start
                .wrapping_add(offset)
                .checked_rem(LAUNCH_TRANSACTION_SLOTS)?;
            match self.slots.get(index)?.as_ref() {
                Some(slot) if slot.open && slot.stage == LaunchStage::AwaitingReady => {
                    Some(LaunchToken {
                        slot: index,
                        generation: slot.generation,
                    })
                }
                _ => None,
            }
        })
    }

    /// The open transaction that owns one job, if any still does.
    pub(crate) fn job_transaction(&self, job_id: u64) -> Option<LaunchToken> {
        if job_id == 0 {
            return None;
        }
        self.slots
            .iter()
            .enumerate()
            .find_map(|(index, slot)| match slot {
                Some(slot) if slot.open && slot.job_id == job_id => Some(LaunchToken {
                    slot: index,
                    generation: slot.generation,
                }),
                _ => None,
            })
    }

    pub(crate) fn open_count(&self) -> usize {
        self.slots.iter().flatten().filter(|slot| slot.open).count()
    }

    /// Frees a finished slot. Refuses while it still owns handles, and refuses
    /// before `Complete`, so every transaction leaves by the same door.
    pub(crate) fn close(&mut self, token: LaunchToken) -> Result<u64, LaunchTransactionError> {
        let slot = self.slot(token)?;
        if slot.stage != LaunchStage::Complete {
            return Err(LaunchTransactionError::Incomplete);
        }
        if slot.resources.is_some() {
            return Err(LaunchTransactionError::ResourcesHeld);
        }
        let generation = slot.generation;
        let job_id = slot.job_id;
        self.slots[token.slot] = None;
        if generation == u64::MAX {
            self.retired[token.slot] = true;
        }
        Ok(job_id)
    }
}

#[cfg(test)]
#[path = "launch_transaction/tests.rs"]
mod tests;
