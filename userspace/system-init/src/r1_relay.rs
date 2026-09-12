//! Reset card R1's evidence relay.
//!
//! The probe is a dynamically launched child and holds no evidence authority.
//! Permanent init does: it observes the probe's `R1SP` records on the probe's
//! own bootstrap channel and submits them through the selector-private evidence
//! syscall. Custody therefore comes from *where* a record arrived, not from
//! anything inside it, which is the property that keeps a launched child from
//! becoming the reporter — the wyr1b-gate arrangement exactly.
//!
//! This module is the decision half and makes no syscall, so every refusal is
//! host testable. What it adds over the kernel collector is the one check the
//! kernel cannot make: the kernel knows the build nonce, but only init knows
//! which plan it actually launched, so only init can refuse a record whose
//! topology fields describe a run that did not happen.

use wyrmroot_runtime::NativeError;

use wyrmroot_r1_saturation::ProbePlan;
use wyrmroot_r1_saturation::record::{
    self, BYTES as RECORD_BYTES, Header, KIND_TERMINAL, parse_header,
};

/// The record size the scenario encodes and the size the evidence syscall
/// accepts are defined in different crates; a drift would be discovered as a
/// run-time rejection of every record, so it fails the build instead.
#[cfg(feature = "r1-selector34")]
const _: () = assert!(RECORD_BYTES == wyrmroot_runtime::R1_EVIDENCE_RECORD_BYTES);

/// Matches `R1_EVIDENCE_RECORD_CAPACITY` in the kernel collector. Init stops at
/// the same bound so an over-talkative probe is refused here rather than
/// discovered when the collector is already full.
pub const RELAY_CAPACITY: usize = 64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RelayAction {
    /// Submit the record and keep listening.
    Submit,
    /// Submit the record; it is the terminal one, and the kernel's handling of
    /// it flushes the transcript and completes the run. Nothing follows it.
    SubmitTerminal,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RelayError {
    /// The datagram was not exactly one record, or its header was malformed.
    Malformed(record::HeaderError),
    /// A record arrived carrying handles. A saturation report needs none, and
    /// forwarding one would move a capability on a probe's say-so.
    UnexpectedHandles,
    /// The topology fields disagree with the plan init launched.
    WrongTopology { online_cpus: u32, hog_count: u32 },
    /// Sequence numbers must be consecutive from one; the collector requires it
    /// and a gap means a record was lost rather than never sent.
    OutOfOrder { expected: u64, observed: u64 },
    /// A record arrived after the terminal one.
    AfterTerminal,
    /// More records than the collector can hold.
    Full,
}

/// One probe's relay. Bound to a plan at construction, so the plan cannot be
/// adopted from the first record that happens to arrive.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct R1Relay {
    plan: ProbePlan,
    submitted: usize,
    sequence: u64,
    terminal_seen: bool,
}

impl R1Relay {
    pub const fn new(plan: ProbePlan) -> Self {
        Self {
            plan,
            submitted: 0,
            sequence: 0,
            terminal_seen: false,
        }
    }

    pub const fn submitted(&self) -> usize {
        self.submitted
    }

    pub const fn terminal_seen(&self) -> bool {
        self.terminal_seen
    }

    /// A run whose terminal record never arrived is not a run that passed. The
    /// caller uses this to decide whether a probe that exited was actually
    /// reporting, rather than inferring completion from the child's exit code.
    pub const fn complete(&self) -> bool {
        self.terminal_seen
    }

    /// Decides what to do with one datagram received on the probe's channel,
    /// without recording anything.
    ///
    /// Separating the decision from the state change is what makes the relay
    /// atomic across a failed submission: a record the kernel refused must not
    /// consume its sequence, or every later record would be refused too and a
    /// diagnostic run would lose its transcript to a transport hiccup.
    ///
    /// `handles` is the received handle count, checked here rather than by the
    /// caller so no call site can forget it.
    pub fn check(&self, bytes: &[u8], handles: usize) -> Result<RelayAction, RelayError> {
        if handles != 0 {
            return Err(RelayError::UnexpectedHandles);
        }
        if self.terminal_seen {
            return Err(RelayError::AfterTerminal);
        }
        let header = validate(bytes, self.plan)?;
        let expected = self.sequence + 1;
        if header.sequence != expected {
            return Err(RelayError::OutOfOrder {
                expected,
                observed: header.sequence,
            });
        }
        if self.submitted >= RELAY_CAPACITY {
            return Err(RelayError::Full);
        }
        if header.kind == KIND_TERMINAL {
            return Ok(RelayAction::SubmitTerminal);
        }
        Ok(RelayAction::Submit)
    }

    /// Records a record that was actually submitted.
    pub fn commit(&mut self, action: RelayAction) {
        self.sequence += 1;
        self.submitted += 1;
        if action == RelayAction::SubmitTerminal {
            self.terminal_seen = true;
        }
    }

    /// Decide and record in one step, for callers with no submission to fail.
    pub fn accept(&mut self, bytes: &[u8], handles: usize) -> Result<RelayAction, RelayError> {
        let action = self.check(bytes, handles)?;
        self.commit(action);
        Ok(action)
    }
}

/// The evidence syscall, as the relay needs it. A trait so the decision path is
/// host testable against a capturing double, matching how every other selector's
/// init-side evidence seam is tested.
pub trait R1EvidenceSink {
    fn submit_r1_evidence(&mut self, record: &[u8; RECORD_BYTES]) -> Result<(), NativeError>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RelayFailure {
    /// The record was inadmissible and was never submitted.
    Refused(RelayError),
    /// The record was admissible and the kernel refused it. The relay is
    /// unchanged, so the caller may retry or report without corrupting the
    /// sequence.
    Rejected(NativeError),
}

/// Relays exactly one datagram: decide, submit, then record.
pub fn relay_one<S: R1EvidenceSink>(
    relay: &mut R1Relay,
    sink: &mut S,
    bytes: &[u8],
    handles: usize,
) -> Result<RelayAction, RelayFailure> {
    let action = relay.check(bytes, handles).map_err(RelayFailure::Refused)?;
    let mut record = [0_u8; RECORD_BYTES];
    record.copy_from_slice(bytes);
    sink.submit_r1_evidence(&record)
        .map_err(RelayFailure::Rejected)?;
    relay.commit(action);
    Ok(action)
}

fn validate(bytes: &[u8], plan: ProbePlan) -> Result<Header, RelayError> {
    if bytes.len() != RECORD_BYTES {
        return Err(RelayError::Malformed(record::HeaderError::WrongLength));
    }
    let header = parse_header(bytes).map_err(RelayError::Malformed)?;
    if header.online_cpus as usize != plan.online_cpus
        || header.hog_count as usize != plan.hog_count
    {
        return Err(RelayError::WrongTopology {
            online_cpus: header.online_cpus,
            hog_count: header.hog_count,
        });
    }
    Ok(header)
}

#[cfg(test)]
mod tests;
