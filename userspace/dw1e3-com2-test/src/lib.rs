//! Byte-defined selector-31 raw COM2 challenge and controller handshake.

#![no_std]
#![forbid(unsafe_code)]

// The selector feature supplies the native actor's dependencies. Cargo also
// enables it while checking this companion protocol library, where the actor-
// only crates are intentionally not referenced otherwise.
#[cfg(feature = "native-probe")]
use deepwyrm_syscall as _;
#[cfg(feature = "native-probe")]
use wyrmroot_device_proto as _;
#[cfg(feature = "native-probe")]
use wyrmroot_loader as _;
#[cfg(feature = "native-probe")]
use wyrmroot_registry_proto as _;
#[cfg(feature = "native-probe")]
use wyrmroot_runtime as _;
#[cfg(feature = "native-probe")]
use wyrmroot_stream_proto as _;

pub const CONTROL_MAGIC: [u8; 4] = *b"WRE3";
pub const CONTROL_VERSION: u16 = 1;
pub const CONTROL_BYTES: usize = 80;
pub const CHALLENGE_BYTES: usize = 24;
pub const RESPONSE_BYTES: usize = CHALLENGE_BYTES;
pub const CLIENT_TRANSACTION_ID: u64 = 1;
pub const CONNECT_TRANSACTION_ID: u64 = 2;
pub const CHALLENGE_GENERATION: u64 = 1;
pub const CHALLENGE2_GENERATION: u64 = 2;
pub const DEVMGR_CONFIG_BYTES: usize = 48;
pub const DEVMGR_CONFIG_MAGIC: [u8; 4] = *b"WDE3";

/// Selector-31 product-side ownership model for the U1 -> U2 replacement
/// leg.  This intentionally contains no kernel-private action numbers: the
/// kernel observes the separately authenticated bind/arm/report calls, while
/// Wyrmroot owns the causal lifetime facts needed before it makes those calls.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DriverIdentity {
    pub attempt_generation: u64,
    pub publication_generation: u64,
    pub stream_generation: u64,
    pub challenge_generation: u64,
}

/// The selector reporter is a separately launched probe process.  Its
/// generation is deliberately independent of the UART attempt and stream.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProbeIdentity {
    pub process_generation: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LifecycleError {
    ZeroIdentity,
    WrongOrder,
    NotFresh,
    StaleIdentity,
    BarrierTimedOut,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LifecycleState {
    Challenge1Active,
    Challenge1Responded,
    TransportEmpty,
    TransportEmptyTimedOut,
    U1PeerClosed,
    U1Reaped,
    U1EndpointsReleased,
    U1ProbeReaped,
    Challenge2Active,
    Challenge2Responded,
    Challenge2TransportEmpty,
    TerminalClaimed,
    StaleU1Reported,
    Complete,
}

/// Maximum timer-paced `LSR.TEMT` polls after final FIFO fill and a successful
/// Interrupt acknowledgement. The first exact `TEMT=1` crosses the barrier;
/// false observations retain state until this bounded budget expires.
pub const TRANSPORT_EMPTY_TEMT_MAX_POLLS: u8 = 3;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Selector31Lifecycle {
    state: LifecycleState,
    u1: DriverIdentity,
    u1_probe: ProbeIdentity,
    u2: Option<DriverIdentity>,
    u2_probe: Option<ProbeIdentity>,
    transport_empty_armed: bool,
    temt_polls: u8,
    challenge2_transport_empty_armed: bool,
    challenge2_temt_polls: u8,
    u2_probe_reaped_successfully: bool,
    queued_data_observed: bool,
    u1_driver_endpoint_released: bool,
    u1_client_endpoint_released: bool,
}

impl Selector31Lifecycle {
    pub const fn new(u1: DriverIdentity, u1_probe: ProbeIdentity) -> Result<Self, LifecycleError> {
        if !identity_is_nonzero(u1) || u1_probe.process_generation == 0 {
            return Err(LifecycleError::ZeroIdentity);
        }
        Ok(Self {
            state: LifecycleState::Challenge1Active,
            u1,
            u1_probe,
            u2: None,
            u2_probe: None,
            transport_empty_armed: false,
            temt_polls: 0,
            challenge2_transport_empty_armed: false,
            challenge2_temt_polls: 0,
            u2_probe_reaped_successfully: false,
            queued_data_observed: false,
            u1_driver_endpoint_released: false,
            u1_client_endpoint_released: false,
        })
    }

    pub fn challenge1_responded(&mut self) -> Result<(), LifecycleError> {
        advance(
            &mut self.state,
            LifecycleState::Challenge1Active,
            LifecycleState::Challenge1Responded,
        )
    }

    /// The final FIFO fill and successful Interrupt acknowledgement must both
    /// be proven before the bounded timer-paced TEMT barrier starts.
    pub fn begin_transport_empty_barrier(
        &mut self,
        final_fifo_fill: bool,
        interrupt_ack_succeeded: bool,
    ) -> Result<(), LifecycleError> {
        self.begin_transport_empty_barrier_after_input(
            final_fifo_fill,
            interrupt_ack_succeeded,
            true,
        )
    }

    /// The final post-ack receive must prove that no later WRST DATA is still
    /// queued before TEMT can authorize closing the stream.
    pub fn begin_transport_empty_barrier_after_input(
        &mut self,
        final_fifo_fill: bool,
        interrupt_ack_succeeded: bool,
        response_input_drained: bool,
    ) -> Result<(), LifecycleError> {
        if self.state != LifecycleState::Challenge1Responded
            || !final_fifo_fill
            || !interrupt_ack_succeeded
            || !response_input_drained
        {
            return Err(LifecycleError::WrongOrder);
        }
        self.transport_empty_armed = true;
        Ok(())
    }

    /// One timer-paced `LSR.TEMT` poll. A false result keeps the barrier
    /// pending; the first true result crosses it. Exhausting the fixed poll
    /// budget fails the selector lifecycle rather than assuming the UART is
    /// empty.
    pub fn timer_paced_temt_poll(&mut self, temt: bool) -> Result<(), LifecycleError> {
        if self.state != LifecycleState::Challenge1Responded || !self.transport_empty_armed {
            return Err(LifecycleError::WrongOrder);
        }
        self.temt_polls = self
            .temt_polls
            .checked_add(1)
            .ok_or(LifecycleError::BarrierTimedOut)?;
        if temt {
            self.state = LifecycleState::TransportEmpty;
            return Ok(());
        }
        if self.temt_polls == TRANSPORT_EMPTY_TEMT_MAX_POLLS {
            self.state = LifecycleState::TransportEmptyTimedOut;
            return Err(LifecycleError::BarrierTimedOut);
        }
        Ok(())
    }

    pub fn queued_data_before_peer_close(&mut self) -> Result<(), LifecycleError> {
        if self.state != LifecycleState::TransportEmpty {
            return Err(LifecycleError::WrongOrder);
        }
        self.queued_data_observed = true;
        Ok(())
    }

    pub fn u1_peer_closed(&mut self) -> Result<(), LifecycleError> {
        if self.state != LifecycleState::TransportEmpty || !self.queued_data_observed {
            return Err(LifecycleError::WrongOrder);
        }
        self.state = LifecycleState::U1PeerClosed;
        Ok(())
    }

    pub fn u1_reaped(&mut self) -> Result<(), LifecycleError> {
        self.u1_finalize_exit(true)
    }

    /// Models the controller's exact post-FinalizeRetire Process exit join.
    /// A nonzero/crashed exit or a zero exit before the ordered peer-close
    /// proof cannot clear U1 state or admit U2.
    pub fn u1_finalize_exit(&mut self, successful_exit_record: bool) -> Result<(), LifecycleError> {
        if !successful_exit_record {
            return Err(LifecycleError::WrongOrder);
        }
        advance(
            &mut self.state,
            LifecycleState::U1PeerClosed,
            LifecycleState::U1Reaped,
        )
    }

    pub fn u1_endpoint_released(&mut self, driver_endpoint: bool) -> Result<(), LifecycleError> {
        if self.state != LifecycleState::U1Reaped
            && self.state != LifecycleState::U1EndpointsReleased
        {
            return Err(LifecycleError::WrongOrder);
        }
        if driver_endpoint {
            self.u1_driver_endpoint_released = true;
        } else {
            self.u1_client_endpoint_released = true;
        }
        if self.u1_driver_endpoint_released && self.u1_client_endpoint_released {
            self.state = LifecycleState::U1EndpointsReleased;
        }
        Ok(())
    }

    /// The U1 probe remains live only to report the ordered peer close.  It
    /// must then be terminated/reaped; action 2 binds a fresh U2 reporter.
    pub fn u1_probe_reaped(&mut self, probe: ProbeIdentity) -> Result<(), LifecycleError> {
        if self.state != LifecycleState::U1EndpointsReleased || probe != self.u1_probe {
            return Err(LifecycleError::WrongOrder);
        }
        self.state = LifecycleState::U1ProbeReaped;
        Ok(())
    }

    pub fn admit_u2(
        &mut self,
        u2: DriverIdentity,
        u2_probe: ProbeIdentity,
    ) -> Result<(), LifecycleError> {
        if self.state != LifecycleState::U1ProbeReaped {
            return Err(LifecycleError::WrongOrder);
        }
        if !identity_is_nonzero(u2) || u2_probe.process_generation == 0 {
            return Err(LifecycleError::ZeroIdentity);
        }
        if u2.attempt_generation <= self.u1.attempt_generation
            || u2.publication_generation <= self.u1.publication_generation
            || u2.stream_generation <= self.u1.stream_generation
            || u2.challenge_generation <= self.u1.challenge_generation
            || u2_probe == self.u1_probe
        {
            return Err(LifecycleError::NotFresh);
        }
        self.u2 = Some(u2);
        self.u2_probe = Some(u2_probe);
        self.u2_probe_reaped_successfully = false;
        self.state = LifecycleState::Challenge2Active;
        Ok(())
    }

    pub fn challenge2_responded(&mut self) -> Result<(), LifecycleError> {
        advance(
            &mut self.state,
            LifecycleState::Challenge2Active,
            LifecycleState::Challenge2Responded,
        )
    }

    /// U2 has a distinct final-byte transport barrier. A response report by
    /// itself, THRE alone, or an unsuccessful ack can never authorize the
    /// controller-only terminal claim.
    pub fn begin_challenge2_transport_empty_barrier(
        &mut self,
        identity: DriverIdentity,
        final_fifo_fill: bool,
        interrupt_ack_succeeded: bool,
    ) -> Result<(), LifecycleError> {
        if self.state != LifecycleState::Challenge2Responded
            || self.u2 != Some(identity)
            || !final_fifo_fill
            || !interrupt_ack_succeeded
        {
            return Err(LifecycleError::WrongOrder);
        }
        self.challenge2_transport_empty_armed = true;
        Ok(())
    }

    /// One Timer-paced U2 `LSR.TEMT` observation. The first true sample is
    /// sufficient; false samples retain state only within the fixed bound.
    pub fn timer_paced_challenge2_temt_poll(
        &mut self,
        identity: DriverIdentity,
        temt: bool,
    ) -> Result<(), LifecycleError> {
        if self.state != LifecycleState::Challenge2Responded
            || self.u2 != Some(identity)
            || !self.challenge2_transport_empty_armed
        {
            return Err(LifecycleError::WrongOrder);
        }
        self.challenge2_temt_polls = self
            .challenge2_temt_polls
            .checked_add(1)
            .ok_or(LifecycleError::BarrierTimedOut)?;
        if temt {
            self.state = LifecycleState::Challenge2TransportEmpty;
            return Ok(());
        }
        if self.challenge2_temt_polls == TRANSPORT_EMPTY_TEMT_MAX_POLLS {
            return Err(LifecycleError::BarrierTimedOut);
        }
        Ok(())
    }

    /// The U2 reporter may leave only after committing its response. Its
    /// exact normal-zero reap is a distinct controller join: a TEMT wake
    /// must not claim the terminal while a raced nonzero probe exit remains
    /// unclassified.
    pub fn u2_probe_reaped(
        &mut self,
        probe: ProbeIdentity,
        successful_exit_record: bool,
    ) -> Result<(), LifecycleError> {
        if !successful_exit_record
            || self.u2_probe != Some(probe)
            || !matches!(
                self.state,
                LifecycleState::Challenge2Responded | LifecycleState::Challenge2TransportEmpty
            )
        {
            return Err(LifecycleError::WrongOrder);
        }
        self.u2_probe_reaped_successfully = true;
        Ok(())
    }

    /// Represents only the controller's existing action-4 terminal claim.
    /// The probe cannot make this transition and there is no fifth action.
    pub fn controller_terminal_claim(
        &mut self,
        identity: DriverIdentity,
    ) -> Result<(), LifecycleError> {
        if self.state != LifecycleState::Challenge2TransportEmpty
            || self.u2 != Some(identity)
            || !self.u2_probe_reaped_successfully
        {
            return Err(LifecycleError::WrongOrder);
        }
        self.state = LifecycleState::TerminalClaimed;
        Ok(())
    }

    /// Accepts the kernel-owned saved-U1 replay observation after challenge 2.
    /// This is not a Wyrmroot raw report or a private action: the kernel must
    /// derive rejection with zero wakes from its retained real U1 delivery.
    pub fn observe_kernel_stale_u1_rejection(
        &mut self,
        identity: DriverIdentity,
    ) -> Result<(), LifecycleError> {
        if self.state != LifecycleState::TerminalClaimed {
            return Err(LifecycleError::WrongOrder);
        }
        if identity != self.u1 {
            return Err(LifecycleError::StaleIdentity);
        }
        self.state = LifecycleState::StaleU1Reported;
        Ok(())
    }

    pub fn finish(&mut self) -> Result<(), LifecycleError> {
        advance(
            &mut self.state,
            LifecycleState::StaleU1Reported,
            LifecycleState::Complete,
        )
    }

    #[must_use]
    pub fn complete(&self) -> bool {
        self.state == LifecycleState::Complete
    }
}

const fn identity_is_nonzero(identity: DriverIdentity) -> bool {
    identity.attempt_generation != 0
        && identity.publication_generation != 0
        && identity.stream_generation != 0
        && identity.challenge_generation != 0
}

fn advance(
    state: &mut LifecycleState,
    expected: LifecycleState,
    next: LifecycleState,
) -> Result<(), LifecycleError> {
    if *state != expected {
        return Err(LifecycleError::WrongOrder);
    }
    *state = next;
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DevmgrConfig {
    pub nonce: u64,
    pub publication_generation: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DevmgrReady {
    pub nonce: u64,
    pub publication_generation: u64,
}

/// UART-owned proof forwarded by devmgr without interpretation. It is a
/// selector-private Wyrmroot control fact, not a DWE3 raw report and never a
/// COM2 record. The controller uses it only to join the exact U1 response to
/// the independent terminate/reap authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransportEmptyFact {
    pub nonce: u64,
    pub attempt_generation: u64,
    pub publication_generation: u64,
    pub stream_generation: u64,
    pub challenge_generation: u64,
    pub response_length: u64,
    pub response_hash: u64,
}

/// Controller-issued commitment for the current exact driver-control endpoint.
/// It crosses no raw serial transport and prevents a driver from inferring Q
/// from its independently allocated attempt generation T.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ChallengeBinding {
    pub nonce: u64,
    pub attempt_generation: u64,
    pub publication_generation: u64,
    pub stream_generation: u64,
    pub challenge_generation: u64,
    pub expected_length: u64,
    pub expected_hash: u64,
}

pub const TRANSPORT_EMPTY_FACT_BYTES: usize = 80;

pub fn encode_transport_empty_fact(
    fact: TransportEmptyFact,
    output: &mut [u8],
) -> Result<(), ProtocolError> {
    if output.len() != TRANSPORT_EMPTY_FACT_BYTES {
        return Err(ProtocolError::WrongSize);
    }
    validate_transport_empty_fact(fact)?;
    output.fill(0);
    output[..4].copy_from_slice(&DEVMGR_CONFIG_MAGIC);
    put16(output, 4, CONTROL_VERSION);
    put16(output, 6, 3);
    put32(output, 8, TRANSPORT_EMPTY_FACT_BYTES as u32);
    put64(output, 16, fact.nonce);
    put64(output, 24, fact.attempt_generation);
    put64(output, 32, fact.publication_generation);
    put64(output, 40, fact.stream_generation);
    put64(output, 48, fact.challenge_generation);
    put64(output, 56, fact.response_length);
    put64(output, 64, fact.response_hash);
    Ok(())
}

pub fn parse_transport_empty_fact(bytes: &[u8]) -> Result<TransportEmptyFact, ProtocolError> {
    if bytes.len() != TRANSPORT_EMPTY_FACT_BYTES
        || get32(bytes, 8) != TRANSPORT_EMPTY_FACT_BYTES as u32
    {
        return Err(ProtocolError::WrongSize);
    }
    if bytes[..4] != DEVMGR_CONFIG_MAGIC {
        return Err(ProtocolError::WrongMagic);
    }
    if get16(bytes, 4) != CONTROL_VERSION {
        return Err(ProtocolError::WrongVersion);
    }
    if get16(bytes, 6) != 3 {
        return Err(ProtocolError::WrongType);
    }
    if get32(bytes, 12) != 0 || bytes[72..].iter().any(|byte| *byte != 0) {
        return Err(ProtocolError::NonzeroReserved);
    }
    let fact = TransportEmptyFact {
        nonce: get64(bytes, 16),
        attempt_generation: get64(bytes, 24),
        publication_generation: get64(bytes, 32),
        stream_generation: get64(bytes, 40),
        challenge_generation: get64(bytes, 48),
        response_length: get64(bytes, 56),
        response_hash: get64(bytes, 64),
    };
    validate_transport_empty_fact(fact)?;
    Ok(fact)
}

pub fn encode_challenge_binding(
    binding: ChallengeBinding,
    output: &mut [u8],
) -> Result<(), ProtocolError> {
    encode_wde3_tuple(4, binding, output)
}

pub fn parse_challenge_binding(bytes: &[u8]) -> Result<ChallengeBinding, ProtocolError> {
    parse_wde3_tuple(4, bytes)
}

pub fn encode_binding_ready(
    binding: ChallengeBinding,
    output: &mut [u8],
) -> Result<(), ProtocolError> {
    encode_wde3_tuple(5, binding, output)
}

pub fn parse_binding_ready(bytes: &[u8]) -> Result<ChallengeBinding, ProtocolError> {
    parse_wde3_tuple(5, bytes)
}

pub fn encode_begin_retire(
    binding: ChallengeBinding,
    output: &mut [u8],
) -> Result<(), ProtocolError> {
    encode_wde3_tuple(6, binding, output)
}

pub fn parse_begin_retire(bytes: &[u8]) -> Result<ChallengeBinding, ProtocolError> {
    parse_wde3_tuple(6, bytes)
}

pub fn encode_finalize_retire(
    binding: ChallengeBinding,
    output: &mut [u8],
) -> Result<(), ProtocolError> {
    encode_wde3_tuple(7, binding, output)
}

pub fn parse_finalize_retire(bytes: &[u8]) -> Result<ChallengeBinding, ProtocolError> {
    parse_wde3_tuple(7, bytes)
}

pub fn encode_retire_stage1_ready(
    binding: ChallengeBinding,
    output: &mut [u8],
) -> Result<(), ProtocolError> {
    encode_wde3_tuple(8, binding, output)
}

pub fn parse_retire_stage1_ready(bytes: &[u8]) -> Result<ChallengeBinding, ProtocolError> {
    parse_wde3_tuple(8, bytes)
}

fn encode_wde3_tuple(
    message_type: u16,
    binding: ChallengeBinding,
    output: &mut [u8],
) -> Result<(), ProtocolError> {
    if output.len() != TRANSPORT_EMPTY_FACT_BYTES {
        return Err(ProtocolError::WrongSize);
    }
    validate_challenge_binding(binding)?;
    output.fill(0);
    output[..4].copy_from_slice(&DEVMGR_CONFIG_MAGIC);
    put16(output, 4, CONTROL_VERSION);
    put16(output, 6, message_type);
    put32(output, 8, TRANSPORT_EMPTY_FACT_BYTES as u32);
    put64(output, 16, binding.nonce);
    put64(output, 24, binding.attempt_generation);
    put64(output, 32, binding.publication_generation);
    put64(output, 40, binding.stream_generation);
    put64(output, 48, binding.challenge_generation);
    put64(output, 56, binding.expected_length);
    put64(output, 64, binding.expected_hash);
    Ok(())
}

fn parse_wde3_tuple(message_type: u16, bytes: &[u8]) -> Result<ChallengeBinding, ProtocolError> {
    if bytes.len() != TRANSPORT_EMPTY_FACT_BYTES
        || get32(bytes, 8) != TRANSPORT_EMPTY_FACT_BYTES as u32
    {
        return Err(ProtocolError::WrongSize);
    }
    if bytes[..4] != DEVMGR_CONFIG_MAGIC {
        return Err(ProtocolError::WrongMagic);
    }
    if get16(bytes, 4) != CONTROL_VERSION {
        return Err(ProtocolError::WrongVersion);
    }
    if get16(bytes, 6) != message_type {
        return Err(ProtocolError::WrongType);
    }
    if get32(bytes, 12) != 0 || bytes[72..].iter().any(|byte| *byte != 0) {
        return Err(ProtocolError::NonzeroReserved);
    }
    let binding = ChallengeBinding {
        nonce: get64(bytes, 16),
        attempt_generation: get64(bytes, 24),
        publication_generation: get64(bytes, 32),
        stream_generation: get64(bytes, 40),
        challenge_generation: get64(bytes, 48),
        expected_length: get64(bytes, 56),
        expected_hash: get64(bytes, 64),
    };
    validate_challenge_binding(binding)?;
    Ok(binding)
}

fn validate_challenge_binding(binding: ChallengeBinding) -> Result<(), ProtocolError> {
    if [
        binding.nonce,
        binding.attempt_generation,
        binding.publication_generation,
        binding.stream_generation,
        binding.challenge_generation,
        binding.expected_hash,
    ]
    .into_iter()
    .any(|value| value == 0)
    {
        return Err(ProtocolError::ZeroIdentity);
    }
    if binding.expected_length != CHALLENGE_BYTES as u64 {
        return Err(ProtocolError::WrongLength);
    }
    Ok(())
}

fn validate_transport_empty_fact(fact: TransportEmptyFact) -> Result<(), ProtocolError> {
    if [
        fact.nonce,
        fact.attempt_generation,
        fact.publication_generation,
        fact.stream_generation,
        fact.challenge_generation,
        fact.response_hash,
    ]
    .into_iter()
    .any(|value| value == 0)
    {
        return Err(ProtocolError::ZeroIdentity);
    }
    if fact.response_length != RESPONSE_BYTES as u64 {
        return Err(ProtocolError::WrongLength);
    }
    Ok(())
}

pub fn encode_devmgr_config(config: DevmgrConfig, output: &mut [u8]) -> Result<(), ProtocolError> {
    encode_devmgr_record(1, config.nonce, config.publication_generation, output)
}

pub fn parse_devmgr_config(bytes: &[u8]) -> Result<DevmgrConfig, ProtocolError> {
    let (nonce, publication_generation) = parse_devmgr_record(bytes, 1)?;
    Ok(DevmgrConfig {
        nonce,
        publication_generation,
    })
}

pub fn encode_devmgr_ready(ready: DevmgrReady, output: &mut [u8]) -> Result<(), ProtocolError> {
    encode_devmgr_record(2, ready.nonce, ready.publication_generation, output)
}

pub fn parse_devmgr_ready(bytes: &[u8]) -> Result<DevmgrReady, ProtocolError> {
    let (nonce, publication_generation) = parse_devmgr_record(bytes, 2)?;
    Ok(DevmgrReady {
        nonce,
        publication_generation,
    })
}

fn encode_devmgr_record(
    message_type: u16,
    nonce: u64,
    publication_generation: u64,
    output: &mut [u8],
) -> Result<(), ProtocolError> {
    if output.len() != DEVMGR_CONFIG_BYTES {
        return Err(ProtocolError::WrongSize);
    }
    if nonce == 0 || publication_generation == 0 {
        return Err(ProtocolError::ZeroIdentity);
    }
    output.fill(0);
    output[..4].copy_from_slice(&DEVMGR_CONFIG_MAGIC);
    put16(output, 4, CONTROL_VERSION);
    put16(output, 6, message_type);
    put32(output, 8, DEVMGR_CONFIG_BYTES as u32);
    put64(output, 16, nonce);
    put64(output, 24, publication_generation);
    Ok(())
}

fn parse_devmgr_record(bytes: &[u8], expected_type: u16) -> Result<(u64, u64), ProtocolError> {
    if bytes.len() != DEVMGR_CONFIG_BYTES || get32(bytes, 8) != DEVMGR_CONFIG_BYTES as u32 {
        return Err(ProtocolError::WrongSize);
    }
    if bytes[..4] != DEVMGR_CONFIG_MAGIC {
        return Err(ProtocolError::WrongMagic);
    }
    if get16(bytes, 4) != CONTROL_VERSION {
        return Err(ProtocolError::WrongVersion);
    }
    if get16(bytes, 6) != expected_type {
        return Err(ProtocolError::WrongType);
    }
    if get32(bytes, 12) != 0 || bytes[32..].iter().any(|byte| *byte != 0) {
        return Err(ProtocolError::NonzeroReserved);
    }
    let nonce = get64(bytes, 16);
    let publication_generation = get64(bytes, 24);
    if nonce == 0 || publication_generation == 0 {
        return Err(ProtocolError::ZeroIdentity);
    }
    Ok((nonce, publication_generation))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ControllerMessage {
    Configure {
        nonce: u64,
        publication_generation: u64,
        challenge_generation: u64,
        expected_length: u64,
        expected_hash: u64,
    },
    Attached {
        nonce: u64,
        publication_generation: u64,
        stream_generation: u64,
        challenge_generation: u64,
    },
    ArmPermit {
        nonce: u64,
        publication_generation: u64,
        stream_generation: u64,
        challenge_generation: u64,
        expected_length: u64,
        expected_hash: u64,
    },
    /// Probe-owned evidence that the exact response was committed to the raw
    /// stream. This is Wyrmroot control correlation, not a private kernel
    /// action or a COM2 control record.
    ResponseCommitted {
        nonce: u64,
        publication_generation: u64,
        stream_generation: u64,
        challenge_generation: u64,
        response_length: u64,
        response_hash: u64,
    },
    /// The retained U1 probe has freshly observed its stream peer close only
    /// after queued input was drained. System-init owns the 0x0a raw report.
    StreamPeerClosed {
        nonce: u64,
        publication_generation: u64,
        stream_generation: u64,
        challenge_generation: u64,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProtocolError {
    WrongSize,
    WrongMagic,
    WrongVersion,
    WrongType,
    ZeroIdentity,
    WrongLength,
    NonzeroReserved,
}

pub fn encode(message: ControllerMessage, output: &mut [u8]) -> Result<(), ProtocolError> {
    if output.len() != CONTROL_BYTES {
        return Err(ProtocolError::WrongSize);
    }
    validate(message)?;
    output.fill(0);
    output[..4].copy_from_slice(&CONTROL_MAGIC);
    put16(output, 4, CONTROL_VERSION);
    put16(output, 6, message_type(message));
    put32(output, 8, CONTROL_BYTES as u32);
    match message {
        ControllerMessage::Configure {
            nonce,
            publication_generation,
            challenge_generation,
            expected_length,
            expected_hash,
        } => {
            put64(output, 16, nonce);
            put64(output, 24, publication_generation);
            put64(output, 40, challenge_generation);
            put64(output, 48, expected_length);
            put64(output, 56, expected_hash);
        }
        ControllerMessage::Attached {
            nonce,
            publication_generation,
            stream_generation,
            challenge_generation,
        } => {
            put64(output, 16, nonce);
            put64(output, 24, publication_generation);
            put64(output, 32, stream_generation);
            put64(output, 40, challenge_generation);
        }
        ControllerMessage::ArmPermit {
            nonce,
            publication_generation,
            stream_generation,
            challenge_generation,
            expected_length,
            expected_hash,
        } => {
            put64(output, 16, nonce);
            put64(output, 24, publication_generation);
            put64(output, 32, stream_generation);
            put64(output, 40, challenge_generation);
            put64(output, 48, expected_length);
            put64(output, 56, expected_hash);
        }
        ControllerMessage::ResponseCommitted {
            nonce,
            publication_generation,
            stream_generation,
            challenge_generation,
            response_length,
            response_hash,
        } => {
            put64(output, 16, nonce);
            put64(output, 24, publication_generation);
            put64(output, 32, stream_generation);
            put64(output, 40, challenge_generation);
            put64(output, 48, response_length);
            put64(output, 56, response_hash);
        }
        ControllerMessage::StreamPeerClosed {
            nonce,
            publication_generation,
            stream_generation,
            challenge_generation,
        } => {
            put64(output, 16, nonce);
            put64(output, 24, publication_generation);
            put64(output, 32, stream_generation);
            put64(output, 40, challenge_generation);
        }
    }
    Ok(())
}

pub fn parse(bytes: &[u8]) -> Result<ControllerMessage, ProtocolError> {
    if bytes.len() != CONTROL_BYTES || get32(bytes, 8) != CONTROL_BYTES as u32 {
        return Err(ProtocolError::WrongSize);
    }
    if bytes[..4] != CONTROL_MAGIC {
        return Err(ProtocolError::WrongMagic);
    }
    if get16(bytes, 4) != CONTROL_VERSION {
        return Err(ProtocolError::WrongVersion);
    }
    if get32(bytes, 12) != 0 || bytes[64..].iter().any(|byte| *byte != 0) {
        return Err(ProtocolError::NonzeroReserved);
    }
    let nonce = get64(bytes, 16);
    let publication_generation = get64(bytes, 24);
    let stream_generation = get64(bytes, 32);
    let challenge_generation = get64(bytes, 40);
    let expected_length = get64(bytes, 48);
    let expected_hash = get64(bytes, 56);
    let message = match get16(bytes, 6) {
        1 => {
            if stream_generation != 0 {
                return Err(ProtocolError::NonzeroReserved);
            }
            ControllerMessage::Configure {
                nonce,
                publication_generation,
                challenge_generation,
                expected_length,
                expected_hash,
            }
        }
        2 => {
            if expected_length != 0 || expected_hash != 0 {
                return Err(ProtocolError::NonzeroReserved);
            }
            ControllerMessage::Attached {
                nonce,
                publication_generation,
                stream_generation,
                challenge_generation,
            }
        }
        3 => ControllerMessage::ArmPermit {
            nonce,
            publication_generation,
            stream_generation,
            challenge_generation,
            expected_length,
            expected_hash,
        },
        4 => ControllerMessage::ResponseCommitted {
            nonce,
            publication_generation,
            stream_generation,
            challenge_generation,
            response_length: expected_length,
            response_hash: expected_hash,
        },
        5 => {
            if expected_length != 0 || expected_hash != 0 {
                return Err(ProtocolError::NonzeroReserved);
            }
            ControllerMessage::StreamPeerClosed {
                nonce,
                publication_generation,
                stream_generation,
                challenge_generation,
            }
        }
        _ => return Err(ProtocolError::WrongType),
    };
    validate(message)?;
    Ok(message)
}

fn validate(message: ControllerMessage) -> Result<(), ProtocolError> {
    let (nonce, publication, stream, challenge, length, hash) = match message {
        ControllerMessage::Configure {
            nonce,
            publication_generation,
            challenge_generation,
            expected_length,
            expected_hash,
        } => (
            nonce,
            publication_generation,
            1,
            challenge_generation,
            expected_length,
            expected_hash,
        ),
        ControllerMessage::Attached {
            nonce,
            publication_generation,
            stream_generation,
            challenge_generation,
        } => (
            nonce,
            publication_generation,
            stream_generation,
            challenge_generation,
            CHALLENGE_BYTES as u64,
            1,
        ),
        ControllerMessage::ArmPermit {
            nonce,
            publication_generation,
            stream_generation,
            challenge_generation,
            expected_length,
            expected_hash,
        } => (
            nonce,
            publication_generation,
            stream_generation,
            challenge_generation,
            expected_length,
            expected_hash,
        ),
        ControllerMessage::ResponseCommitted {
            nonce,
            publication_generation,
            stream_generation,
            challenge_generation,
            response_length,
            response_hash,
        } => (
            nonce,
            publication_generation,
            stream_generation,
            challenge_generation,
            response_length,
            response_hash,
        ),
        ControllerMessage::StreamPeerClosed {
            nonce,
            publication_generation,
            stream_generation,
            challenge_generation,
        } => (
            nonce,
            publication_generation,
            stream_generation,
            challenge_generation,
            CHALLENGE_BYTES as u64,
            1,
        ),
    };
    if [nonce, publication, stream, challenge, hash]
        .into_iter()
        .any(|value| value == 0)
    {
        return Err(ProtocolError::ZeroIdentity);
    }
    if length != CHALLENGE_BYTES as u64 {
        return Err(ProtocolError::WrongLength);
    }
    Ok(())
}

pub fn challenge(nonce: u64) -> [u8; CHALLENGE_BYTES] {
    challenge_for_generation(nonce, CHALLENGE_GENERATION)
}

/// Derives the raw binary-safe challenge from its frozen per-leg nonce. The
/// generation identifies lifecycle correlation only; it never rewrites raw
/// payload bytes, which must match the xtask freezer exactly.
pub fn challenge_for_generation(nonce: u64, _generation: u64) -> [u8; CHALLENGE_BYTES] {
    let challenge_nonce = nonce;
    let mut bytes = [0u8; CHALLENGE_BYTES];
    bytes[..8].copy_from_slice(&[0x0d, 0x0a, 0x00, 0x7f, b'D', b'W', b'1', b'E']);
    bytes[8..16].copy_from_slice(&challenge_nonce.to_le_bytes());
    bytes[16..24].copy_from_slice(&challenge_nonce.rotate_left(17).to_le_bytes());
    bytes
}

pub fn response(input: &[u8; CHALLENGE_BYTES]) -> [u8; RESPONSE_BYTES] {
    let mut output = [0u8; RESPONSE_BYTES];
    let mut index = 0;
    while index != input.len() {
        output[index] = input[input.len() - 1 - index] ^ (0xa5u8.wrapping_add(index as u8));
        index += 1;
    }
    output
}

/// Challenge bytes are committed by the controller's exact length/hash tuple.
/// In E3B the build/evidence nonce intentionally differs from both frozen
/// challenge payload nonces, so a probe must not derive payload bytes from it.
pub const fn challenge_matches_commitment(
    input: &[u8; CHALLENGE_BYTES],
    expected_length: u64,
    expected_hash: u64,
) -> bool {
    expected_length == CHALLENGE_BYTES as u64
        && expected_hash != 0
        && fnv1a64(input) == expected_hash
}

pub const fn fnv1a64(bytes: &[u8]) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325u64;
    let mut index = 0;
    while index != bytes.len() {
        hash ^= bytes[index] as u64;
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
        index += 1;
    }
    hash
}

const fn message_type(message: ControllerMessage) -> u16 {
    match message {
        ControllerMessage::Configure { .. } => 1,
        ControllerMessage::Attached { .. } => 2,
        ControllerMessage::ArmPermit { .. } => 3,
        ControllerMessage::ResponseCommitted { .. } => 4,
        ControllerMessage::StreamPeerClosed { .. } => 5,
    }
}

fn put16(output: &mut [u8], offset: usize, value: u16) {
    output[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}
fn put32(output: &mut [u8], offset: usize, value: u32) {
    output[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}
fn put64(output: &mut [u8], offset: usize, value: u64) {
    output[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}
fn get16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes(
        bytes[offset..offset + 2]
            .try_into()
            .expect("fixed WRE3 field"),
    )
}
fn get32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(
        bytes[offset..offset + 4]
            .try_into()
            .expect("fixed WRE3 field"),
    )
}
fn get64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(
        bytes[offset..offset + 8]
            .try_into()
            .expect("fixed WRE3 field"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn challenge_is_binary_safe_nonce_bound_and_response_is_exact() {
        let first = challenge(0x0123_4567_89ab_cdef);
        let second = challenge(0xfedc_ba98_7654_3210);
        assert_ne!(first, second);
        for byte in [0x0d, 0x0a, 0x00, 0x7f, b'D'] {
            assert!(first.contains(&byte));
        }
        assert_ne!(response(&first), first);
        assert_ne!(fnv1a64(&response(&first)), fnv1a64(&first));
    }

    #[test]
    fn controller_records_round_trip_and_reject_reserved_bytes() {
        let message = ControllerMessage::ArmPermit {
            nonce: 1,
            publication_generation: 2,
            stream_generation: 3,
            challenge_generation: 4,
            expected_length: CHALLENGE_BYTES as u64,
            expected_hash: 5,
        };
        let mut bytes = [0; CONTROL_BYTES];
        encode(message, &mut bytes).unwrap();
        assert_eq!(parse(&bytes), Ok(message));
        bytes[79] = 1;
        assert_eq!(parse(&bytes), Err(ProtocolError::NonzeroReserved));
    }

    #[test]
    fn devmgr_config_and_ready_are_directional_and_generation_exact() {
        let config = DevmgrConfig {
            nonce: 7,
            publication_generation: 9,
        };
        let mut bytes = [0; DEVMGR_CONFIG_BYTES];
        encode_devmgr_config(config, &mut bytes).unwrap();
        assert_eq!(parse_devmgr_config(&bytes), Ok(config));
        assert_eq!(parse_devmgr_ready(&bytes), Err(ProtocolError::WrongType));

        let ready = DevmgrReady {
            nonce: config.nonce,
            publication_generation: config.publication_generation,
        };
        encode_devmgr_ready(ready, &mut bytes).unwrap();
        assert_eq!(parse_devmgr_ready(&bytes), Ok(ready));
        assert_eq!(parse_devmgr_config(&bytes), Err(ProtocolError::WrongType));
        bytes[47] = 1;
        assert_eq!(
            parse_devmgr_ready(&bytes),
            Err(ProtocolError::NonzeroReserved)
        );
    }

    #[test]
    fn commitment_keeps_evidence_nonce_distinct_from_both_frozen_challenges() {
        let evidence_nonce = 0x1111_2222_3333_4444;
        let challenge1_nonce = 0x5555_6666_7777_8888;
        let challenge2_nonce = 0x9999_aaaa_bbbb_cccc;
        assert_ne!(evidence_nonce, challenge1_nonce);
        assert_ne!(evidence_nonce, challenge2_nonce);
        let challenge1 = challenge(challenge1_nonce);
        let challenge2 = challenge_for_generation(challenge2_nonce, CHALLENGE2_GENERATION);
        assert_ne!(challenge1, challenge2);
        assert!(challenge_matches_commitment(
            &challenge1,
            CHALLENGE_BYTES as u64,
            fnv1a64(&challenge1)
        ));
        assert!(challenge_matches_commitment(
            &challenge2,
            CHALLENGE_BYTES as u64,
            fnv1a64(&challenge2)
        ));
        assert_ne!(response(&challenge1), response(&challenge2));
    }

    #[test]
    fn transport_empty_fact_round_trips_and_rejects_wrong_response_length() {
        let fact = TransportEmptyFact {
            nonce: 1,
            attempt_generation: 2,
            publication_generation: 3,
            stream_generation: 4,
            challenge_generation: 5,
            response_length: RESPONSE_BYTES as u64,
            response_hash: 6,
        };
        let mut bytes = [0u8; TRANSPORT_EMPTY_FACT_BYTES];
        encode_transport_empty_fact(fact, &mut bytes).unwrap();
        assert_eq!(parse_transport_empty_fact(&bytes), Ok(fact));
        bytes[56] = 1;
        assert_eq!(
            parse_transport_empty_fact(&bytes),
            Err(ProtocolError::WrongLength)
        );
    }

    #[test]
    fn challenge_binding_keeps_attempt_and_challenge_generations_independent() {
        let binding = ChallengeBinding {
            nonce: 1,
            attempt_generation: 9,
            publication_generation: 3,
            stream_generation: 4,
            challenge_generation: 2,
            expected_length: CHALLENGE_BYTES as u64,
            expected_hash: 6,
        };
        let mut bytes = [0u8; TRANSPORT_EMPTY_FACT_BYTES];
        encode_challenge_binding(binding, &mut bytes).unwrap();
        assert_eq!(parse_challenge_binding(&bytes), Ok(binding));
        assert_eq!(
            parse_transport_empty_fact(&bytes),
            Err(ProtocolError::WrongType)
        );
    }

    #[test]
    fn wde3_direction_types_are_exact() {
        let binding = ChallengeBinding {
            nonce: 1,
            attempt_generation: 9,
            publication_generation: 3,
            stream_generation: 4,
            challenge_generation: 2,
            expected_length: CHALLENGE_BYTES as u64,
            expected_hash: 6,
        };
        let fact = TransportEmptyFact {
            nonce: binding.nonce,
            attempt_generation: binding.attempt_generation,
            publication_generation: binding.publication_generation,
            stream_generation: binding.stream_generation,
            challenge_generation: binding.challenge_generation,
            response_length: binding.expected_length,
            response_hash: binding.expected_hash,
        };
        let mut bytes = [0u8; TRANSPORT_EMPTY_FACT_BYTES];
        encode_transport_empty_fact(fact, &mut bytes).unwrap();
        assert_eq!(u16::from_le_bytes([bytes[6], bytes[7]]), 3);
        assert_eq!(parse_transport_empty_fact(&bytes), Ok(fact));
        encode_challenge_binding(binding, &mut bytes).unwrap();
        assert_eq!(u16::from_le_bytes([bytes[6], bytes[7]]), 4);
        assert_eq!(parse_challenge_binding(&bytes), Ok(binding));
        encode_binding_ready(binding, &mut bytes).unwrap();
        assert_eq!(u16::from_le_bytes([bytes[6], bytes[7]]), 5);
        assert_eq!(parse_binding_ready(&bytes), Ok(binding));
        encode_begin_retire(binding, &mut bytes).unwrap();
        assert_eq!(u16::from_le_bytes([bytes[6], bytes[7]]), 6);
        assert_eq!(parse_begin_retire(&bytes), Ok(binding));
        encode_finalize_retire(binding, &mut bytes).unwrap();
        assert_eq!(u16::from_le_bytes([bytes[6], bytes[7]]), 7);
        assert_eq!(parse_finalize_retire(&bytes), Ok(binding));
        encode_retire_stage1_ready(binding, &mut bytes).unwrap();
        assert_eq!(u16::from_le_bytes([bytes[6], bytes[7]]), 8);
        assert_eq!(parse_retire_stage1_ready(&bytes), Ok(binding));
        assert_eq!(
            parse_transport_empty_fact(&bytes),
            Err(ProtocolError::WrongType)
        );
    }

    #[test]
    fn lifecycle_requires_the_exact_u1_retirement_before_a_fresh_u2_reporter() {
        let u1 = DriverIdentity {
            attempt_generation: 11,
            publication_generation: 21,
            stream_generation: 31,
            challenge_generation: 1,
        };
        let probe1 = ProbeIdentity {
            process_generation: 41,
        };
        let mut lifecycle = Selector31Lifecycle::new(u1, probe1).unwrap();
        lifecycle.challenge1_responded().unwrap();
        assert_eq!(lifecycle.u1_peer_closed(), Err(LifecycleError::WrongOrder));
        lifecycle.begin_transport_empty_barrier(true, true).unwrap();
        lifecycle.timer_paced_temt_poll(false).unwrap();
        lifecycle.timer_paced_temt_poll(true).unwrap();
        lifecycle.queued_data_before_peer_close().unwrap();
        lifecycle.u1_peer_closed().unwrap();
        lifecycle.u1_reaped().unwrap();
        lifecycle.u1_endpoint_released(true).unwrap();
        lifecycle.u1_endpoint_released(false).unwrap();
        assert_eq!(
            lifecycle.admit_u2(
                DriverIdentity {
                    attempt_generation: 12,
                    publication_generation: 22,
                    stream_generation: 32,
                    challenge_generation: 2,
                },
                ProbeIdentity {
                    process_generation: 42,
                },
            ),
            Err(LifecycleError::WrongOrder)
        );
        lifecycle.u1_probe_reaped(probe1).unwrap();
        let u2 = DriverIdentity {
            attempt_generation: 12,
            publication_generation: 22,
            stream_generation: 32,
            challenge_generation: 2,
        };
        lifecycle
            .admit_u2(
                u2,
                ProbeIdentity {
                    process_generation: 42,
                },
            )
            .unwrap();
        lifecycle.challenge2_responded().unwrap();
        lifecycle
            .begin_challenge2_transport_empty_barrier(u2, true, true)
            .unwrap();
        lifecycle
            .timer_paced_challenge2_temt_poll(u2, true)
            .unwrap();
        assert_eq!(
            lifecycle.controller_terminal_claim(u2),
            Err(LifecycleError::WrongOrder)
        );
        lifecycle
            .u2_probe_reaped(
                ProbeIdentity {
                    process_generation: 42,
                },
                true,
            )
            .unwrap();
        lifecycle.controller_terminal_claim(u2).unwrap();
        lifecycle.observe_kernel_stale_u1_rejection(u1).unwrap();
        lifecycle.finish().unwrap();
        assert!(lifecycle.complete());
    }

    #[test]
    fn lifecycle_rejects_non_fresh_u2_and_non_timer_temt_barriers() {
        let u1 = DriverIdentity {
            attempt_generation: 1,
            publication_generation: 2,
            stream_generation: 3,
            challenge_generation: 1,
        };
        let probe1 = ProbeIdentity {
            process_generation: 4,
        };
        let mut lifecycle = Selector31Lifecycle::new(u1, probe1).unwrap();
        lifecycle.challenge1_responded().unwrap();
        assert_eq!(
            lifecycle.begin_transport_empty_barrier(true, false),
            Err(LifecycleError::WrongOrder)
        );
        assert_eq!(
            lifecycle.begin_transport_empty_barrier(false, true),
            Err(LifecycleError::WrongOrder)
        );
        assert_eq!(
            lifecycle.begin_transport_empty_barrier_after_input(true, true, false),
            Err(LifecycleError::WrongOrder)
        );
        lifecycle.begin_transport_empty_barrier(true, true).unwrap();
        assert_eq!(lifecycle.timer_paced_temt_poll(false), Ok(()));
        assert_eq!(lifecycle.timer_paced_temt_poll(false), Ok(()));
        assert_eq!(
            lifecycle.timer_paced_temt_poll(false),
            Err(LifecycleError::BarrierTimedOut)
        );
    }

    #[test]
    fn u1_exit_requires_the_ordered_close_and_successful_terminal_record() {
        let u1 = DriverIdentity {
            attempt_generation: 1,
            publication_generation: 2,
            stream_generation: 3,
            challenge_generation: 1,
        };
        let mut lifecycle = Selector31Lifecycle::new(
            u1,
            ProbeIdentity {
                process_generation: 4,
            },
        )
        .unwrap();
        // A premature zero exit cannot skip the response/TEMT/close sequence.
        assert_eq!(
            lifecycle.u1_finalize_exit(true),
            Err(LifecycleError::WrongOrder)
        );
        lifecycle.challenge1_responded().unwrap();
        lifecycle
            .begin_transport_empty_barrier_after_input(true, true, true)
            .unwrap();
        lifecycle.timer_paced_temt_poll(true).unwrap();
        lifecycle.queued_data_before_peer_close().unwrap();
        lifecycle.u1_peer_closed().unwrap();
        // A nonzero/crashed exit after peer close still cannot admit U2.
        assert_eq!(
            lifecycle.u1_finalize_exit(false),
            Err(LifecycleError::WrongOrder)
        );
        lifecycle.u1_finalize_exit(true).unwrap();
    }

    #[test]
    fn u2_terminal_requires_its_own_acknowledged_temt_fact() {
        let u1 = DriverIdentity {
            attempt_generation: 1,
            publication_generation: 2,
            stream_generation: 3,
            challenge_generation: 1,
        };
        let u2 = DriverIdentity {
            attempt_generation: 4,
            publication_generation: 5,
            stream_generation: 6,
            challenge_generation: 2,
        };
        let mut lifecycle = Selector31Lifecycle::new(
            u1,
            ProbeIdentity {
                process_generation: 7,
            },
        )
        .unwrap();
        lifecycle.challenge1_responded().unwrap();
        lifecycle.begin_transport_empty_barrier(true, true).unwrap();
        lifecycle.timer_paced_temt_poll(true).unwrap();
        lifecycle.queued_data_before_peer_close().unwrap();
        lifecycle.u1_peer_closed().unwrap();
        lifecycle.u1_reaped().unwrap();
        lifecycle.u1_endpoint_released(true).unwrap();
        lifecycle.u1_endpoint_released(false).unwrap();
        lifecycle
            .u1_probe_reaped(ProbeIdentity {
                process_generation: 7,
            })
            .unwrap();
        lifecycle
            .admit_u2(
                u2,
                ProbeIdentity {
                    process_generation: 8,
                },
            )
            .unwrap();
        lifecycle.challenge2_responded().unwrap();
        assert_eq!(
            lifecycle.controller_terminal_claim(u2),
            Err(LifecycleError::WrongOrder)
        );
        assert_eq!(
            lifecycle.begin_challenge2_transport_empty_barrier(u1, true, true),
            Err(LifecycleError::WrongOrder)
        );
        assert_eq!(
            lifecycle.begin_challenge2_transport_empty_barrier(u2, false, true),
            Err(LifecycleError::WrongOrder)
        );
        assert_eq!(
            lifecycle.begin_challenge2_transport_empty_barrier(u2, true, false),
            Err(LifecycleError::WrongOrder)
        );
        lifecycle
            .begin_challenge2_transport_empty_barrier(u2, true, true)
            .unwrap();
        assert_eq!(
            lifecycle.timer_paced_challenge2_temt_poll(u1, true),
            Err(LifecycleError::WrongOrder)
        );
        assert_eq!(
            lifecycle.timer_paced_challenge2_temt_poll(u2, false),
            Ok(())
        );
        assert_eq!(
            lifecycle.timer_paced_challenge2_temt_poll(u2, false),
            Ok(())
        );
        assert_eq!(
            lifecycle.timer_paced_challenge2_temt_poll(u2, false),
            Err(LifecycleError::BarrierTimedOut)
        );
    }

    #[test]
    fn u2_nonzero_exit_cannot_claim_after_a_prior_temt_wake() {
        let u1 = DriverIdentity {
            attempt_generation: 1,
            publication_generation: 2,
            stream_generation: 3,
            challenge_generation: 1,
        };
        let u2 = DriverIdentity {
            attempt_generation: 4,
            publication_generation: 5,
            stream_generation: 6,
            challenge_generation: 2,
        };
        let probe1 = ProbeIdentity {
            process_generation: 7,
        };
        let probe2 = ProbeIdentity {
            process_generation: 8,
        };
        let mut lifecycle = Selector31Lifecycle::new(u1, probe1).unwrap();
        lifecycle.challenge1_responded().unwrap();
        lifecycle.begin_transport_empty_barrier(true, true).unwrap();
        lifecycle.timer_paced_temt_poll(true).unwrap();
        lifecycle.queued_data_before_peer_close().unwrap();
        lifecycle.u1_peer_closed().unwrap();
        lifecycle.u1_reaped().unwrap();
        lifecycle.u1_endpoint_released(true).unwrap();
        lifecycle.u1_endpoint_released(false).unwrap();
        lifecycle.u1_probe_reaped(probe1).unwrap();
        lifecycle.admit_u2(u2, probe2).unwrap();
        lifecycle.challenge2_responded().unwrap();
        lifecycle
            .begin_challenge2_transport_empty_barrier(u2, true, true)
            .unwrap();
        // Model the TEMT branch winning the resident poll before the queued
        // U2 process EXITED signal is classified.
        lifecycle
            .timer_paced_challenge2_temt_poll(u2, true)
            .unwrap();
        assert_eq!(
            lifecycle.controller_terminal_claim(u2),
            Err(LifecycleError::WrongOrder)
        );
        assert_eq!(
            lifecycle.u2_probe_reaped(probe2, false),
            Err(LifecycleError::WrongOrder)
        );
        assert_eq!(
            lifecycle.controller_terminal_claim(u2),
            Err(LifecycleError::WrongOrder)
        );
    }
}
