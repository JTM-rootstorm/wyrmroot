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
    BarrierIncomplete,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LifecycleState {
    Challenge1Active,
    Challenge1Responded,
    TransportEmpty,
    U1PeerClosed,
    U1Reaped,
    U1EndpointsReleased,
    U1ProbeReaped,
    Challenge2Active,
    Challenge2Responded,
    StaleU1Reported,
    Complete,
}

/// The bounded number of timer-paced `LSR.TEMT` observations required by the
/// selector product after the last FIFO fill and a successful Interrupt ack.
/// It is a product bound, not a UART driver retry policy.
pub const TRANSPORT_EMPTY_TEMT_SAMPLES: u8 = 3;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Selector31Lifecycle {
    state: LifecycleState,
    u1: DriverIdentity,
    u1_probe: ProbeIdentity,
    u2: Option<DriverIdentity>,
    u2_probe: Option<ProbeIdentity>,
    temt_samples: u8,
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
            temt_samples: 0,
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
    /// be proven before a timer-paced TEMT sample can count toward the exact
    /// U1 transport-empty barrier.
    pub fn timer_paced_temt(
        &mut self,
        final_fifo_fill: bool,
        interrupt_ack_succeeded: bool,
        temt: bool,
    ) -> Result<(), LifecycleError> {
        if self.state != LifecycleState::Challenge1Responded
            || !final_fifo_fill
            || !interrupt_ack_succeeded
        {
            return Err(LifecycleError::WrongOrder);
        }
        if !temt {
            self.temt_samples = 0;
            return Ok(());
        }
        self.temt_samples = self
            .temt_samples
            .checked_add(1)
            .ok_or(LifecycleError::BarrierIncomplete)?;
        if self.temt_samples == TRANSPORT_EMPTY_TEMT_SAMPLES {
            self.state = LifecycleState::TransportEmpty;
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
        if u2.attempt_generation == self.u1.attempt_generation
            || u2.publication_generation == self.u1.publication_generation
            || u2.stream_generation == self.u1.stream_generation
            || u2_probe == self.u1_probe
        {
            return Err(LifecycleError::NotFresh);
        }
        self.u2 = Some(u2);
        self.u2_probe = Some(u2_probe);
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

    pub fn stale_u1_report(&mut self, identity: DriverIdentity) -> Result<(), LifecycleError> {
        if self.state != LifecycleState::Challenge2Responded {
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
    let mut bytes = [0u8; CHALLENGE_BYTES];
    bytes[..8].copy_from_slice(&[0x0d, 0x0a, 0x00, 0x7f, b'D', b'W', b'1', b'E']);
    bytes[8..16].copy_from_slice(&nonce.to_le_bytes());
    bytes[16..24].copy_from_slice(&nonce.rotate_left(17).to_le_bytes());
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
    fn lifecycle_requires_the_exact_u1_retirement_before_a_fresh_u2_reporter() {
        let u1 = DriverIdentity {
            attempt_generation: 11,
            publication_generation: 21,
            stream_generation: 31,
        };
        let probe1 = ProbeIdentity {
            process_generation: 41,
        };
        let mut lifecycle = Selector31Lifecycle::new(u1, probe1).unwrap();
        lifecycle.challenge1_responded().unwrap();
        assert_eq!(lifecycle.u1_peer_closed(), Err(LifecycleError::WrongOrder));
        for _ in 0..TRANSPORT_EMPTY_TEMT_SAMPLES {
            lifecycle.timer_paced_temt(true, true, true).unwrap();
        }
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
        lifecycle.stale_u1_report(u1).unwrap();
        lifecycle.finish().unwrap();
        assert!(lifecycle.complete());
    }

    #[test]
    fn lifecycle_rejects_non_fresh_u2_and_non_timer_temt_barriers() {
        let u1 = DriverIdentity {
            attempt_generation: 1,
            publication_generation: 2,
            stream_generation: 3,
        };
        let probe1 = ProbeIdentity {
            process_generation: 4,
        };
        let mut lifecycle = Selector31Lifecycle::new(u1, probe1).unwrap();
        lifecycle.challenge1_responded().unwrap();
        assert_eq!(
            lifecycle.timer_paced_temt(true, false, true),
            Err(LifecycleError::WrongOrder)
        );
        assert_eq!(
            lifecycle.timer_paced_temt(false, true, true),
            Err(LifecycleError::WrongOrder)
        );
        for _ in 0..TRANSPORT_EMPTY_TEMT_SAMPLES {
            lifecycle.timer_paced_temt(true, true, true).unwrap();
        }
        lifecycle.queued_data_before_peer_close().unwrap();
        lifecycle.u1_peer_closed().unwrap();
        lifecycle.u1_reaped().unwrap();
        lifecycle.u1_endpoint_released(true).unwrap();
        lifecycle.u1_endpoint_released(false).unwrap();
        lifecycle.u1_probe_reaped(probe1).unwrap();
        assert_eq!(
            lifecycle.admit_u2(
                DriverIdentity {
                    attempt_generation: 1,
                    publication_generation: 5,
                    stream_generation: 6,
                },
                ProbeIdentity {
                    process_generation: 7,
                },
            ),
            Err(LifecycleError::NotFresh)
        );
    }
}
