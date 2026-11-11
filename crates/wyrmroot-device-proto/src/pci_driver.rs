//! WRDP 1.0: devmgr's direct control of a polled PCI driver (root
//! `STORAGE_PLAN.md` W2).
//!
//! A PCI-function role has no platform interrupt to stage and no quiescence
//! handshake: the function's bus mastering is off until its own driver turns
//! it on, and the IOMMU blocks its DMA until that driver maps memory. So the
//! sequence is one MOVE and one reply:
//!
//! ```text
//! devmgr -> driver   STAGE   (+ the reduced DeviceResource)
//! driver -> devmgr   READY | FAILURE
//! ```
//!
//! This codec is separate from WRDC so neither parser can reinterpret the
//! other's messages.
//!
//! A PCI driver publishes its own service. Init installs the registry
//! publication when it constructs the driver and sends the endpoint over the
//! driver's launch Channel as one [`PublicationGrant`] (`WRPG`), carrying the
//! registry correlation the driver's PUBLISH must name.

use crate::control::ControlEndpoint;
use crate::control_v1_1::ControlIdentityV1_1;
use crate::coordinator::{AttemptGeneration, BundleGeneration, EndpointGeneration, EndpointId};
use crate::manifest::{PciFunction, RoleId};

pub const MAGIC: [u8; 4] = *b"WRDP";
pub const MAJOR: u16 = 1;
pub const MINOR: u16 = 0;
pub const HEADER_BYTES: usize = 72;
pub const STAGE_BYTES: usize = HEADER_BYTES + 16;
pub const READY_BYTES: usize = HEADER_BYTES;
pub const FAILURE_BYTES: usize = HEADER_BYTES + 8;
/// The largest WRDP message, for receive buffers.
pub const MAX_BYTES: usize = STAGE_BYTES;

const TYPE_STAGE: u32 = 1;
const TYPE_READY: u32 = 2;
const TYPE_FAILURE: u32 = 3;

pub const GRANT_MAGIC: [u8; 4] = *b"WRPG";
pub const GRANT_BYTES: usize = 56;

/// Init's grant of one installed registry publication to a PCI driver.
/// Carries exactly one Channel handle: the publication endpoint.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PublicationGrant {
    pub registry_generation: u64,
    pub endpoint_id: u64,
    pub endpoint_generation: u64,
    /// The transaction the driver's PUBLISH uses.
    pub transaction_id: u64,
    pub service_generation: u64,
}

impl PublicationGrant {
    const fn fields(self) -> [u64; 5] {
        [
            self.registry_generation,
            self.endpoint_id,
            self.endpoint_generation,
            self.transaction_id,
            self.service_generation,
        ]
    }
}

pub fn encode_grant(
    grant: PublicationGrant,
    output: &mut [u8; GRANT_BYTES],
) -> Result<(), PciDriverParseError> {
    if grant.fields().contains(&0) {
        return Err(PciDriverParseError::ZeroIdentity);
    }
    output.fill(0);
    output[..4].copy_from_slice(&GRANT_MAGIC);
    output[4..6].copy_from_slice(&MAJOR.to_le_bytes());
    output[6..8].copy_from_slice(&MINOR.to_le_bytes());
    put32(output, 8, GRANT_BYTES as u32);
    put32(output, 12, 1);
    for (index, value) in grant.fields().into_iter().enumerate() {
        put64(output, 16 + 8 * index, value);
    }
    Ok(())
}

pub fn parse_grant(bytes: &[u8]) -> Result<PublicationGrant, PciDriverParseError> {
    if bytes.len() != GRANT_BYTES || get32(bytes, 8) as usize != GRANT_BYTES {
        return Err(PciDriverParseError::WrongSize);
    }
    if bytes[..4] != GRANT_MAGIC {
        return Err(PciDriverParseError::WrongMagic);
    }
    if get16(bytes, 4) != MAJOR || get16(bytes, 6) != MINOR {
        return Err(PciDriverParseError::WrongVersion);
    }
    if get32(bytes, 12) != 1 {
        return Err(PciDriverParseError::WrongHandleCount);
    }
    let grant = PublicationGrant {
        registry_generation: get64(bytes, 16),
        endpoint_id: get64(bytes, 24),
        endpoint_generation: get64(bytes, 32),
        transaction_id: get64(bytes, 40),
        service_generation: get64(bytes, 48),
    };
    if grant.fields().contains(&0) {
        return Err(PciDriverParseError::ZeroIdentity);
    }
    Ok(grant)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PciDriverMessage {
    /// Carries exactly one DeviceResource handle.
    Stage {
        identity: ControlIdentityV1_1,
        resource_id: u64,
        function: PciFunction,
    },
    Ready {
        identity: ControlIdentityV1_1,
    },
    Failure {
        identity: ControlIdentityV1_1,
        /// The driver's own nonzero failure step.
        code: u32,
    },
}

impl PciDriverMessage {
    pub const fn identity(self) -> ControlIdentityV1_1 {
        match self {
            Self::Stage { identity, .. }
            | Self::Ready { identity }
            | Self::Failure { identity, .. } => identity,
        }
    }

    pub const fn wire_size(self) -> usize {
        match self {
            Self::Stage { .. } => STAGE_BYTES,
            Self::Ready { .. } => READY_BYTES,
            Self::Failure { .. } => FAILURE_BYTES,
        }
    }

    pub const fn handle_count(self) -> u32 {
        match self {
            Self::Stage { .. } => 1,
            _ => 0,
        }
    }

    const fn message_type(self) -> u32 {
        match self {
            Self::Stage { .. } => TYPE_STAGE,
            Self::Ready { .. } => TYPE_READY,
            Self::Failure { .. } => TYPE_FAILURE,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PciDriverParseError {
    WrongSize,
    WrongMagic,
    WrongVersion,
    UnknownMessage,
    NonzeroFlags,
    WrongHandleCount,
    ZeroIdentity,
    ZeroField,
    NonzeroReserved,
}

pub fn encode(message: PciDriverMessage, output: &mut [u8]) -> Result<(), PciDriverParseError> {
    if output.len() != message.wire_size() {
        return Err(PciDriverParseError::WrongSize);
    }
    validate_identity(message.identity())?;
    validate_body(message)?;
    output.fill(0);
    output[..4].copy_from_slice(&MAGIC);
    output[4..6].copy_from_slice(&MAJOR.to_le_bytes());
    output[6..8].copy_from_slice(&MINOR.to_le_bytes());
    put32(output, 8, message.message_type());
    put32(output, 16, output.len() as u32);
    put32(output, 20, message.handle_count());
    let identity = message.identity();
    put64(output, 24, identity.role_id.0);
    put64(output, 32, identity.bundle_generation.0);
    put64(output, 40, identity.attempt_generation.0);
    put64(output, 48, identity.endpoint.id.0);
    put64(output, 56, identity.endpoint.generation.0);
    put64(output, 64, identity.transaction_id);
    match message {
        PciDriverMessage::Stage {
            resource_id,
            function,
            ..
        } => {
            put64(output, 72, resource_id);
            put32(output, 80, function.address);
            put32(output, 84, function.ids);
        }
        PciDriverMessage::Failure { code, .. } => put32(output, 72, code),
        PciDriverMessage::Ready { .. } => {}
    }
    Ok(())
}

pub fn parse(bytes: &[u8]) -> Result<PciDriverMessage, PciDriverParseError> {
    if bytes.len() < HEADER_BYTES {
        return Err(PciDriverParseError::WrongSize);
    }
    if bytes[..4] != MAGIC {
        return Err(PciDriverParseError::WrongMagic);
    }
    if get16(bytes, 4) != MAJOR || get16(bytes, 6) != MINOR {
        return Err(PciDriverParseError::WrongVersion);
    }
    if get32(bytes, 12) != 0 {
        return Err(PciDriverParseError::NonzeroFlags);
    }
    if get32(bytes, 16) as usize != bytes.len() {
        return Err(PciDriverParseError::WrongSize);
    }
    let identity = ControlIdentityV1_1 {
        role_id: RoleId(get64(bytes, 24)),
        bundle_generation: BundleGeneration(get64(bytes, 32)),
        attempt_generation: AttemptGeneration(get64(bytes, 40)),
        endpoint: ControlEndpoint {
            id: EndpointId(get64(bytes, 48)),
            generation: EndpointGeneration(get64(bytes, 56)),
        },
        transaction_id: get64(bytes, 64),
    };
    let message = match get32(bytes, 8) {
        TYPE_STAGE if bytes.len() == STAGE_BYTES => PciDriverMessage::Stage {
            identity,
            resource_id: get64(bytes, 72),
            function: PciFunction {
                address: get32(bytes, 80),
                ids: get32(bytes, 84),
            },
        },
        TYPE_READY if bytes.len() == READY_BYTES => PciDriverMessage::Ready { identity },
        TYPE_FAILURE if bytes.len() == FAILURE_BYTES => {
            if get32(bytes, 76) != 0 {
                return Err(PciDriverParseError::NonzeroReserved);
            }
            PciDriverMessage::Failure {
                identity,
                code: get32(bytes, 72),
            }
        }
        TYPE_STAGE | TYPE_READY | TYPE_FAILURE => return Err(PciDriverParseError::WrongSize),
        _ => return Err(PciDriverParseError::UnknownMessage),
    };
    if get32(bytes, 20) != message.handle_count() {
        return Err(PciDriverParseError::WrongHandleCount);
    }
    validate_identity(identity)?;
    validate_body(message)?;
    Ok(message)
}

fn validate_identity(identity: ControlIdentityV1_1) -> Result<(), PciDriverParseError> {
    if identity.role_id.0 == 0
        || identity.bundle_generation.0 == 0
        || identity.attempt_generation.0 == 0
        || identity.endpoint.id.0 == 0
        || identity.endpoint.generation.0 == 0
        || identity.transaction_id == 0
    {
        return Err(PciDriverParseError::ZeroIdentity);
    }
    Ok(())
}

fn validate_body(message: PciDriverMessage) -> Result<(), PciDriverParseError> {
    match message {
        PciDriverMessage::Stage {
            resource_id,
            function,
            ..
        } if resource_id == 0 || function.ids == 0 => Err(PciDriverParseError::ZeroField),
        PciDriverMessage::Failure { code: 0, .. } => Err(PciDriverParseError::ZeroField),
        _ => Ok(()),
    }
}

fn put32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}
fn put64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}
fn get16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([bytes[offset], bytes[offset + 1]])
}
fn get32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().expect("bounded"))
}
fn get64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(bytes[offset..offset + 8].try_into().expect("bounded"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::BOOT_DISK_POLICY;

    fn identity() -> ControlIdentityV1_1 {
        ControlIdentityV1_1 {
            role_id: RoleId(2),
            bundle_generation: BundleGeneration(3),
            attempt_generation: AttemptGeneration(4),
            endpoint: ControlEndpoint {
                id: EndpointId(5),
                generation: EndpointGeneration(1),
            },
            transaction_id: 6,
        }
    }

    fn messages() -> [PciDriverMessage; 3] {
        [
            PciDriverMessage::Stage {
                identity: identity(),
                resource_id: 2,
                function: BOOT_DISK_POLICY.pci,
            },
            PciDriverMessage::Ready {
                identity: identity(),
            },
            PciDriverMessage::Failure {
                identity: identity(),
                code: 17,
            },
        ]
    }

    #[test]
    fn every_message_round_trips_at_its_exact_size() {
        for message in messages() {
            let mut bytes = [0u8; MAX_BYTES];
            let bytes = &mut bytes[..message.wire_size()];
            encode(message, bytes).unwrap();
            assert_eq!(parse(bytes), Ok(message));
            // One byte short or long is refused.
            assert_eq!(
                parse(&bytes[..bytes.len() - 1]),
                Err(PciDriverParseError::WrongSize)
            );
        }
    }

    #[test]
    fn header_fields_are_checked() {
        let message = messages()[0];
        let mut good = [0u8; STAGE_BYTES];
        encode(message, &mut good).unwrap();
        let cases: [(usize, &[u8], PciDriverParseError); 7] = [
            (0, b"WRDC", PciDriverParseError::WrongMagic),
            (6, &1u16.to_le_bytes(), PciDriverParseError::WrongVersion),
            (8, &9u32.to_le_bytes(), PciDriverParseError::UnknownMessage),
            (8, &2u32.to_le_bytes(), PciDriverParseError::WrongSize),
            (12, &1u32.to_le_bytes(), PciDriverParseError::NonzeroFlags),
            (
                20,
                &0u32.to_le_bytes(),
                PciDriverParseError::WrongHandleCount,
            ),
            (64, &0u64.to_le_bytes(), PciDriverParseError::ZeroIdentity),
        ];
        for (offset, value, expected) in cases {
            let mut bad = good;
            bad[offset..offset + value.len()].copy_from_slice(value);
            assert_eq!(parse(&bad), Err(expected), "offset {offset}");
        }
        let mut bad = good;
        bad[72..80].fill(0);
        assert_eq!(parse(&bad), Err(PciDriverParseError::ZeroField));
    }

    #[test]
    fn failure_needs_a_code_and_a_zero_reserved_word() {
        let mut bytes = [0u8; FAILURE_BYTES];
        encode(messages()[2], &mut bytes).unwrap();
        bytes[76] = 1;
        assert_eq!(parse(&bytes), Err(PciDriverParseError::NonzeroReserved));
        assert_eq!(
            encode(
                PciDriverMessage::Failure {
                    identity: identity(),
                    code: 0
                },
                &mut bytes
            ),
            Err(PciDriverParseError::ZeroField)
        );
    }

    #[test]
    fn encode_refuses_a_wrong_buffer_or_zero_identity() {
        let mut bytes = [0u8; STAGE_BYTES];
        assert_eq!(
            encode(messages()[1], &mut bytes),
            Err(PciDriverParseError::WrongSize)
        );
        let mut zero = identity();
        zero.endpoint.generation = EndpointGeneration(0);
        assert_eq!(
            encode(
                PciDriverMessage::Ready { identity: zero },
                &mut bytes[..READY_BYTES]
            ),
            Err(PciDriverParseError::ZeroIdentity)
        );
    }

    #[test]
    fn publication_grant_round_trips_and_refuses_zero_or_damage() {
        let grant = PublicationGrant {
            registry_generation: 1,
            endpoint_id: 2,
            endpoint_generation: 3,
            transaction_id: 4,
            service_generation: 5,
        };
        let mut bytes = [0u8; GRANT_BYTES];
        encode_grant(grant, &mut bytes).unwrap();
        assert_eq!(parse_grant(&bytes), Ok(grant));
        for (offset, expected) in [
            (0, PciDriverParseError::WrongMagic),
            (6, PciDriverParseError::WrongVersion),
            (8, PciDriverParseError::WrongSize),
            (12, PciDriverParseError::WrongHandleCount),
        ] {
            let mut bad = bytes;
            bad[offset] ^= 0x40;
            assert_eq!(parse_grant(&bad), Err(expected), "offset {offset}");
        }
        for field in 0..5 {
            let mut bad = bytes;
            bad[16 + 8 * field..24 + 8 * field].fill(0);
            assert_eq!(parse_grant(&bad), Err(PciDriverParseError::ZeroIdentity));
        }
        assert_eq!(
            parse_grant(&bytes[..GRANT_BYTES - 8]),
            Err(PciDriverParseError::WrongSize)
        );
        assert_eq!(
            encode_grant(
                PublicationGrant {
                    transaction_id: 0,
                    ..grant
                },
                &mut bytes
            ),
            Err(PciDriverParseError::ZeroIdentity)
        );
    }
}
