//! WRCS 1.1 publication install/rebind with the supervisor-issued service generation.
//!
//! The registry binding and service generation belong to distinct namespaces.
//! Status remains WRCS 1.0; this extension accepts only publication handoffs.

use crate::controller::{self, ControllerMessage, ControllerParseError, MessageType};

pub const MINOR: u16 = 1;
pub const RECORD_BYTES: usize = 80;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PublicationMessage {
    pub controller: ControllerMessage,
    pub service_generation: u64,
}

pub fn encode(message: PublicationMessage, output: &mut [u8]) -> Result<(), ControllerParseError> {
    if output.len() != RECORD_BYTES {
        return Err(ControllerParseError::WrongSize);
    }
    if matches!(message.controller, ControllerMessage::Status { .. }) {
        return Err(ControllerParseError::UnknownMessage);
    }
    if message.service_generation == 0 {
        return Err(ControllerParseError::ZeroIdentity);
    }
    controller::encode(message.controller, &mut output[..controller::HEADER_BYTES])?;
    output[6..8].copy_from_slice(&MINOR.to_le_bytes());
    output[16..20].copy_from_slice(&(RECORD_BYTES as u32).to_le_bytes());
    output[72..80].copy_from_slice(&message.service_generation.to_le_bytes());
    Ok(())
}

pub fn parse(bytes: &[u8]) -> Result<PublicationMessage, ControllerParseError> {
    if bytes.len() != RECORD_BYTES {
        return Err(ControllerParseError::WrongSize);
    }
    if bytes[..4] != controller::MAGIC {
        return Err(ControllerParseError::WrongMagic);
    }
    if bytes[4..6] != controller::MAJOR.to_le_bytes() || bytes[6..8] != MINOR.to_le_bytes() {
        return Err(ControllerParseError::WrongVersion);
    }
    if bytes[16..20] != (RECORD_BYTES as u32).to_le_bytes() {
        return Err(ControllerParseError::WrongSize);
    }
    if bytes[8..12] != (MessageType::InstallPublication as u32).to_le_bytes()
        && bytes[8..12] != (MessageType::RebindPublication as u32).to_le_bytes()
    {
        return Err(ControllerParseError::UnknownMessage);
    }

    // Reuse the strict legacy validation of all common header fields. The
    // original 1.1 bytes are never admitted by the 1.0 parser itself.
    let mut header = [0; controller::HEADER_BYTES];
    header.copy_from_slice(&bytes[..controller::HEADER_BYTES]);
    header[6..8].copy_from_slice(&controller::MINOR.to_le_bytes());
    header[16..20].copy_from_slice(&(controller::HEADER_BYTES as u32).to_le_bytes());
    let controller = controller::parse(&header)?;
    let mut generation_bytes = [0; 8];
    generation_bytes.copy_from_slice(&bytes[72..80]);
    let service_generation = u64::from_le_bytes(generation_bytes);
    if service_generation == 0 {
        return Err(ControllerParseError::ZeroIdentity);
    }
    Ok(PublicationMessage {
        controller,
        service_generation,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::controller::StatusCode;
    use crate::coordinator::{
        RegistryBinding, RegistryEndpoint, RegistryEndpointGeneration, RegistryEndpointId,
        RegistryGeneration, SupervisorGeneration,
    };

    fn publication(rebind: bool) -> PublicationMessage {
        let supervisor_generation = SupervisorGeneration(3);
        let binding = RegistryBinding {
            generation: RegistryGeneration(1),
            endpoint: RegistryEndpoint {
                id: RegistryEndpointId(17),
                generation: RegistryEndpointGeneration(2),
            },
        };
        let transaction_id = 19;
        let controller = if rebind {
            ControllerMessage::RebindPublication {
                supervisor_generation,
                binding,
                transaction_id,
            }
        } else {
            ControllerMessage::InstallPublication {
                supervisor_generation,
                binding,
                transaction_id,
            }
        };
        PublicationMessage {
            controller,
            // A1-02: the registry lifetime is 1; the issued service generation
            // is 0xc10801. Equal small fixtures concealed the missing handoff.
            service_generation: 0xc10801,
        }
    }

    fn encoded(rebind: bool) -> [u8; RECORD_BYTES] {
        let mut bytes = [0xa5; RECORD_BYTES];
        encode(publication(rebind), &mut bytes).unwrap();
        bytes
    }

    #[test]
    fn exact_install_and_rebind_wire_preserves_distinct_generations() {
        for rebind in [false, true] {
            let message = publication(rebind);
            let bytes = encoded(rebind);
            let mut expected = [0; RECORD_BYTES];
            expected[..4].copy_from_slice(b"WRCS");
            expected[4..8].copy_from_slice(&[1, 0, 1, 0]);
            expected[8] = if rebind { 2 } else { 1 };
            expected[16] = 80;
            expected[20] = u8::from(rebind);
            expected[24] = 3;
            expected[32] = 1;
            expected[40] = 17;
            expected[48] = 2;
            expected[56] = 19;
            expected[72..80].copy_from_slice(&[1, 8, 193, 0, 0, 0, 0, 0]);
            assert_eq!(bytes, expected);
            assert_eq!(parse(&bytes), Ok(message));
        }
    }

    #[test]
    fn generation_is_nonzero_and_uses_all_eight_bytes() {
        for rebind in [false, true] {
            let mut message = publication(rebind);
            let mut bytes = encoded(rebind);
            message.service_generation = 0;
            assert_eq!(
                encode(message, &mut bytes),
                Err(ControllerParseError::ZeroIdentity)
            );
            bytes[72..80].fill(0);
            assert_eq!(parse(&bytes), Err(ControllerParseError::ZeroIdentity));
            message.service_generation = u64::MAX;
            encode(message, &mut bytes).unwrap();
            assert_eq!(&bytes[72..80], &[0xff; 8]);
            assert_eq!(parse(&bytes), Ok(message));
        }
    }

    #[test]
    fn rejects_truncation_trailing_bytes_and_wrong_declared_size() {
        let bytes = encoded(false);
        for length in 0..RECORD_BYTES {
            assert_eq!(
                parse(&bytes[..length]),
                Err(ControllerParseError::WrongSize)
            );
            let mut output = [0; RECORD_BYTES];
            assert_eq!(
                encode(publication(false), &mut output[..length]),
                Err(ControllerParseError::WrongSize)
            );
        }
        let mut oversized = [0; RECORD_BYTES + 1];
        oversized[..RECORD_BYTES].copy_from_slice(&bytes);
        assert_eq!(parse(&oversized), Err(ControllerParseError::WrongSize));
        assert_eq!(
            encode(publication(false), &mut oversized),
            Err(ControllerParseError::WrongSize)
        );
        for size in [0u32, 72, 79, 81, 88, u32::MAX] {
            let mut wrong_size = bytes;
            wrong_size[16..20].copy_from_slice(&size.to_le_bytes());
            assert_eq!(parse(&wrong_size), Err(ControllerParseError::WrongSize));
        }
    }

    #[test]
    fn rejects_wrong_magic_major_minor_and_message_type() {
        let mut bytes = encoded(false);
        bytes[0] ^= 1;
        assert_eq!(parse(&bytes), Err(ControllerParseError::WrongMagic));
        for offset in [4, 6] {
            for version in [0u16, 2, u16::MAX] {
                let mut bytes = encoded(false);
                bytes[offset..offset + 2].copy_from_slice(&version.to_le_bytes());
                assert_eq!(parse(&bytes), Err(ControllerParseError::WrongVersion));
            }
        }
        for message_type in [0u32, 3, 4, u32::MAX] {
            let mut bytes = encoded(false);
            bytes[8..12].copy_from_slice(&message_type.to_le_bytes());
            assert_eq!(parse(&bytes), Err(ControllerParseError::UnknownMessage));
        }
    }

    #[test]
    fn reuses_common_flags_reserved_and_identity_validation() {
        for rebind in [false, true] {
            for offset in 12..16 {
                let mut bytes = encoded(rebind);
                bytes[offset] = 1;
                assert_eq!(parse(&bytes), Err(ControllerParseError::NonzeroFlags));
            }
            for offset in 64..72 {
                let mut bytes = encoded(rebind);
                bytes[offset] = 1;
                assert_eq!(parse(&bytes), Err(ControllerParseError::NonzeroReserved));
            }
            for offset in [24, 32, 40, 48, 56] {
                let mut bytes = encoded(rebind);
                bytes[offset..offset + 8].fill(0);
                assert_eq!(parse(&bytes), Err(ControllerParseError::ZeroIdentity));
            }
        }
    }

    #[test]
    fn encode_rejects_invalid_common_identity() {
        let mut message = publication(false);
        if let ControllerMessage::InstallPublication {
            ref mut transaction_id,
            ..
        } = message.controller
        {
            *transaction_id = 0;
        }
        assert_eq!(
            encode(message, &mut [0; RECORD_BYTES]),
            Err(ControllerParseError::ZeroIdentity)
        );
    }

    #[test]
    fn requires_exact_handle_counts_for_each_message_type() {
        for rebind in [false, true] {
            for count in [0u32, 1, 2, u32::MAX] {
                if count == u32::from(rebind) {
                    continue;
                }
                let mut bytes = encoded(rebind);
                bytes[20..24].copy_from_slice(&count.to_le_bytes());
                assert_eq!(parse(&bytes), Err(ControllerParseError::WrongHandleCount));
            }
        }
    }

    #[test]
    fn legacy_publication_and_version_downgrades_are_rejected() {
        for rebind in [false, true] {
            let message = publication(rebind);
            let mut legacy = [0; controller::INSTALL_BYTES];
            controller::encode(message.controller, &mut legacy).unwrap();
            assert_eq!(controller::parse(&legacy), Ok(message.controller));
            assert_eq!(parse(&legacy), Err(ControllerParseError::WrongSize));
            let mut bytes = encoded(rebind);
            assert_eq!(
                controller::parse(&bytes),
                Err(ControllerParseError::WrongVersion)
            );
            // A copied legacy header with a tail cannot masquerade as 1.1.
            bytes[..controller::HEADER_BYTES].copy_from_slice(&legacy);
            assert_eq!(parse(&bytes), Err(ControllerParseError::WrongVersion));
            assert_eq!(
                controller::parse(&bytes),
                Err(ControllerParseError::WrongSize)
            );
        }
    }

    #[test]
    fn status_remains_legacy_only() {
        let status = ControllerMessage::Status {
            supervisor_generation: SupervisorGeneration(3),
            binding: None,
            transaction_id: 19,
            status: StatusCode::OperationalWaitingForRegistry,
            attempt_generation: None,
        };
        let mut legacy = [0; controller::STATUS_BYTES];
        controller::encode(status, &mut legacy).unwrap();
        assert_eq!(controller::parse(&legacy), Ok(status));
        assert_eq!(parse(&legacy), Err(ControllerParseError::WrongSize));
        assert_eq!(
            encode(
                PublicationMessage {
                    controller: status,
                    service_generation: 1
                },
                &mut [0; RECORD_BYTES]
            ),
            Err(ControllerParseError::UnknownMessage)
        );
        legacy[6..8].copy_from_slice(&MINOR.to_le_bytes());
        assert_eq!(
            controller::parse(&legacy),
            Err(ControllerParseError::WrongVersion)
        );
    }
}
