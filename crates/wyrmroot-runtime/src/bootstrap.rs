//! Generic validation plans that the eventual exact Deepwyrm binding will execute.

use deepwyrm_syscall::{
    DW_BASE_PAGE_SIZE, DW_OBJECT_TYPE_ADDRESS_REGION, DW_OBJECT_TYPE_CHANNEL,
    DW_OBJECT_TYPE_MEMORY_OBJECT, DW_RIGHT_DUPLICATE, DW_RIGHT_INSPECT, DW_RIGHT_MAP,
    DW_RIGHT_MODIFY, DW_RIGHT_READ, DW_RIGHT_TRANSFER, DW_RIGHT_WAIT, DW_RIGHT_WRITE, DwObjectType,
    DwRights,
};

/// Native page size required by the D0 mapping contract.
pub const PAGE_SIZE: u64 = DW_BASE_PAGE_SIZE as u64;
/// WYR0-C's maximum encoded bootfs archive size.
pub const MAX_BOOTFS_LOGICAL_SIZE: u64 = 32 * 1024 * 1024;

/// Object metadata from either receive metadata or a fresh object-info query.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CapabilityInfo<ObjectType, Rights> {
    /// Exact object type imported from the Deepwyrm ABI at the call site.
    pub object_type: ObjectType,
    /// Exact rights mask imported from the Deepwyrm ABI at the call site.
    pub rights: Rights,
}

/// Required type and rights for a named bootstrap capability.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CapabilityExpectation<ObjectType, Rights> {
    /// Required object type.
    pub object_type: ObjectType,
    /// Required exact rights.
    pub rights: Rights,
}

/// Exact pinned-ABI contract for the child bootstrap Channel.
pub const BOOTSTRAP_CHANNEL_EXPECTATION: CapabilityExpectation<DwObjectType, DwRights> =
    CapabilityExpectation {
        object_type: DW_OBJECT_TYPE_CHANNEL,
        rights: DwRights(DW_RIGHT_READ.0 | DW_RIGHT_WRITE.0 | DW_RIGHT_WAIT.0 | DW_RIGHT_INSPECT.0),
    };

/// Exact pinned-ABI contract for the received self-root AddressRegion.
pub const SELF_ROOT_EXPECTATION: CapabilityExpectation<DwObjectType, DwRights> =
    CapabilityExpectation {
        object_type: DW_OBJECT_TYPE_ADDRESS_REGION,
        rights: DwRights(DW_RIGHT_MAP.0 | DW_RIGHT_MODIFY.0 | DW_RIGHT_INSPECT.0),
    };

/// Exact pinned-ABI contract for the received immutable bootfs MemoryObject.
pub const BOOTFS_EXPECTATION: CapabilityExpectation<DwObjectType, DwRights> =
    CapabilityExpectation {
        object_type: DW_OBJECT_TYPE_MEMORY_OBJECT,
        rights: DwRights(
            DW_RIGHT_READ.0
                | DW_RIGHT_MAP.0
                | DW_RIGHT_INSPECT.0
                | DW_RIGHT_DUPLICATE.0
                | DW_RIGHT_TRANSFER.0,
        ),
    };

/// Receive and fresh-query metadata for one ordered INIT capability.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InitCapability<ObjectType, Rights> {
    /// Metadata provided by the Channel receive operation.
    pub received: CapabilityInfo<ObjectType, Rights>,
    /// Metadata returned by a new object-info query on the received local handle.
    pub fresh: CapabilityInfo<ObjectType, Rights>,
}

/// Metadata validation failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CapabilityValidationError {
    /// The bootstrap Channel's receive metadata disagreed with its exact contract.
    InvalidBootstrapChannel,
    /// INIT did not provide exactly the root and bootfs capabilities.
    WrongInitCapabilityCount,
    /// Receive metadata did not equal the role contract.
    InvalidReceivedCapability,
    /// A fresh object-info query did not equal the role contract.
    InvalidFreshCapability,
}

/// Validates exact bootstrap Channel type and rights without hard-coding ABI constants.
pub fn validate_bootstrap_channel<ObjectType: Eq, Rights: Eq>(
    actual: CapabilityInfo<ObjectType, Rights>,
    expected: CapabilityExpectation<ObjectType, Rights>,
) -> Result<(), CapabilityValidationError> {
    if actual.object_type == expected.object_type && actual.rights == expected.rights {
        Ok(())
    } else {
        Err(CapabilityValidationError::InvalidBootstrapChannel)
    }
}

/// Validates the two ordered INIT capabilities using both receive and fresh-query metadata.
pub fn validate_init_capabilities<ObjectType: Eq, Rights: Eq>(
    capabilities: &[InitCapability<ObjectType, Rights>],
    root: CapabilityExpectation<ObjectType, Rights>,
    bootfs: CapabilityExpectation<ObjectType, Rights>,
) -> Result<(), CapabilityValidationError> {
    if capabilities.len() != 2 {
        return Err(CapabilityValidationError::WrongInitCapabilityCount);
    }
    for (capability, expected) in [(&capabilities[0], &root), (&capabilities[1], &bootfs)] {
        if capability.received.object_type != expected.object_type
            || capability.received.rights != expected.rights
        {
            return Err(CapabilityValidationError::InvalidReceivedCapability);
        }
        if capability.fresh.object_type != expected.object_type
            || capability.fresh.rights != expected.rights
        {
            return Err(CapabilityValidationError::InvalidFreshCapability);
        }
    }
    Ok(())
}

/// The read-only mapping extent required for a validated bootfs logical length.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MappingPlan {
    /// Exact archive bytes passed to the WYR0-C parser.
    pub logical_size: u64,
    /// Page-rounded map capacity; its tail is never parser input.
    pub mapped_size: u64,
}

/// Bootfs logical-length validation failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MappingPlanError {
    /// The archive is empty.
    EmptyArchive,
    /// The archive exceeds the WYR0-C encoded limit.
    ArchiveTooLarge,
    /// Page rounding overflowed.
    RoundingOverflow,
}

impl MappingPlan {
    /// Creates the exact read-only mapping plan; the caller must map only `mapped_size` and parse only `logical_size`.
    pub fn for_bootfs(logical_size: u64) -> Result<Self, MappingPlanError> {
        Self::for_limit(logical_size, MAX_BOOTFS_LOGICAL_SIZE)
    }

    fn for_limit(logical_size: u64, maximum_size: u64) -> Result<Self, MappingPlanError> {
        if logical_size == 0 {
            return Err(MappingPlanError::EmptyArchive);
        }
        if logical_size > maximum_size {
            return Err(MappingPlanError::ArchiveTooLarge);
        }
        let rounded = logical_size
            .checked_add(PAGE_SIZE - 1)
            .ok_or(MappingPlanError::RoundingOverflow)?
            / PAGE_SIZE
            * PAGE_SIZE;
        Ok(Self {
            logical_size,
            mapped_size: rounded,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum Object {
        Channel,
        Region,
        Memory,
    }
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct Rights(u8);
    const CHANNEL: CapabilityExpectation<Object, Rights> = CapabilityExpectation {
        object_type: Object::Channel,
        rights: Rights(1),
    };
    const ROOT: CapabilityExpectation<Object, Rights> = CapabilityExpectation {
        object_type: Object::Region,
        rights: Rights(2),
    };
    const BOOTFS: CapabilityExpectation<Object, Rights> = CapabilityExpectation {
        object_type: Object::Memory,
        rights: Rights(3),
    };
    fn cap(object_type: Object, rights: Rights) -> InitCapability<Object, Rights> {
        let info = CapabilityInfo {
            object_type,
            rights,
        };
        InitCapability {
            received: info,
            fresh: info,
        }
    }
    #[test]
    fn rejects_wrong_type_and_right_sets() {
        assert_eq!(
            BOOTSTRAP_CHANNEL_EXPECTATION.object_type,
            DW_OBJECT_TYPE_CHANNEL
        );
        assert_eq!(
            SELF_ROOT_EXPECTATION.object_type,
            DW_OBJECT_TYPE_ADDRESS_REGION
        );
        assert_eq!(BOOTFS_EXPECTATION.object_type, DW_OBJECT_TYPE_MEMORY_OBJECT);
        assert_eq!(
            validate_bootstrap_channel(
                CapabilityInfo {
                    object_type: Object::Channel,
                    rights: Rights(2)
                },
                CHANNEL
            ),
            Err(CapabilityValidationError::InvalidBootstrapChannel)
        );
        assert_eq!(
            validate_init_capabilities(
                &[
                    cap(Object::Region, Rights(2)),
                    cap(Object::Memory, Rights(3))
                ],
                ROOT,
                BOOTFS
            ),
            Ok(())
        );
        assert_eq!(
            validate_init_capabilities(
                &[
                    cap(Object::Memory, Rights(2)),
                    cap(Object::Memory, Rights(3))
                ],
                ROOT,
                BOOTFS
            ),
            Err(CapabilityValidationError::InvalidReceivedCapability)
        );
        let stale = InitCapability {
            received: CapabilityInfo {
                object_type: Object::Region,
                rights: Rights(2),
            },
            fresh: CapabilityInfo {
                object_type: Object::Memory,
                rights: Rights(3),
            },
        };
        assert_eq!(
            validate_init_capabilities(&[stale, cap(Object::Memory, Rights(3))], ROOT, BOOTFS),
            Err(CapabilityValidationError::InvalidFreshCapability)
        );
        assert_eq!(
            validate_init_capabilities(&[cap(Object::Region, Rights(2))], ROOT, BOOTFS),
            Err(CapabilityValidationError::WrongInitCapabilityCount)
        );
    }
    #[test]
    fn plans_exact_logical_and_rounded_mapping() {
        assert_eq!(
            MappingPlan::for_bootfs(1),
            Ok(MappingPlan {
                logical_size: 1,
                mapped_size: PAGE_SIZE
            })
        );
        assert_eq!(
            MappingPlan::for_bootfs(0),
            Err(MappingPlanError::EmptyArchive)
        );
        assert_eq!(
            MappingPlan::for_bootfs(MAX_BOOTFS_LOGICAL_SIZE + 1),
            Err(MappingPlanError::ArchiveTooLarge)
        );
        assert_eq!(
            MappingPlan::for_limit(u64::MAX, u64::MAX),
            Err(MappingPlanError::RoundingOverflow)
        );
    }
}
