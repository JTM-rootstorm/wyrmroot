//! Canonical, bounded WRDM v1.1 q35 device-role manifest.
//!
//! Minor 1 (root `STORAGE_PLAN.md` W2) admits a second role after COM2: the
//! boot disk, a PCI function whose address and vendor/device IDs occupy the
//! record bytes 64..72 that a port-I/O record keeps zero.

use core::ops::Range;

pub const MAGIC: [u8; 4] = *b"WRDM";
pub const MAJOR: u16 = 1;
pub const MINOR: u16 = 1;
pub const HEADER_BYTES: usize = 32;
pub const RECORD_BYTES: usize = 144;
pub const MAX_RECORDS: usize = 4;
pub const MAX_DRIVER_PATH_BYTES: usize = 64;

pub const PROFILE_Q35: ProfileId = ProfileId(1);
pub const PROFILE_Q35_VERSION: ProfileVersion = ProfileVersion(1);
pub const COM2_ROLE_ID: RoleId = RoleId(1);
pub const UART16550D_PATH: &[u8] = b"system/uart16550d";
pub const SERIAL_TRANSPORT_METADATA_POLICY: MetadataPolicyId = MetadataPolicyId(1);
pub const BOOT_DISK_ROLE_ID: RoleId = RoleId(2);
pub const VIRTIO_BLKD_PATH: &[u8] = b"system/virtio-blkd";
pub const BLOCK_DEVICE_METADATA_POLICY: MetadataPolicyId = MetadataPolicyId(2);
/// The boot device table's resource for the boot disk (root `STORAGE_PLAN.md`
/// W1): q35 bus 0, device 1, function 0, a modern virtio block device.
pub const BOOT_DISK_RESOURCE_ID: u64 = 2;
pub const BOOT_DISK_PCI_ADDRESS: u32 = 1 << 3;
pub const VIRTIO_BLOCK_PCI_IDS: u32 = 0x1af4 | 0x1042 << 16;

/// Stable WYR1-C publication metadata installed by the controller before any
/// device binding exists.  This names a typed device-metadata/control service;
/// it is deliberately not a UART byte-stream protocol or a claim of COM2
/// ownership.
pub const SERIAL_CONSOLE_SERVICE_NAME: &[u8] = b"device.serial.console0";
pub const SERIAL_CONSOLE_PROTOCOL_ID: u64 = 0x5345_5249_414c_4330;
pub const SERIAL_CONSOLE_PROTOCOL_MAJOR: u16 = 1;
/// Historical selector-29 metadata/control profile. This remains byte-exact.
pub const SERIAL_CONSOLE_PROTOCOL_MINOR: u16 = 0;
/// WYR1-D selected-product profile with the direct WRSC connector.
pub const SERIAL_CONSOLE_CONNECTOR_PROTOCOL_MINOR: u16 = 1;
pub const SERIAL_CONSOLE_SUPERVISOR_ROLE_ID: u32 = 2;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PublicationPolicy {
    pub service_name: &'static [u8],
    pub protocol_id: u64,
    pub protocol_major: u16,
    pub protocol_minor: u16,
    pub supervisor_role_id: u32,
}

pub const SERIAL_CONSOLE_PUBLICATION_POLICY: PublicationPolicy = PublicationPolicy {
    service_name: SERIAL_CONSOLE_SERVICE_NAME,
    protocol_id: SERIAL_CONSOLE_PROTOCOL_ID,
    protocol_major: SERIAL_CONSOLE_PROTOCOL_MAJOR,
    protocol_minor: SERIAL_CONSOLE_PROTOCOL_MINOR,
    supervisor_role_id: SERIAL_CONSOLE_SUPERVISOR_ROLE_ID,
};

/// Product-gated WYR1-D connector publication. The stable service and protocol
/// identity are shared with 1.0, but the minor is intentionally distinct.
pub const SERIAL_CONSOLE_CONNECTOR_PUBLICATION_POLICY: PublicationPolicy = PublicationPolicy {
    service_name: SERIAL_CONSOLE_SERVICE_NAME,
    protocol_id: SERIAL_CONSOLE_PROTOCOL_ID,
    protocol_major: SERIAL_CONSOLE_PROTOCOL_MAJOR,
    protocol_minor: SERIAL_CONSOLE_CONNECTOR_PROTOCOL_MINOR,
    supervisor_role_id: SERIAL_CONSOLE_SUPERVISOR_ROLE_ID,
};

/// The boot disk's BlockDevice service (root `STORAGE_PLAN.md` W2/W3). Its
/// `WRBD` protocol is defined by W3; until then a connection offer is closed.
pub const BOOT_DISK_SERVICE_NAME: &[u8] = b"device.block.virtio0";
pub const BLOCK_DEVICE_PROTOCOL_ID: u64 = u64::from_le_bytes(*b"WRBD\0\0\0\0");
pub const BLOCK_DEVICE_SUPERVISOR_ROLE_ID: u32 = 3;

pub const BOOT_DISK_PUBLICATION_POLICY: PublicationPolicy = PublicationPolicy {
    service_name: BOOT_DISK_SERVICE_NAME,
    protocol_id: BLOCK_DEVICE_PROTOCOL_ID,
    protocol_major: 1,
    protocol_minor: 0,
    supervisor_role_id: BLOCK_DEVICE_SUPERVISOR_ROLE_ID,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProfileId(pub u32);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProfileVersion(pub u32);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RoleId(pub u64);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ContentIdentity(pub [u8; 32]);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MetadataPolicyId(pub u32);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PioRange {
    pub base: u16,
    pub length: u16,
}

impl PioRange {
    pub const fn end(self) -> u32 {
        self.base as u32 + self.length as u32
    }

    pub(crate) const fn as_range(self) -> Range<u32> {
        self.base as u32..self.end()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeviceRole<'a> {
    pub role_id: RoleId,
    pub hardware: Hardware,
    pub resource_kind: ResourceKind,
    pub pio: PioRange,
    pub irq: u32,
    /// The PCI function of a [`ResourceKind::PciFunction`] role.
    pub pci: Option<PciFunction>,
    pub driver_path: &'a [u8],
    pub content_identity: ContentIdentity,
    pub metadata_policy: MetadataPolicyId,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Hardware {
    Com1,
    Com2,
    BootDisk,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResourceKind {
    PioInterrupt,
    PciFunction,
}

/// One PCI function, as the boot device table names it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PciFunction {
    /// `segment<<16 | bus<<8 | device<<3 | function`.
    pub address: u32,
    /// `vendor | device<<16`.
    pub ids: u32,
}

/// The fixed boot-disk role (root `STORAGE_PLAN.md` W2).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BootDiskPolicy {
    pub role_id: RoleId,
    pub resource_id: u64,
    pub pci: PciFunction,
    pub driver_path: &'static [u8],
    pub metadata_policy: MetadataPolicyId,
}

pub const BOOT_DISK_POLICY: BootDiskPolicy = BootDiskPolicy {
    role_id: BOOT_DISK_ROLE_ID,
    resource_id: BOOT_DISK_RESOURCE_ID,
    pci: PciFunction {
        address: BOOT_DISK_PCI_ADDRESS,
        ids: VIRTIO_BLOCK_PCI_IDS,
    },
    driver_path: VIRTIO_BLKD_PATH,
    metadata_policy: BLOCK_DEVICE_METADATA_POLICY,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Com2Policy {
    pub role_id: RoleId,
    pub profile: ProfileId,
    pub profile_version: ProfileVersion,
    pub pio: PioRange,
    pub irq: u32,
    pub driver_path: &'static [u8],
    pub metadata_policy: MetadataPolicyId,
}

pub const COM2_POLICY: Com2Policy = Com2Policy {
    role_id: COM2_ROLE_ID,
    profile: PROFILE_Q35,
    profile_version: PROFILE_Q35_VERSION,
    pio: PioRange {
        base: 0x2f8,
        length: 8,
    },
    irq: 3,
    driver_path: UART16550D_PATH,
    metadata_policy: SERIAL_TRANSPORT_METADATA_POLICY,
};

/// Encode the one canonical WYR1-C1 q35 COM2 role.
///
/// The caller supplies only the immutable driver content identity. Every
/// hardware and policy field is fixed here so host product tooling cannot
/// accidentally mint a second dialect of WRDM.
pub fn encode_com2_manifest(
    content_identity: ContentIdentity,
    output: &mut [u8],
) -> Result<usize, ManifestError> {
    encode_roles(content_identity, None, output)
}

/// Encode the product role set: COM2, then the boot disk (`STORAGE_PLAN.md`
/// W2). As with [`encode_com2_manifest`], only the two driver identities come
/// from the caller.
pub fn encode_product_manifest(
    uart_identity: ContentIdentity,
    block_identity: ContentIdentity,
    output: &mut [u8],
) -> Result<usize, ManifestError> {
    encode_roles(uart_identity, Some(block_identity), output)
}

fn encode_roles(
    uart_identity: ContentIdentity,
    block_identity: Option<ContentIdentity>,
    output: &mut [u8],
) -> Result<usize, ManifestError> {
    let count = 1 + usize::from(block_identity.is_some());
    let total = HEADER_BYTES + count * RECORD_BYTES;
    if output.len() < total {
        return Err(ManifestError::WrongSize);
    }
    if uart_identity.0.iter().all(|byte| *byte == 0)
        || block_identity.is_some_and(|identity| identity.0.iter().all(|byte| *byte == 0))
    {
        return Err(ManifestError::ZeroContentIdentity);
    }
    output[..total].fill(0);
    output[..4].copy_from_slice(&MAGIC);
    output[4..6].copy_from_slice(&MAJOR.to_le_bytes());
    output[6..8].copy_from_slice(&MINOR.to_le_bytes());
    output[8..12].copy_from_slice(&(total as u32).to_le_bytes());
    output[12..14].copy_from_slice(&(count as u16).to_le_bytes());
    output[16..20].copy_from_slice(&COM2_POLICY.profile.0.to_le_bytes());
    output[20..24].copy_from_slice(&COM2_POLICY.profile_version.0.to_le_bytes());

    let base = HEADER_BYTES;
    output[base..base + 8].copy_from_slice(&COM2_POLICY.role_id.0.to_le_bytes());
    output[base + 8..base + 12].copy_from_slice(&2u32.to_le_bytes());
    output[base + 12..base + 16].copy_from_slice(&1u32.to_le_bytes());
    output[base + 16..base + 18].copy_from_slice(&COM2_POLICY.pio.base.to_le_bytes());
    output[base + 18..base + 20].copy_from_slice(&COM2_POLICY.pio.length.to_le_bytes());
    output[base + 20..base + 24].copy_from_slice(&COM2_POLICY.irq.to_le_bytes());
    output[base + 24..base + 26]
        .copy_from_slice(&(COM2_POLICY.driver_path.len() as u16).to_le_bytes());
    output[base + 28..base + 60].copy_from_slice(&uart_identity.0);
    output[base + 60..base + 64].copy_from_slice(&COM2_POLICY.metadata_policy.0.to_le_bytes());
    output[base + 72..base + 72 + COM2_POLICY.driver_path.len()]
        .copy_from_slice(COM2_POLICY.driver_path);

    if let Some(identity) = block_identity {
        let base = HEADER_BYTES + RECORD_BYTES;
        let policy = BOOT_DISK_POLICY;
        output[base..base + 8].copy_from_slice(&policy.role_id.0.to_le_bytes());
        output[base + 8..base + 12].copy_from_slice(&3u32.to_le_bytes());
        output[base + 12..base + 16].copy_from_slice(&2u32.to_le_bytes());
        output[base + 24..base + 26]
            .copy_from_slice(&(policy.driver_path.len() as u16).to_le_bytes());
        output[base + 28..base + 60].copy_from_slice(&identity.0);
        output[base + 60..base + 64].copy_from_slice(&policy.metadata_policy.0.to_le_bytes());
        output[base + 64..base + 68].copy_from_slice(&policy.pci.address.to_le_bytes());
        output[base + 68..base + 72].copy_from_slice(&policy.pci.ids.to_le_bytes());
        output[base + 72..base + 72 + policy.driver_path.len()].copy_from_slice(policy.driver_path);
    }
    Ok(total)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Manifest<'a> {
    pub profile: ProfileId,
    pub profile_version: ProfileVersion,
    records: [Option<DeviceRole<'a>>; MAX_RECORDS],
    count: usize,
}

impl<'a> Manifest<'a> {
    /// Parses a WRDM manifest from its page-granular immutable object view.
    ///
    /// The WRDM header remains the sole logical-length authority. Any bytes
    /// beyond that exact logical extent must be zero, so page alignment cannot
    /// smuggle a second policy payload past the strict [`Self::parse`] path.
    pub fn parse_padded(bytes: &'a [u8]) -> Result<Self, ManifestError> {
        if bytes.len() < HEADER_BYTES {
            return Err(ManifestError::WrongSize);
        }
        if bytes[..4] != MAGIC {
            return Err(ManifestError::WrongMagic);
        }
        if get_u16(bytes, 4) != MAJOR || get_u16(bytes, 6) != MINOR {
            return Err(ManifestError::WrongVersion);
        }
        let total = get_u32(bytes, 8) as usize;
        if total < HEADER_BYTES || total > bytes.len() {
            return Err(ManifestError::WrongSize);
        }
        if bytes[total..].iter().any(|byte| *byte != 0) {
            return Err(ManifestError::NonzeroObjectPadding);
        }
        Self::parse(&bytes[..total])
    }

    pub fn parse(bytes: &'a [u8]) -> Result<Self, ManifestError> {
        if bytes.len() < HEADER_BYTES {
            return Err(ManifestError::WrongSize);
        }
        if bytes[..4] != MAGIC {
            return Err(ManifestError::WrongMagic);
        }
        if get_u16(bytes, 4) != MAJOR || get_u16(bytes, 6) != MINOR {
            return Err(ManifestError::WrongVersion);
        }
        let total = get_u32(bytes, 8) as usize;
        let count = get_u16(bytes, 12) as usize;
        if total != bytes.len() || count == 0 || count > MAX_RECORDS {
            return Err(ManifestError::WrongSize);
        }
        if get_u16(bytes, 14) != 0 || get_u64(bytes, 24) != 0 {
            return Err(ManifestError::NonzeroReserved);
        }
        let profile = ProfileId(get_u32(bytes, 16));
        let profile_version = ProfileVersion(get_u32(bytes, 20));
        if profile != PROFILE_Q35 || profile_version != PROFILE_Q35_VERSION {
            return Err(ManifestError::WrongProfile);
        }
        let expected = HEADER_BYTES
            .checked_add(
                count
                    .checked_mul(RECORD_BYTES)
                    .ok_or(ManifestError::WrongSize)?,
            )
            .ok_or(ManifestError::WrongSize)?;
        if expected != bytes.len() {
            return Err(ManifestError::WrongSize);
        }

        let mut records: [Option<DeviceRole<'a>>; MAX_RECORDS] = [None; MAX_RECORDS];
        for index in 0..count {
            let base = HEADER_BYTES + index * RECORD_BYTES;
            let record = parse_record(bytes, base)?;
            for previous in records.iter().flatten() {
                if previous.role_id == record.role_id {
                    return Err(ManifestError::DuplicateRole);
                }
                if previous.pci.is_some() || record.pci.is_some() {
                    if previous.pci == record.pci {
                        return Err(ManifestError::DuplicateRole);
                    }
                    continue;
                }
                if previous.irq == record.irq {
                    return Err(ManifestError::DuplicateIrq);
                }
                if previous
                    .pio
                    .as_range()
                    .any(|port| record.pio.as_range().contains(&port))
                {
                    return Err(ManifestError::OverlappingPio);
                }
            }
            records[index] = Some(record);
        }
        Ok(Self {
            profile,
            profile_version,
            records,
            count,
        })
    }

    pub const fn len(&self) -> usize {
        self.count
    }
    pub const fn is_empty(&self) -> bool {
        self.count == 0
    }

    pub fn get(&self, index: usize) -> Option<DeviceRole<'a>> {
        self.records.get(index).copied().flatten()
    }

    /// Admit the WYR1-C COM2 role, checking the complete fixed policy and the
    /// exact role set: COM2 first, then at most the boot disk. The content
    /// identity is supplied by the immutable product manifest rather than
    /// inferred from a path string.
    pub fn match_com2(
        &self,
        expected_content: ContentIdentity,
    ) -> Result<DeviceRole<'a>, ManifestError> {
        self.check_role_set()?;
        let role = self.records[0].ok_or(ManifestError::WrongSize)?;
        if role.role_id != COM2_POLICY.role_id {
            return Err(ManifestError::UnknownRole);
        }
        if role.hardware != Hardware::Com2 {
            return Err(ManifestError::Com1Rejected);
        }
        if role.resource_kind != ResourceKind::PioInterrupt
            || role.pio != COM2_POLICY.pio
            || role.irq != COM2_POLICY.irq
        {
            return Err(ManifestError::WrongResource);
        }
        if role.driver_path != COM2_POLICY.driver_path {
            return Err(ManifestError::WrongDriverPath);
        }
        if role.metadata_policy != COM2_POLICY.metadata_policy {
            return Err(ManifestError::WrongMetadataPolicy);
        }
        if role.content_identity != expected_content {
            return Err(ManifestError::WrongContentIdentity);
        }
        Ok(role)
    }

    /// The boot-disk role, if the manifest has one, checked against the
    /// complete fixed [`BOOT_DISK_POLICY`]. The identity is not checked here:
    /// [`Self::match_boot_disk`] does that for a caller that knows it.
    pub fn boot_disk(&self) -> Result<Option<DeviceRole<'a>>, ManifestError> {
        self.check_role_set()?;
        let Some(role) = self.records[1] else {
            return Ok(None);
        };
        if role.role_id != BOOT_DISK_POLICY.role_id {
            return Err(ManifestError::UnknownRole);
        }
        if role.hardware != Hardware::BootDisk
            || role.resource_kind != ResourceKind::PciFunction
            || role.pci != Some(BOOT_DISK_POLICY.pci)
        {
            return Err(ManifestError::WrongResource);
        }
        if role.driver_path != BOOT_DISK_POLICY.driver_path {
            return Err(ManifestError::WrongDriverPath);
        }
        if role.metadata_policy != BOOT_DISK_POLICY.metadata_policy {
            return Err(ManifestError::WrongMetadataPolicy);
        }
        Ok(Some(role))
    }

    /// Admit the boot-disk role with exactly `expected_content`.
    pub fn match_boot_disk(
        &self,
        expected_content: ContentIdentity,
    ) -> Result<DeviceRole<'a>, ManifestError> {
        let role = self
            .boot_disk()?
            .ok_or(ManifestError::UnexpectedRoleCount)?;
        if role.content_identity != expected_content {
            return Err(ManifestError::WrongContentIdentity);
        }
        Ok(role)
    }

    /// The role whose ID is `role_id`, if this manifest has it.
    pub fn role(&self, role_id: RoleId) -> Option<DeviceRole<'a>> {
        self.records[..self.count]
            .iter()
            .flatten()
            .find(|role| role.role_id == role_id)
            .copied()
    }

    fn check_role_set(&self) -> Result<(), ManifestError> {
        if self.count != 1 && self.count != 2 {
            return Err(ManifestError::UnexpectedRoleCount);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ManifestError {
    WrongSize,
    WrongMagic,
    WrongVersion,
    WrongProfile,
    NonzeroReserved,
    NonzeroObjectPadding,
    ZeroRole,
    UnknownHardware,
    UnknownResourceKind,
    ZeroPioLength,
    PioRangeOverflow,
    ZeroIrq,
    ZeroContentIdentity,
    ZeroMetadataPolicy,
    PathEmpty,
    PathTooLong,
    NonzeroPathPadding,
    DuplicateRole,
    DuplicateIrq,
    OverlappingPio,
    UnexpectedRoleCount,
    UnknownRole,
    Com1Rejected,
    WrongResource,
    WrongDriverPath,
    WrongMetadataPolicy,
    WrongContentIdentity,
}

fn parse_record<'a>(bytes: &'a [u8], base: usize) -> Result<DeviceRole<'a>, ManifestError> {
    let role_id = RoleId(get_u64(bytes, base));
    if role_id.0 == 0 {
        return Err(ManifestError::ZeroRole);
    }
    let hardware = match get_u32(bytes, base + 8) {
        1 => Hardware::Com1,
        2 => Hardware::Com2,
        3 => Hardware::BootDisk,
        _ => return Err(ManifestError::UnknownHardware),
    };
    let resource_kind = match get_u32(bytes, base + 12) {
        1 => ResourceKind::PioInterrupt,
        2 => ResourceKind::PciFunction,
        _ => return Err(ManifestError::UnknownResourceKind),
    };
    let pio = PioRange {
        base: get_u16(bytes, base + 16),
        length: get_u16(bytes, base + 18),
    };
    let irq = get_u32(bytes, base + 20);
    let pci_fields = PciFunction {
        address: get_u32(bytes, base + 64),
        ids: get_u32(bytes, base + 68),
    };
    let pci = match resource_kind {
        ResourceKind::PioInterrupt => {
            if pio.length == 0 {
                return Err(ManifestError::ZeroPioLength);
            }
            if pio.end() > 0x1_0000 {
                return Err(ManifestError::PioRangeOverflow);
            }
            if irq == 0 {
                return Err(ManifestError::ZeroIrq);
            }
            if pci_fields.address != 0 || pci_fields.ids != 0 {
                return Err(ManifestError::NonzeroReserved);
            }
            None
        }
        ResourceKind::PciFunction => {
            if pio.base != 0 || pio.length != 0 || irq != 0 {
                return Err(ManifestError::NonzeroReserved);
            }
            // Segment 0 only, and a vendor that is neither absent nor zero.
            let vendor = pci_fields.ids & 0xffff;
            if pci_fields.address >> 16 != 0 || vendor == 0 || vendor == 0xffff {
                return Err(ManifestError::WrongResource);
            }
            Some(pci_fields)
        }
    };
    let path_len = get_u16(bytes, base + 24) as usize;
    if path_len == 0 {
        return Err(ManifestError::PathEmpty);
    }
    if path_len > MAX_DRIVER_PATH_BYTES {
        return Err(ManifestError::PathTooLong);
    }
    if get_u16(bytes, base + 26) != 0
        || bytes[base + 136..base + RECORD_BYTES]
            .iter()
            .any(|byte| *byte != 0)
    {
        return Err(ManifestError::NonzeroReserved);
    }
    let content_identity = ContentIdentity(
        bytes[base + 28..base + 60]
            .try_into()
            .expect("validated fixed record"),
    );
    if content_identity.0.iter().all(|byte| *byte == 0) {
        return Err(ManifestError::ZeroContentIdentity);
    }
    let metadata_policy = MetadataPolicyId(get_u32(bytes, base + 60));
    if metadata_policy.0 == 0 {
        return Err(ManifestError::ZeroMetadataPolicy);
    }
    let path = bytes
        .get(base + 72..base + 72 + MAX_DRIVER_PATH_BYTES)
        .ok_or(ManifestError::WrongSize)?;
    if path[path_len..].iter().any(|byte| *byte != 0) {
        return Err(ManifestError::NonzeroPathPadding);
    }
    Ok(DeviceRole {
        role_id,
        hardware,
        resource_kind,
        pio,
        irq,
        pci,
        driver_path: &path[..path_len],
        content_identity,
        metadata_policy,
    })
}

fn get_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([bytes[offset], bytes[offset + 1]])
}
fn get_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(
        bytes[offset..offset + 4]
            .try_into()
            .expect("validated fixed record"),
    )
}
fn get_u64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(
        bytes[offset..offset + 8]
            .try_into()
            .expect("validated fixed record"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest(
        role: u64,
        hardware: u32,
        base: u16,
        irq: u32,
        path: &[u8],
        content: u8,
    ) -> [u8; HEADER_BYTES + RECORD_BYTES] {
        let mut out = [0u8; HEADER_BYTES + RECORD_BYTES];
        out[..4].copy_from_slice(&MAGIC);
        out[4..6].copy_from_slice(&MAJOR.to_le_bytes());
        out[6..8].copy_from_slice(&MINOR.to_le_bytes());
        let total = out.len() as u32;
        out[8..12].copy_from_slice(&total.to_le_bytes());
        out[12..14].copy_from_slice(&1u16.to_le_bytes());
        out[16..20].copy_from_slice(&PROFILE_Q35.0.to_le_bytes());
        out[20..24].copy_from_slice(&PROFILE_Q35_VERSION.0.to_le_bytes());
        let b = HEADER_BYTES;
        out[b..b + 8].copy_from_slice(&role.to_le_bytes());
        out[b + 8..b + 12].copy_from_slice(&hardware.to_le_bytes());
        out[b + 12..b + 16].copy_from_slice(&1u32.to_le_bytes());
        out[b + 16..b + 18].copy_from_slice(&base.to_le_bytes());
        out[b + 18..b + 20].copy_from_slice(&8u16.to_le_bytes());
        out[b + 20..b + 24].copy_from_slice(&irq.to_le_bytes());
        out[b + 24..b + 26].copy_from_slice(&(path.len() as u16).to_le_bytes());
        out[b + 28..b + 60].copy_from_slice(&[content; 32]);
        out[b + 60..b + 64].copy_from_slice(&1u32.to_le_bytes());
        out[b + 72..b + 72 + path.len()].copy_from_slice(path);
        out
    }

    #[test]
    fn exact_com2_policy_matches() {
        let bytes = manifest(1, 2, 0x2f8, 3, UART16550D_PATH, 9);
        let parsed = Manifest::parse(&bytes).unwrap();
        assert_eq!(
            parsed
                .match_com2(ContentIdentity([9; 32]))
                .unwrap()
                .pio
                .end(),
            0x300
        );
    }

    #[test]
    fn canonical_com2_encoder_round_trips_and_zeroes_tail() {
        let mut bytes = [0xa5; HEADER_BYTES + RECORD_BYTES + 7];
        let size = encode_com2_manifest(ContentIdentity([9; 32]), &mut bytes).unwrap();
        assert_eq!(size, HEADER_BYTES + RECORD_BYTES);
        assert!(bytes[size..].iter().all(|byte| *byte == 0xa5));
        let parsed = Manifest::parse(&bytes[..size]).unwrap();
        assert_eq!(
            parsed.match_com2(ContentIdentity([9; 32])).unwrap().pio,
            COM2_POLICY.pio
        );
        assert_eq!(
            encode_com2_manifest(ContentIdentity([0; 32]), &mut bytes),
            Err(ManifestError::ZeroContentIdentity)
        );
        assert_eq!(
            encode_com2_manifest(ContentIdentity([9; 32]), &mut bytes[..16]),
            Err(ManifestError::WrongSize)
        );
    }

    #[test]
    fn page_granular_object_view_uses_declared_extent_and_rejects_hidden_tail() {
        let exact = manifest(1, 2, 0x2f8, 3, UART16550D_PATH, 9);
        let mut page = [0u8; 4096];
        page[..exact.len()].copy_from_slice(&exact);

        assert_eq!(Manifest::parse(&page), Err(ManifestError::WrongSize));
        assert_eq!(Manifest::parse_padded(&page).unwrap().len(), 1);

        page[exact.len()] = 1;
        assert_eq!(
            Manifest::parse_padded(&page),
            Err(ManifestError::NonzeroObjectPadding)
        );
        page[exact.len()] = 0;
        page[8..12].copy_from_slice(&4097u32.to_le_bytes());
        assert_eq!(Manifest::parse_padded(&page), Err(ManifestError::WrongSize));
    }

    #[test]
    fn serial_console_publication_policy_is_fixed_metadata_only() {
        assert_eq!(SERIAL_CONSOLE_SERVICE_NAME, b"device.serial.console0");
        assert_ne!(SERIAL_CONSOLE_PROTOCOL_ID, 0);
        assert_eq!(SERIAL_CONSOLE_PROTOCOL_MAJOR, 1);
        assert_eq!(SERIAL_CONSOLE_PROTOCOL_MINOR, 0);
        assert_eq!(SERIAL_CONSOLE_SUPERVISOR_ROLE_ID, 2);
        assert_eq!(
            SERIAL_CONSOLE_PUBLICATION_POLICY,
            PublicationPolicy {
                service_name: SERIAL_CONSOLE_SERVICE_NAME,
                protocol_id: SERIAL_CONSOLE_PROTOCOL_ID,
                protocol_major: SERIAL_CONSOLE_PROTOCOL_MAJOR,
                protocol_minor: SERIAL_CONSOLE_PROTOCOL_MINOR,
                supervisor_role_id: SERIAL_CONSOLE_SUPERVISOR_ROLE_ID,
            }
        );
        assert_eq!(SERIAL_CONSOLE_CONNECTOR_PROTOCOL_MINOR, 1);
        assert_eq!(
            SERIAL_CONSOLE_CONNECTOR_PUBLICATION_POLICY,
            PublicationPolicy {
                protocol_minor: 1,
                ..SERIAL_CONSOLE_PUBLICATION_POLICY
            }
        );
    }

    #[test]
    fn rejects_com1_and_wrong_driver() {
        let mut bytes = manifest(1, 1, 0x3f8, 4, UART16550D_PATH, 9);
        assert_eq!(
            Manifest::parse(&bytes)
                .unwrap()
                .match_com2(ContentIdentity([9; 32])),
            Err(ManifestError::Com1Rejected)
        );
        bytes[HEADER_BYTES + 8..HEADER_BYTES + 12].copy_from_slice(&2u32.to_le_bytes());
        bytes[HEADER_BYTES + 16..HEADER_BYTES + 18].copy_from_slice(&0x2f8u16.to_le_bytes());
        bytes[HEADER_BYTES + 20..HEADER_BYTES + 24].copy_from_slice(&3u32.to_le_bytes());
        bytes[HEADER_BYTES + 72] = b'x';
        let parsed = Manifest::parse(&bytes).unwrap();
        assert_eq!(
            parsed.match_com2(ContentIdentity([9; 32])),
            Err(ManifestError::WrongDriverPath)
        );
    }

    #[test]
    fn rejects_overflow_reserved_and_duplicate() {
        let mut bytes = manifest(1, 2, 0xffff, 3, UART16550D_PATH, 9);
        assert_eq!(
            Manifest::parse(&bytes),
            Err(ManifestError::PioRangeOverflow)
        );
        bytes = manifest(1, 2, 0x2f8, 3, UART16550D_PATH, 9);
        bytes[14] = 1;
        assert_eq!(Manifest::parse(&bytes), Err(ManifestError::NonzeroReserved));
        bytes[14] = 0;
        assert_eq!(
            Manifest::parse(&bytes)
                .unwrap()
                .match_com2(ContentIdentity([8; 32])),
            Err(ManifestError::WrongContentIdentity)
        );
    }

    #[test]
    fn rejects_wrong_metadata_and_unchecked_tail_bytes() {
        let mut bytes = manifest(1, 2, 0x2f8, 3, UART16550D_PATH, 9);
        bytes[HEADER_BYTES + 60..HEADER_BYTES + 64].copy_from_slice(&2u32.to_le_bytes());
        assert_eq!(
            Manifest::parse(&bytes)
                .unwrap()
                .match_com2(ContentIdentity([9; 32])),
            Err(ManifestError::WrongMetadataPolicy)
        );
        bytes[HEADER_BYTES + 60..HEADER_BYTES + 64].copy_from_slice(&1u32.to_le_bytes());
        bytes[HEADER_BYTES + RECORD_BYTES - 1] = 1;
        assert_eq!(Manifest::parse(&bytes), Err(ManifestError::NonzeroReserved));
    }

    #[test]
    fn structural_header_and_record_failures_are_closed() {
        let baseline = manifest(1, 2, 0x2f8, 3, UART16550D_PATH, 9);
        let mut bad = baseline;
        bad[6] = 2;
        assert_eq!(Manifest::parse(&bad), Err(ManifestError::WrongVersion));
        bad = baseline;
        bad[6] = 0;
        assert_eq!(Manifest::parse(&bad), Err(ManifestError::WrongVersion));
        bad = baseline;
        bad[16..20].copy_from_slice(&2u32.to_le_bytes());
        assert_eq!(Manifest::parse(&bad), Err(ManifestError::WrongProfile));
        bad = baseline;
        bad[HEADER_BYTES..HEADER_BYTES + 8].fill(0);
        assert_eq!(Manifest::parse(&bad), Err(ManifestError::ZeroRole));
        bad = baseline;
        bad[HEADER_BYTES + 12..HEADER_BYTES + 16].copy_from_slice(&3u32.to_le_bytes());
        assert_eq!(
            Manifest::parse(&bad),
            Err(ManifestError::UnknownResourceKind)
        );
        bad = baseline;
        bad[HEADER_BYTES + 64] = 1;
        assert_eq!(Manifest::parse(&bad), Err(ManifestError::NonzeroReserved));
        bad = baseline;
        bad[HEADER_BYTES + 18..HEADER_BYTES + 20].fill(0);
        assert_eq!(Manifest::parse(&bad), Err(ManifestError::ZeroPioLength));
        bad = baseline;
        bad[HEADER_BYTES + 28..HEADER_BYTES + 60].fill(0);
        assert_eq!(
            Manifest::parse(&bad),
            Err(ManifestError::ZeroContentIdentity)
        );
        bad = baseline;
        bad[HEADER_BYTES + 72 + UART16550D_PATH.len()] = 1;
        assert_eq!(
            Manifest::parse(&bad),
            Err(ManifestError::NonzeroPathPadding)
        );
    }

    #[test]
    fn duplicate_and_overlap_relations_are_rejected() {
        let one = manifest(1, 2, 0x2f8, 3, UART16550D_PATH, 9);
        let mut two = [0u8; HEADER_BYTES + 2 * RECORD_BYTES];
        two[..HEADER_BYTES].copy_from_slice(&one[..HEADER_BYTES]);
        two[HEADER_BYTES..HEADER_BYTES + RECORD_BYTES].copy_from_slice(&one[HEADER_BYTES..]);
        two[HEADER_BYTES + RECORD_BYTES..].copy_from_slice(&one[HEADER_BYTES..]);
        let total = two.len() as u32;
        two[8..12].copy_from_slice(&total.to_le_bytes());
        two[12..14].copy_from_slice(&2u16.to_le_bytes());
        assert_eq!(Manifest::parse(&two), Err(ManifestError::DuplicateRole));

        let second = HEADER_BYTES + RECORD_BYTES;
        two[second..second + 8].copy_from_slice(&2u64.to_le_bytes());
        assert_eq!(Manifest::parse(&two), Err(ManifestError::DuplicateIrq));
        two[second + 20..second + 24].copy_from_slice(&5u32.to_le_bytes());
        assert_eq!(Manifest::parse(&two), Err(ManifestError::OverlappingPio));
    }

    fn product(block: u8) -> [u8; HEADER_BYTES + 2 * RECORD_BYTES] {
        let mut bytes = [0u8; HEADER_BYTES + 2 * RECORD_BYTES];
        let size = encode_product_manifest(
            ContentIdentity([9; 32]),
            ContentIdentity([block; 32]),
            &mut bytes,
        )
        .unwrap();
        assert_eq!(size, bytes.len());
        bytes
    }

    #[test]
    fn product_manifest_admits_com2_then_the_boot_disk() {
        let bytes = product(7);
        let parsed = Manifest::parse(&bytes).unwrap();
        assert_eq!(parsed.len(), 2);
        assert_eq!(
            parsed.match_com2(ContentIdentity([9; 32])).unwrap().role_id,
            COM2_ROLE_ID
        );
        let disk = parsed.match_boot_disk(ContentIdentity([7; 32])).unwrap();
        assert_eq!(disk.role_id, BOOT_DISK_ROLE_ID);
        assert_eq!(disk.pci, Some(BOOT_DISK_POLICY.pci));
        assert_eq!(disk.driver_path, VIRTIO_BLKD_PATH);
        assert_eq!(disk.pio, PioRange { base: 0, length: 0 });
        assert_eq!(
            parsed.match_boot_disk(ContentIdentity([9; 32])),
            Err(ManifestError::WrongContentIdentity)
        );
        assert_eq!(parsed.role(BOOT_DISK_ROLE_ID), Some(disk));
        assert_eq!(parsed.role(RoleId(3)), None);
    }

    #[test]
    fn com2_only_manifest_has_no_boot_disk() {
        let mut bytes = [0u8; HEADER_BYTES + RECORD_BYTES];
        encode_com2_manifest(ContentIdentity([9; 32]), &mut bytes).unwrap();
        let parsed = Manifest::parse(&bytes).unwrap();
        assert_eq!(parsed.boot_disk(), Ok(None));
        assert_eq!(
            parsed.match_boot_disk(ContentIdentity([9; 32])),
            Err(ManifestError::UnexpectedRoleCount)
        );
    }

    #[test]
    fn boot_disk_record_rejects_every_field_outside_its_policy() {
        let second = HEADER_BYTES + RECORD_BYTES;
        let check = |offset: usize, value: &[u8], expected: ManifestError| {
            let mut bytes = product(7);
            bytes[offset..offset + value.len()].copy_from_slice(value);
            let result = Manifest::parse(&bytes)
                .and_then(|parsed| parsed.match_boot_disk(ContentIdentity([7; 32])));
            assert_eq!(result, Err(expected), "offset {offset}");
        };
        // Port-I/O and interrupt fields belong to the other kind.
        check(
            second + 16,
            &1u16.to_le_bytes(),
            ManifestError::NonzeroReserved,
        );
        check(
            second + 18,
            &1u16.to_le_bytes(),
            ManifestError::NonzeroReserved,
        );
        check(
            second + 20,
            &1u32.to_le_bytes(),
            ManifestError::NonzeroReserved,
        );
        // Another function, other IDs, segment 1, or no vendor.
        check(
            second + 64,
            &(2u32 << 3).to_le_bytes(),
            ManifestError::WrongResource,
        );
        check(
            second + 68,
            &0x1001_1af4u32.to_le_bytes(),
            ManifestError::WrongResource,
        );
        check(
            second + 66,
            &1u16.to_le_bytes(),
            ManifestError::WrongResource,
        );
        check(
            second + 68,
            &0xffffu16.to_le_bytes(),
            ManifestError::WrongResource,
        );
        check(
            second + 68,
            &0u16.to_le_bytes(),
            ManifestError::WrongResource,
        );
        // Another role, hardware, driver or metadata policy.
        check(second, &3u64.to_le_bytes(), ManifestError::UnknownRole);
        check(
            second + 8,
            &2u32.to_le_bytes(),
            ManifestError::WrongResource,
        );
        check(second + 72, b"x", ManifestError::WrongDriverPath);
        check(
            second + 60,
            &1u32.to_le_bytes(),
            ManifestError::WrongMetadataPolicy,
        );
        check(second + 136, &[1], ManifestError::NonzeroReserved);
    }

    #[test]
    fn a_port_record_may_not_carry_pci_fields_and_two_roles_may_not_share_a_function() {
        let mut bytes = product(7);
        bytes[HEADER_BYTES + 68] = 1;
        assert_eq!(Manifest::parse(&bytes), Err(ManifestError::NonzeroReserved));

        // The boot disk in the first slot is not the role set COM2 needs.
        let mut swapped = product(7);
        let (first, second) = swapped[HEADER_BYTES..].split_at_mut(RECORD_BYTES);
        first.swap_with_slice(&mut second[..RECORD_BYTES]);
        let parsed = Manifest::parse(&swapped).unwrap();
        assert_eq!(
            parsed.match_com2(ContentIdentity([9; 32])),
            Err(ManifestError::UnknownRole)
        );
        assert_eq!(parsed.boot_disk(), Err(ManifestError::UnknownRole));
    }

    #[test]
    fn product_encoder_refuses_a_zero_block_identity() {
        let mut bytes = [0u8; HEADER_BYTES + 2 * RECORD_BYTES];
        assert_eq!(
            encode_product_manifest(
                ContentIdentity([9; 32]),
                ContentIdentity([0; 32]),
                &mut bytes
            ),
            Err(ManifestError::ZeroContentIdentity)
        );
        assert_eq!(
            encode_product_manifest(
                ContentIdentity([9; 32]),
                ContentIdentity([7; 32]),
                &mut bytes[..HEADER_BYTES + RECORD_BYTES]
            ),
            Err(ManifestError::WrongSize)
        );
    }
}
