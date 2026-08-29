//! Canonical, bounded WRDM v1 q35 device-role manifest.

use core::ops::Range;

pub const MAGIC: [u8; 4] = *b"WRDM";
pub const MAJOR: u16 = 1;
pub const MINOR: u16 = 0;
pub const HEADER_BYTES: usize = 32;
pub const RECORD_BYTES: usize = 112;
pub const MAX_RECORDS: usize = 4;
pub const MAX_DRIVER_PATH_BYTES: usize = 64;

pub const PROFILE_Q35: ProfileId = ProfileId(1);
pub const PROFILE_Q35_VERSION: ProfileVersion = ProfileVersion(1);
pub const COM2_ROLE_ID: RoleId = RoleId(1);
pub const UART16550D_PATH: &[u8] = b"system/uart16550d";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProfileId(pub u32);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProfileVersion(pub u32);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RoleId(pub u64);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ContentIdentity(pub u64);

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

    pub const fn as_range(self) -> Range<u32> {
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
    pub driver_path: &'a [u8],
    pub content_identity: ContentIdentity,
    pub metadata_policy: MetadataPolicyId,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Hardware {
    Com1,
    Com2,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResourceKind {
    Pio,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Com2Policy {
    pub role_id: RoleId,
    pub profile: ProfileId,
    pub profile_version: ProfileVersion,
    pub pio: PioRange,
    pub irq: u32,
    pub driver_path: &'static [u8],
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
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Manifest<'a> {
    pub profile: ProfileId,
    pub profile_version: ProfileVersion,
    records: [Option<DeviceRole<'a>>; MAX_RECORDS],
    count: usize,
}

impl<'a> Manifest<'a> {
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

    /// Admit the one WYR1-C role, checking the complete fixed policy.  The
    /// content identity is supplied by the immutable product manifest rather
    /// than inferred from a path string.
    pub fn match_com2(
        &self,
        expected_content: ContentIdentity,
    ) -> Result<DeviceRole<'a>, ManifestError> {
        if self.count != 1 {
            return Err(ManifestError::UnexpectedRoleCount);
        }
        let role = self.records[0].ok_or(ManifestError::WrongSize)?;
        if role.role_id != COM2_POLICY.role_id {
            return Err(ManifestError::UnknownRole);
        }
        if role.hardware != Hardware::Com2 {
            return Err(ManifestError::Com1Rejected);
        }
        if role.resource_kind != ResourceKind::Pio
            || role.pio != COM2_POLICY.pio
            || role.irq != COM2_POLICY.irq
        {
            return Err(ManifestError::WrongResource);
        }
        if role.driver_path != COM2_POLICY.driver_path {
            return Err(ManifestError::WrongDriverPath);
        }
        if role.content_identity != expected_content {
            return Err(ManifestError::WrongContentIdentity);
        }
        Ok(role)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ManifestError {
    WrongSize,
    WrongMagic,
    WrongVersion,
    WrongProfile,
    NonzeroReserved,
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
        _ => return Err(ManifestError::UnknownHardware),
    };
    let resource_kind = match get_u32(bytes, base + 12) {
        1 => ResourceKind::Pio,
        _ => return Err(ManifestError::UnknownResourceKind),
    };
    let pio = PioRange {
        base: get_u16(bytes, base + 16),
        length: get_u16(bytes, base + 18),
    };
    if pio.length == 0 {
        return Err(ManifestError::ZeroPioLength);
    }
    if pio.end() > 0x1_0000 {
        return Err(ManifestError::PioRangeOverflow);
    }
    let irq = get_u32(bytes, base + 20);
    if irq == 0 {
        return Err(ManifestError::ZeroIrq);
    }
    let path_len = get_u16(bytes, base + 24) as usize;
    if path_len == 0 {
        return Err(ManifestError::PathEmpty);
    }
    if path_len > MAX_DRIVER_PATH_BYTES {
        return Err(ManifestError::PathTooLong);
    }
    if get_u16(bytes, base + 26) != 0 || get_u32(bytes, base + 40) != 0 {
        return Err(ManifestError::NonzeroReserved);
    }
    let content_identity = ContentIdentity(get_u64(bytes, base + 28));
    if content_identity.0 == 0 {
        return Err(ManifestError::ZeroContentIdentity);
    }
    let metadata_policy = MetadataPolicyId(get_u32(bytes, base + 36));
    if metadata_policy.0 == 0 {
        return Err(ManifestError::ZeroMetadataPolicy);
    }
    let path = bytes
        .get(base + 44..base + 44 + MAX_DRIVER_PATH_BYTES)
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
        content: u64,
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
        out[b + 28..b + 36].copy_from_slice(&content.to_le_bytes());
        out[b + 36..b + 40].copy_from_slice(&1u32.to_le_bytes());
        out[b + 44..b + 44 + path.len()].copy_from_slice(path);
        out
    }

    #[test]
    fn exact_com2_policy_matches() {
        let bytes = manifest(1, 2, 0x2f8, 3, UART16550D_PATH, 9);
        let parsed = Manifest::parse(&bytes).unwrap();
        assert_eq!(
            parsed.match_com2(ContentIdentity(9)).unwrap().pio.end(),
            0x300
        );
    }

    #[test]
    fn rejects_com1_and_wrong_driver() {
        let mut bytes = manifest(1, 1, 0x3f8, 4, UART16550D_PATH, 9);
        assert_eq!(
            Manifest::parse(&bytes)
                .unwrap()
                .match_com2(ContentIdentity(9)),
            Err(ManifestError::Com1Rejected)
        );
        bytes[HEADER_BYTES + 8..HEADER_BYTES + 12].copy_from_slice(&2u32.to_le_bytes());
        bytes[HEADER_BYTES + 16..HEADER_BYTES + 18].copy_from_slice(&0x2f8u16.to_le_bytes());
        bytes[HEADER_BYTES + 20..HEADER_BYTES + 24].copy_from_slice(&3u32.to_le_bytes());
        bytes[HEADER_BYTES + 44] = b'x';
        let parsed = Manifest::parse(&bytes).unwrap();
        assert_eq!(
            parsed.match_com2(ContentIdentity(9)),
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
                .match_com2(ContentIdentity(8)),
            Err(ManifestError::WrongContentIdentity)
        );
    }
}
