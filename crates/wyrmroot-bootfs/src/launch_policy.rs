//! Canonical immutable WYR1-B launch policy.

#![forbid(unsafe_code)]

pub const LAUNCH_POLICY_PATH: &str = "system/bootstrap/launch-policy-v1";
pub const WYR1_B_GATE_PATH: &str = "system/bootstrap/wyr1-b-gate-v1";
pub const HEADER_BYTES: usize = 64;
pub const RECORD_BYTES: usize = 64;
pub const MAX_ENTRIES: usize = 32;
pub const MAX_PATH_BYTES: usize = 256;
const MAGIC: [u8; 4] = *b"WRJP";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LaunchPolicyEntry<'a> {
    pub path: &'a str,
    pub content_sha256: [u8; 32],
    pub startup_abi: u16,
    pub profile_id: u16,
    pub allow_no_streams: bool,
    pub allow_three_streams: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LaunchPolicy<'a> {
    bytes: &'a [u8],
    count: usize,
    strings_offset: usize,
    boot_generation_sha256: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PolicyError {
    WrongSize,
    WrongMagic,
    UnsupportedVersion,
    NonzeroReserved,
    InvalidCount,
    InvalidBootGeneration,
    InvalidPath,
    NoncanonicalPathOrder,
    InvalidDigest,
    InvalidStartupProfile,
    InvalidStreamModes,
    InvalidClassification,
    ArithmeticOverflow,
}

impl<'a> LaunchPolicy<'a> {
    pub fn parse(bytes: &'a [u8]) -> Result<Self, PolicyError> {
        if bytes.len() < HEADER_BYTES || bytes[..4] != MAGIC {
            return Err(if bytes.len() < HEADER_BYTES {
                PolicyError::WrongSize
            } else {
                PolicyError::WrongMagic
            });
        }
        if get_u16(bytes, 4)? != 1 || get_u16(bytes, 6)? != 0 {
            return Err(PolicyError::UnsupportedVersion);
        }
        if get_u16(bytes, 8)? as usize != HEADER_BYTES
            || get_u16(bytes, 10)? as usize != RECORD_BYTES
        {
            return Err(PolicyError::WrongSize);
        }
        let count = usize::from(get_u16(bytes, 12)?);
        if !(1..=MAX_ENTRIES).contains(&count) {
            return Err(PolicyError::InvalidCount);
        }
        if get_u16(bytes, 14)? != 0 || get_u64(bytes, 56)? != 0 {
            return Err(PolicyError::NonzeroReserved);
        }
        if get_u32(bytes, 16)? as usize != bytes.len() {
            return Err(PolicyError::WrongSize);
        }
        let string_bytes =
            usize::try_from(get_u32(bytes, 20)?).map_err(|_| PolicyError::WrongSize)?;
        let records_bytes = count
            .checked_mul(RECORD_BYTES)
            .ok_or(PolicyError::ArithmeticOverflow)?;
        let strings_offset = HEADER_BYTES
            .checked_add(records_bytes)
            .ok_or(PolicyError::ArithmeticOverflow)?;
        if strings_offset
            .checked_add(string_bytes)
            .ok_or(PolicyError::ArithmeticOverflow)?
            != bytes.len()
        {
            return Err(PolicyError::WrongSize);
        }
        let mut boot_generation_sha256 = [0; 32];
        boot_generation_sha256.copy_from_slice(&bytes[24..56]);
        if boot_generation_sha256 == [0; 32] {
            return Err(PolicyError::InvalidBootGeneration);
        }
        let policy = Self {
            bytes,
            count,
            strings_offset,
            boot_generation_sha256,
        };
        let mut previous = None;
        let mut expected_offset = 0usize;
        for index in 0..count {
            let entry = policy.entry(index).ok_or(PolicyError::WrongSize)??;
            if previous.is_some_and(|path: &str| path >= entry.path) {
                return Err(PolicyError::NoncanonicalPathOrder);
            }
            let record = policy.record(index)?;
            if get_u32(record, 0)? as usize != expected_offset {
                return Err(PolicyError::InvalidPath);
            }
            expected_offset = expected_offset
                .checked_add(entry.path.len())
                .ok_or(PolicyError::ArithmeticOverflow)?;
            previous = Some(entry.path);
        }
        if expected_offset != string_bytes {
            return Err(PolicyError::InvalidPath);
        }
        Ok(policy)
    }

    pub const fn len(self) -> usize {
        self.count
    }

    pub const fn is_empty(self) -> bool {
        self.count == 0
    }

    pub const fn boot_generation_sha256(self) -> [u8; 32] {
        self.boot_generation_sha256
    }

    pub fn entry(self, index: usize) -> Option<Result<LaunchPolicyEntry<'a>, PolicyError>> {
        if index >= self.count {
            return None;
        }
        Some(self.parse_entry(index))
    }

    pub fn find(self, path: &str) -> Option<LaunchPolicyEntry<'a>> {
        (0..self.count).find_map(|index| {
            self.parse_entry(index)
                .ok()
                .filter(|entry| entry.path == path)
        })
    }

    fn parse_entry(self, index: usize) -> Result<LaunchPolicyEntry<'a>, PolicyError> {
        let record = self.record(index)?;
        if record[48..64] != [0; 16] {
            return Err(PolicyError::NonzeroReserved);
        }
        let path_offset =
            usize::try_from(get_u32(record, 0)?).map_err(|_| PolicyError::InvalidPath)?;
        let path_len = usize::from(get_u16(record, 4)?);
        if path_len == 0 || path_len > MAX_PATH_BYTES {
            return Err(PolicyError::InvalidPath);
        }
        let start = self
            .strings_offset
            .checked_add(path_offset)
            .ok_or(PolicyError::ArithmeticOverflow)?;
        let end = start
            .checked_add(path_len)
            .ok_or(PolicyError::ArithmeticOverflow)?;
        let path =
            core::str::from_utf8(self.bytes.get(start..end).ok_or(PolicyError::InvalidPath)?)
                .map_err(|_| PolicyError::InvalidPath)?;
        validate_path(path)?;
        if get_u16(record, 6)? != 2 || get_u16(record, 8)? != 1 {
            return Err(PolicyError::InvalidStartupProfile);
        }
        let stream_modes = get_u16(record, 10)?;
        if stream_modes == 0 || stream_modes & !0b11 != 0 {
            return Err(PolicyError::InvalidStreamModes);
        }
        if get_u32(record, 12)? != 1 {
            return Err(PolicyError::InvalidClassification);
        }
        let mut content_sha256 = [0; 32];
        content_sha256.copy_from_slice(&record[16..48]);
        if content_sha256 == [0; 32] {
            return Err(PolicyError::InvalidDigest);
        }
        Ok(LaunchPolicyEntry {
            path,
            content_sha256,
            startup_abi: 2,
            profile_id: 1,
            allow_no_streams: stream_modes & 1 != 0,
            allow_three_streams: stream_modes & 2 != 0,
        })
    }

    fn record(self, index: usize) -> Result<&'a [u8], PolicyError> {
        let start = HEADER_BYTES
            .checked_add(
                index
                    .checked_mul(RECORD_BYTES)
                    .ok_or(PolicyError::ArithmeticOverflow)?,
            )
            .ok_or(PolicyError::ArithmeticOverflow)?;
        self.bytes
            .get(start..start + RECORD_BYTES)
            .ok_or(PolicyError::WrongSize)
    }
}

pub fn encode(
    boot_generation_sha256: [u8; 32],
    entries: &[LaunchPolicyEntry<'_>],
    output: &mut [u8],
) -> Result<usize, PolicyError> {
    if boot_generation_sha256 == [0; 32] {
        return Err(PolicyError::InvalidBootGeneration);
    }
    if entries.is_empty() || entries.len() > MAX_ENTRIES {
        return Err(PolicyError::InvalidCount);
    }
    let string_bytes = entries.iter().try_fold(0usize, |sum, entry| {
        sum.checked_add(entry.path.len())
            .ok_or(PolicyError::ArithmeticOverflow)
    })?;
    let total = HEADER_BYTES
        .checked_add(entries.len() * RECORD_BYTES)
        .and_then(|value| value.checked_add(string_bytes))
        .ok_or(PolicyError::ArithmeticOverflow)?;
    if output.len() < total {
        return Err(PolicyError::WrongSize);
    }
    output[..total].fill(0);
    output[..4].copy_from_slice(&MAGIC);
    put_u16(output, 4, 1)?;
    put_u16(output, 8, HEADER_BYTES as u16)?;
    put_u16(output, 10, RECORD_BYTES as u16)?;
    put_u16(output, 12, entries.len() as u16)?;
    put_u32(output, 16, total as u32)?;
    put_u32(output, 20, string_bytes as u32)?;
    output[24..56].copy_from_slice(&boot_generation_sha256);
    let mut string_offset = 0usize;
    let strings_start = HEADER_BYTES + entries.len() * RECORD_BYTES;
    let mut previous = None;
    for (index, entry) in entries.iter().enumerate() {
        validate_path(entry.path)?;
        if previous.is_some_and(|path: &str| path >= entry.path) {
            return Err(PolicyError::NoncanonicalPathOrder);
        }
        if entry.content_sha256 == [0; 32] {
            return Err(PolicyError::InvalidDigest);
        }
        if entry.startup_abi != 2 || entry.profile_id != 1 {
            return Err(PolicyError::InvalidStartupProfile);
        }
        let stream_modes =
            u16::from(entry.allow_no_streams) | (u16::from(entry.allow_three_streams) << 1);
        if stream_modes == 0 {
            return Err(PolicyError::InvalidStreamModes);
        }
        let record = HEADER_BYTES + index * RECORD_BYTES;
        put_u32(output, record, string_offset as u32)?;
        put_u16(output, record + 4, entry.path.len() as u16)?;
        put_u16(output, record + 6, 2)?;
        put_u16(output, record + 8, 1)?;
        put_u16(output, record + 10, stream_modes)?;
        put_u32(output, record + 12, 1)?;
        output[record + 16..record + 48].copy_from_slice(&entry.content_sha256);
        output[strings_start + string_offset..strings_start + string_offset + entry.path.len()]
            .copy_from_slice(entry.path.as_bytes());
        string_offset += entry.path.len();
        previous = Some(entry.path);
    }
    LaunchPolicy::parse(&output[..total])?;
    Ok(total)
}

fn validate_path(path: &str) -> Result<(), PolicyError> {
    if path.is_empty()
        || path.len() > MAX_PATH_BYTES
        || !path.is_ascii()
        || path.starts_with('/')
        || path.as_bytes().contains(&0)
        || path
            .split('/')
            .any(|component| component.is_empty() || matches!(component, "." | ".."))
    {
        return Err(PolicyError::InvalidPath);
    }
    Ok(())
}

fn get_u16(bytes: &[u8], offset: usize) -> Result<u16, PolicyError> {
    Ok(u16::from_le_bytes(
        bytes
            .get(offset..offset + 2)
            .ok_or(PolicyError::WrongSize)?
            .try_into()
            .map_err(|_| PolicyError::WrongSize)?,
    ))
}
fn get_u32(bytes: &[u8], offset: usize) -> Result<u32, PolicyError> {
    Ok(u32::from_le_bytes(
        bytes
            .get(offset..offset + 4)
            .ok_or(PolicyError::WrongSize)?
            .try_into()
            .map_err(|_| PolicyError::WrongSize)?,
    ))
}
fn get_u64(bytes: &[u8], offset: usize) -> Result<u64, PolicyError> {
    Ok(u64::from_le_bytes(
        bytes
            .get(offset..offset + 8)
            .ok_or(PolicyError::WrongSize)?
            .try_into()
            .map_err(|_| PolicyError::WrongSize)?,
    ))
}
fn put_u16(bytes: &mut [u8], offset: usize, value: u16) -> Result<(), PolicyError> {
    bytes
        .get_mut(offset..offset + 2)
        .ok_or(PolicyError::WrongSize)?
        .copy_from_slice(&value.to_le_bytes());
    Ok(())
}
fn put_u32(bytes: &mut [u8], offset: usize, value: u32) -> Result<(), PolicyError> {
    bytes
        .get_mut(offset..offset + 4)
        .ok_or(PolicyError::WrongSize)?
        .copy_from_slice(&value.to_le_bytes());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn deterministic_policy_round_trips_and_binds_hello() {
        let entry = LaunchPolicyEntry {
            path: "bin/hello",
            content_sha256: [0x22; 32],
            startup_abi: 2,
            profile_id: 1,
            allow_no_streams: true,
            allow_three_streams: true,
        };
        let mut bytes = [0u8; 512];
        let size = encode([0x11; 32], &[entry], &mut bytes).unwrap();
        let parsed = LaunchPolicy::parse(&bytes[..size]).unwrap();
        assert_eq!(parsed.boot_generation_sha256(), [0x11; 32]);
        assert_eq!(parsed.find("bin/hello"), Some(entry));
        let mut malformed = bytes;
        malformed[56] = 1;
        assert!(LaunchPolicy::parse(&malformed[..size]).is_err());
    }
}
