//! The product's platform configuration (`WRPC` v1, DW2 §10.3 item 6).
//!
//! One fixed 64-byte little-endian record that init reads from bootfs
//! before it accepts a job. It carries the memory policy a product sets:
//! a cap on each job's budget and the reserve kept back for the resident
//! services. Parsing is strict and fail-closed; init treats any refusal as
//! "no usable config" and falls back to its fixed job budget.

#![forbid(unsafe_code)]

pub const PLATFORM_CONFIG_PATH: &str = "system/bootstrap/platform-config-v1";
pub const PLATFORM_CONFIG_BYTES: usize = 64;
const MAGIC: [u8; 4] = *b"WRPC";
const VERSION_MAJOR: u16 = 1;
const VERSION_MINOR: u16 = 0;
const PAGE_BYTES: u64 = 4096;

/// What a product configures. Zero means "none" for the cap and "the
/// default" for the reserve.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PlatformConfig {
    /// The most any one job's memory budget may be, in bytes; zero for no
    /// cap. A multiple of 4096.
    pub job_memory_bytes_max: u64,
    /// RAM kept back for the resident services before jobs are budgeted, in
    /// bytes; zero for init's default. A multiple of 4096.
    pub resident_reserve_bytes: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PlatformConfigError {
    WrongSize,
    WrongMagic,
    UnsupportedVersion,
    NonzeroReserved,
    /// A byte count that is not a whole number of pages.
    Unaligned,
}

impl PlatformConfig {
    pub fn parse(bytes: &[u8]) -> Result<Self, PlatformConfigError> {
        if bytes.len() != PLATFORM_CONFIG_BYTES {
            return Err(PlatformConfigError::WrongSize);
        }
        if bytes[..4] != MAGIC {
            return Err(PlatformConfigError::WrongMagic);
        }
        if get_u16(bytes, 4) != VERSION_MAJOR || get_u16(bytes, 6) != VERSION_MINOR {
            return Err(PlatformConfigError::UnsupportedVersion);
        }
        if get_u32(bytes, 8) as usize != PLATFORM_CONFIG_BYTES {
            return Err(PlatformConfigError::WrongSize);
        }
        if get_u32(bytes, 12) != 0 || bytes[32..].iter().any(|&byte| byte != 0) {
            return Err(PlatformConfigError::NonzeroReserved);
        }
        let config = Self {
            job_memory_bytes_max: get_u64(bytes, 16),
            resident_reserve_bytes: get_u64(bytes, 24),
        };
        config.validate()?;
        Ok(config)
    }

    /// The exact encoding [`Self::parse`] accepts.
    pub fn encode(self) -> Result<[u8; PLATFORM_CONFIG_BYTES], PlatformConfigError> {
        self.validate()?;
        let mut bytes = [0u8; PLATFORM_CONFIG_BYTES];
        bytes[..4].copy_from_slice(&MAGIC);
        bytes[4..6].copy_from_slice(&VERSION_MAJOR.to_le_bytes());
        bytes[6..8].copy_from_slice(&VERSION_MINOR.to_le_bytes());
        bytes[8..12].copy_from_slice(&(PLATFORM_CONFIG_BYTES as u32).to_le_bytes());
        bytes[16..24].copy_from_slice(&self.job_memory_bytes_max.to_le_bytes());
        bytes[24..32].copy_from_slice(&self.resident_reserve_bytes.to_le_bytes());
        Ok(bytes)
    }

    fn validate(self) -> Result<(), PlatformConfigError> {
        if !self.job_memory_bytes_max.is_multiple_of(PAGE_BYTES)
            || !self.resident_reserve_bytes.is_multiple_of(PAGE_BYTES)
        {
            return Err(PlatformConfigError::Unaligned);
        }
        Ok(())
    }
}

fn get_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([bytes[offset], bytes[offset + 1]])
}

fn get_u32(bytes: &[u8], offset: usize) -> u32 {
    let mut word = [0u8; 4];
    word.copy_from_slice(&bytes[offset..offset + 4]);
    u32::from_le_bytes(word)
}

fn get_u64(bytes: &[u8], offset: usize) -> u64 {
    let mut word = [0u8; 8];
    word.copy_from_slice(&bytes[offset..offset + 8]);
    u64::from_le_bytes(word)
}

#[cfg(test)]
mod tests {
    use super::*;

    const DEV: PlatformConfig = PlatformConfig {
        job_memory_bytes_max: 512 << 20,
        resident_reserve_bytes: 0,
    };

    #[test]
    fn a_config_round_trips() {
        let bytes = DEV.encode().unwrap();
        assert_eq!(&bytes[..4], b"WRPC");
        assert_eq!(PlatformConfig::parse(&bytes), Ok(DEV));
        let none = PlatformConfig::default();
        assert_eq!(PlatformConfig::parse(&none.encode().unwrap()), Ok(none));
    }

    #[test]
    fn a_truncated_or_extended_config_is_refused() {
        let bytes = DEV.encode().unwrap();
        for len in [0, 4, 32, 63] {
            assert_eq!(
                PlatformConfig::parse(&bytes[..len]),
                Err(PlatformConfigError::WrongSize)
            );
        }
        let mut long = [0u8; PLATFORM_CONFIG_BYTES + 1];
        long[..PLATFORM_CONFIG_BYTES].copy_from_slice(&bytes);
        assert_eq!(
            PlatformConfig::parse(&long),
            Err(PlatformConfigError::WrongSize)
        );
    }

    #[test]
    fn every_header_field_is_checked() {
        let good = DEV.encode().unwrap();
        let mutate = |offset: usize| {
            let mut bytes = good;
            bytes[offset] ^= 1;
            PlatformConfig::parse(&bytes)
        };
        assert_eq!(mutate(0), Err(PlatformConfigError::WrongMagic));
        assert_eq!(mutate(4), Err(PlatformConfigError::UnsupportedVersion));
        assert_eq!(mutate(6), Err(PlatformConfigError::UnsupportedVersion));
        assert_eq!(mutate(8), Err(PlatformConfigError::WrongSize));
        assert_eq!(mutate(12), Err(PlatformConfigError::NonzeroReserved));
        for offset in 32..PLATFORM_CONFIG_BYTES {
            assert_eq!(mutate(offset), Err(PlatformConfigError::NonzeroReserved));
        }
    }

    #[test]
    fn byte_counts_must_be_whole_pages() {
        let mut bytes = DEV.encode().unwrap();
        bytes[16] = 1;
        assert_eq!(
            PlatformConfig::parse(&bytes),
            Err(PlatformConfigError::Unaligned)
        );
        let mut bytes = DEV.encode().unwrap();
        bytes[24] = 0x80;
        assert_eq!(
            PlatformConfig::parse(&bytes),
            Err(PlatformConfigError::Unaligned)
        );
        let unaligned = PlatformConfig {
            job_memory_bytes_max: 0,
            resident_reserve_bytes: 100,
        };
        assert_eq!(unaligned.encode(), Err(PlatformConfigError::Unaligned));
    }
}
