//! Bounded loader configuration selection for the WYR0 artifact set.
//!
//! WYR0 does not need a boot menu or general configuration language. The only accepted
//! configuration is an optional `profile=default` assignment. Artifact locations remain fixed
//! by [`crate::artifacts`] and cannot be overridden by firmware or media input.

#![allow(dead_code)]

use core::str;

/// Maximum configuration size accepted before parsing begins.
pub const MAX_CONFIG_BYTES: usize = 4096;

/// The only profile currently supported by the loader.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Profile {
    Default,
}

/// Parsed loader configuration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LoaderConfig {
    pub profile: Profile,
}

impl LoaderConfig {
    pub const DEFAULT: Self = Self {
        profile: Profile::Default,
    };

    /// Parse the deliberately tiny UTF-8 configuration grammar.
    ///
    /// Empty lines and lines beginning with `#` are ignored. Every other line must be exactly
    /// `profile=default`; duplicate assignments and unknown keys fail closed.
    pub fn parse(input: &[u8]) -> Result<Self, ConfigError> {
        if input.len() > MAX_CONFIG_BYTES {
            return Err(ConfigError::TooLarge);
        }

        let text = str::from_utf8(input).map_err(|_| ConfigError::InvalidUtf8)?;
        let config = Self::DEFAULT;
        let mut profile_seen = false;

        for raw_line in text.split('\n') {
            let line = raw_line.strip_suffix('\r').unwrap_or(raw_line).trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            let (key, value) = line.split_once('=').ok_or(ConfigError::MalformedLine)?;
            if key != "profile" {
                return Err(ConfigError::UnknownKey);
            }
            if profile_seen {
                return Err(ConfigError::DuplicateKey);
            }
            if value != "default" {
                return Err(ConfigError::UnsupportedProfile);
            }
            profile_seen = true;
        }

        Ok(config)
    }
}

/// Fail-closed configuration errors.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConfigError {
    TooLarge,
    InvalidUtf8,
    MalformedLine,
    UnknownKey,
    DuplicateKey,
    UnsupportedProfile,
}
