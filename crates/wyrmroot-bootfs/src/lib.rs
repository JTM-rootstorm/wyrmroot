//! Deterministic, read-only WYR0 boot archive support.
//!
//! The default surface is allocation-free and parses an immutable borrowed byte slice. The
//! host-side deterministic encoder is available through the opt-in `builder` feature.

#![no_std]
#![forbid(unsafe_code)]

pub mod archive;
#[cfg(feature = "builder")]
pub mod builder;
#[cfg(feature = "builder")]
pub mod content;
mod limits;
pub mod path;
#[cfg(feature = "builder")]
pub mod wyr1;

pub use limits::{BootfsLimits, WYR0_LIMITS};

/// Wyrmroot's first deterministic boot archive policy revision.
pub const FORMAT_VERSION: u32 = 1;

/// The only CPIO header magic accepted and emitted by WYR0-C.
pub const NEWC_MAGIC: &[u8; 6] = b"070701";
