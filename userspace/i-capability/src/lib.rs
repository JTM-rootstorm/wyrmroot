#![no_std]
#![deny(unsafe_code)]

//! Trusted WYR0-I native capability controller, evidence framing, and deterministic probe logic.

use deepwyrm_syscall as _;
use wyrmroot_bootfs as _;
use wyrmroot_loader as _;

mod content;
mod evidence;
mod model;
mod native;
mod sha256;

pub use content::{
    ASSET_BOOTFS_PATH, CANONICAL_ASSET_SOURCE, CANONICAL_CONFIG_SOURCE, CONFIG_BOOTFS_PATH,
    ContentError, SelectorContent, validate_selector_content,
};
pub use evidence::{
    CANCEL_TRANSACTION, CHANNEL_TOKEN, CONTENT_TOKEN, EXHAUST_TRANSACTION_BASE, EvidenceError,
    EvidenceEvent, EvidenceKind, EvidenceTranscript, MEMORY_CHILD_RIGHTS_MASK, MEMORY_PAGE_BYTES,
    MEMORY_TRANSACTION, NORMAL_TRANSACTION, REQUIRED_CAPABILITY_MASK, RESTART_TRANSACTION_BASE,
    WAIT_TOKEN, WRCAP1_EVENT_COUNT, WRCAP1_RECORD_BYTES, validate_relay_record,
};
pub use model::{
    ModelError, prove_overload_replay_and_cleanup, prove_restart_replacement_and_exhaustion,
};
pub use native::run_i_capability;
pub use sha256::prefix_u64 as sha256_prefix_u64;

/// Selector-local failure detail, `0x24SSOOOO`.
#[must_use]
pub const fn failure(stage: EvidenceKind, operation: u16) -> u32 {
    0x2400_0000 | ((stage as u32) << 16) | operation as u32
}
