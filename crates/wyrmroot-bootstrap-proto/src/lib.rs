//! Deterministic Wyrmroot bootstrap protocol encoding.
//!
//! This crate owns only the Wyrmroot wire envelope and semantic capability roles. It is
//! deliberately independent of Deepwyrm object IDs, rights masks, syscall IDs, and handle
//! values; `wyrmroot-runtime` binds those roles to the exact pinned Deepwyrm ABI.

#![no_std]
#![deny(unsafe_code)]
#![deny(unused_crate_dependencies)]

mod envelope;

pub use envelope::{
    BOOTSTRAP_INIT_V1_SIZE, BOOTSTRAP_INIT_V2_SIZE, BOOTSTRAP_INIT_V3_SIZE,
    BOOTSTRAP_READY_V1_SIZE, BOOTSTRAP_READY_V2_SIZE, BOOTSTRAP_READY_V3_SIZE, BootstrapMessage,
    CapabilityRole, DecodeError, HEADER_SIZE, InitMessage, InitMessageV2, InitMessageV3,
    MAX_BOOTSTRAP_HANDLES, MAX_BOOTSTRAP_V2_HANDLES, MessageType, PROTOCOL_MAGIC, PROTOCOL_MAJOR,
    PROTOCOL_MINOR, PROTOCOL_MINOR_V2, PROTOCOL_MINOR_V3, ReadyMessage, ReadyMessageV2,
    ReadyMessageV3, decode,
};
