//! Allocation-free native startup and bootstrap validation support.
//!
//! The live syscall and object-info calls remain deliberately absent until WYR0's exact
//! Deepwyrm-owned consumer binding exists. This crate nevertheless provides the safe parsing
//! and validation plans that the guest entry path will feed from that binding; it never assigns
//! syscall numbers, object-type IDs, rights masks, or magic handle values itself.

#![no_std]
#![deny(unsafe_code)]
#![deny(unused_crate_dependencies)]

mod bootstrap;
mod diagnostics;
mod startup;

pub use bootstrap::{
    BOOTFS_EXPECTATION, BOOTSTRAP_CHANNEL_EXPECTATION, CapabilityExpectation, CapabilityInfo,
    CapabilityValidationError, InitCapability, MAX_BOOTFS_LOGICAL_SIZE, MappingPlan,
    MappingPlanError, PAGE_SIZE, SELF_ROOT_EXPECTATION, validate_bootstrap_channel,
    validate_init_capabilities,
};
pub use startup::{
    AUXILIARY_VECTOR_TERMINATOR, BootstrapChannelHandle, STARTUP_ABI_V1, STARTUP_BLOCK_SIZE,
    StartupBlock, StartupError, StartupRegisters, StartupString,
};
