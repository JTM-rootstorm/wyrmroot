//! WYR1-C device-role policy, coordinator model, and direct driver control.
//!
//! This crate deliberately contains policy and correlation data only.  It does
//! not describe Deepwyrm object types, rights, or the representation of a
//! DeviceResource or Interrupt handle.

#![no_std]
#![forbid(unsafe_code)]

pub mod control;
pub mod coordinator;
pub mod manifest;

pub use control::{ControlEndpoint, ControlMessage, ControlParseError, FailureCode};
pub use coordinator::{
    Coordinator, CoordinatorError, CoordinatorState, RegistryBinding, RegistryEndpoint,
};
pub use manifest::{
    COM2_POLICY, COM2_ROLE_ID, DeviceRole, Manifest, ManifestError, PioRange, ProfileId,
    ProfileVersion, RoleId, UART16550D_PATH,
};
