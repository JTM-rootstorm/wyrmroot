//! WYR1-C device-role policy, coordinator model, and direct driver control.
//!
//! This crate deliberately contains policy and correlation data only.  It does
//! not describe Deepwyrm object types, rights, or the representation of a
//! DeviceResource or Interrupt handle.

#![no_std]
#![forbid(unsafe_code)]

pub mod control;
pub mod controller;
pub mod coordinator;
pub mod driver_launch;
pub mod manifest;

pub use control::{ControlEndpoint, ControlMessage, ControlParseError, FailureCode};
pub use controller::{
    ControllerMessage, ControllerParseError, MessageType as ControllerMessageType, StatusCode,
};
pub use coordinator::{
    Coordinator, CoordinatorError, CoordinatorState, RegistryBinding, RegistryEndpoint,
};
pub use driver_launch::{
    DEVICE_DRIVER_PATH, DirectControlRights, DriverLaunch, DriverLaunchError, DriverLaunchRequest,
    DriverLaunchState, LAUNCH_REQUEST_BYTES, LAUNCH_RESPONSE_BYTES, encode_constructed,
    encode_request, parse_constructed, parse_request,
};
pub use manifest::{
    COM2_POLICY, COM2_ROLE_ID, DeviceRole, Manifest, ManifestError, PioRange, ProfileId,
    ProfileVersion, PublicationPolicy, RoleId, SERIAL_CONSOLE_PROTOCOL_ID,
    SERIAL_CONSOLE_PROTOCOL_MAJOR, SERIAL_CONSOLE_PROTOCOL_MINOR,
    SERIAL_CONSOLE_PUBLICATION_POLICY, SERIAL_CONSOLE_SERVICE_NAME,
    SERIAL_CONSOLE_SUPERVISOR_ROLE_ID, UART16550D_PATH, encode_com2_manifest,
};
