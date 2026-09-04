//! WYR1-C device-role policy, coordinator model, and direct driver control.
//!
//! This crate deliberately contains policy and correlation data only.  It does
//! not describe Deepwyrm object types, rights, or the representation of a
//! DeviceResource or Interrupt handle.

#![no_std]
#![forbid(unsafe_code)]

pub mod connector;
pub mod control;
pub mod control_v1_1;
pub mod controller;
pub mod coordinator;
pub mod d5_controller;
pub mod driver_launch;
pub mod manifest;

pub use connector::{ConnectorErrorCode, ConnectorIdentity, ConnectorMessage, ConnectorParseError};
pub use control::{
    ControlEndpoint, ControlMessage, ControlParseError, FailureCode, TRIGGER_FAILURE_BYTES,
};
pub use control_v1_1::{ControlIdentityV1_1, ControlMessageV1_1, ControlParseErrorV1_1};
pub use controller::{
    ControllerMessage, ControllerParseError, MessageType as ControllerMessageType, StatusCode,
};
pub use coordinator::{
    Coordinator, CoordinatorError, CoordinatorState, RegistryBinding, RegistryEndpoint,
};
pub use d5_controller::{
    D5ControllerMessage, D5ControllerParseError, D5DriverIdentity, D5StreamIdentity,
};
pub use driver_launch::{
    C6_FACT_BYTES, C6Fact, DEVICE_DRIVER_PATH, DRIVER_RETIRED_BYTES, DirectControlRights,
    DriverLaunch, DriverLaunchError, DriverLaunchRequest, DriverLaunchState, LAUNCH_REQUEST_BYTES,
    LAUNCH_RESPONSE_BYTES, REAPED_RESPONSE_BYTES, SELECTOR29_FAILURE_ATTEMPT_GENERATION,
    SELECTOR29_FAILURE_SUPERVISOR_GENERATION, encode_c6_fact, encode_constructed,
    encode_driver_retired, encode_reaped, encode_request, parse_c6_fact, parse_constructed,
    parse_driver_retired, parse_reaped, parse_request, selector29_should_fail,
};
pub use manifest::{
    COM2_POLICY, COM2_ROLE_ID, DeviceRole, Manifest, ManifestError, PioRange, ProfileId,
    ProfileVersion, PublicationPolicy, RoleId, SERIAL_CONSOLE_CONNECTOR_PROTOCOL_MINOR,
    SERIAL_CONSOLE_CONNECTOR_PUBLICATION_POLICY, SERIAL_CONSOLE_PROTOCOL_ID,
    SERIAL_CONSOLE_PROTOCOL_MAJOR, SERIAL_CONSOLE_PROTOCOL_MINOR,
    SERIAL_CONSOLE_PUBLICATION_POLICY, SERIAL_CONSOLE_SERVICE_NAME,
    SERIAL_CONSOLE_SUPERVISOR_ROLE_ID, UART16550D_PATH, encode_com2_manifest,
};
