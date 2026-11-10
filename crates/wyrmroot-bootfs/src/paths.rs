//! Paths and contents the product archive and `system-init` agree on.

/// Permanent supervisor executable.
pub const INIT_PATH: &str = "system/init";
pub const REGISTRYD_PATH: &str = "system/registryd";
pub const DEVMGR_PATH: &str = "system/devmgr";
pub const UART16550D_PATH: &str = "system/uart16550d";
pub const CONSOLED_PATH: &str = "system/consoled";
pub const WYRMSH_PATH: &str = "system/wyrmsh";
pub const HELLO_PATH: &str = "bin/hello";
pub const CPU_HOG_PATH: &str = "bin/cpu-hog";
pub const RRC_MANIFEST_PATH: &str = "system/bootstrap/rrc-a-v1";
pub const LAUNCH_POLICY_PATH: &str = crate::launch_policy::LAUNCH_POLICY_PATH;
/// The product marker `system-init` checks before it reads the device
/// manifest.
pub const MARKER_PATH: &str = "system/bootstrap/product-v1";
pub const MARKER: &[u8] = b"WYRMROOT-PRODUCT-1";
pub const DEVICE_MANIFEST_PATH: &str = "system/bootstrap/device-manifest-v1";
