//! Paths and contents the product archive and `system-init` agree on.

/// Permanent supervisor executable.
pub const INIT_PATH: &str = "system/init";
pub const REGISTRYD_PATH: &str = "system/registryd";
pub const DEVMGR_PATH: &str = "system/devmgr";
pub const UART16550D_PATH: &str = "system/uart16550d";
/// The boot-disk driver (root `STORAGE_PLAN.md` W2).
pub const VIRTIO_BLKD_PATH: &str = "system/virtio-blkd";
pub const CONSOLED_PATH: &str = "system/consoled";
/// The storage service roles init stages (root `STORAGE_PLAN.md` W6, W7).
/// blockmgr serves both volumes as two roles of one executable.
pub const BLOCKMGR_PATH: &str = "system/blockmgr";
pub const FAT32D_PATH: &str = "system/fat32d";
pub const EXT4D_PATH: &str = "system/ext4d";
pub const VFSD_PATH: &str = "system/vfsd";
pub const SERVICE_ROLE_PATHS: [&str; 4] = [BLOCKMGR_PATH, FAT32D_PATH, EXT4D_PATH, VFSD_PATH];
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
