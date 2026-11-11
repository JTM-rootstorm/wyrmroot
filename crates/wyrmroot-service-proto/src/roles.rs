//! The storage service roles init launches after devmgr (root
//! `STORAGE_PLAN.md` W6), and the registry services they publish.
//!
//! Role identities are WRSV/loader correlation, not authority; they sit
//! above the device roles' range so the two can never be confused.

/// One registry service, as a publisher installs it or a client looks it up.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ServiceName {
    pub name: &'static [u8],
    pub protocol_id: u64,
    pub major: u16,
    pub minor: u16,
    /// The supervisor role the registry records for the publication.
    pub supervisor_role_id: u32,
}

/// WRBD, as `wyrmroot-block-proto` names it.
pub const BLOCK_DEVICE_PROTOCOL_ID: u64 = u64::from_le_bytes(*b"WRBD\0\0\0\0");
/// WRNS, as `wyrmroot-fs-proto` names it.
pub const NAMESPACE_PROTOCOL_ID: u64 = u64::from_le_bytes(*b"WRNS\0\0\0\0");

/// The boot volume: the ESP, as blockmgr finds it on the boot disk.
pub const BOOT_VOLUME: ServiceName = ServiceName {
    name: b"volume.boot0",
    protocol_id: BLOCK_DEVICE_PROTOCOL_ID,
    major: 1,
    minor: 0,
    supervisor_role_id: 4,
};

/// The system namespace vfsd serves.
pub const SYSTEM_VFS: ServiceName = ServiceName {
    name: b"system.vfs",
    protocol_id: NAMESPACE_PROTOCOL_ID,
    major: 1,
    minor: 0,
    supervisor_role_id: 5,
};

pub const BLOCKMGR_ROLE_ID: u64 = 0x100;
pub const BLOCKMGR_PATH: &str = "system/blockmgr";
pub const FAT32D_ROLE_ID: u64 = 0x101;
pub const FAT32D_PATH: &str = "system/fat32d";
pub const VFSD_ROLE_ID: u64 = 0x102;
pub const VFSD_PATH: &str = "system/vfsd";

/// fat32d: the server end of its root directory's WRFS Channel.
pub const SLOT_FS_ROOT: u32 = 1;
/// vfsd: a filesystem root to mount at the Channel's label, read-only with
/// `CHANNEL_READ_ONLY`.
pub const SLOT_MOUNT: u32 = 2;
