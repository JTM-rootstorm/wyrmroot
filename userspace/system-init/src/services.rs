//! The storage service roles (root `STORAGE_PLAN.md` W6, W7): blockmgr for
//! each volume, fat32d, ext4d and vfsd, launched and staged by init after
//! devmgr.
//!
//! Each role is a bootfs executable whose launch-policy entry carries the
//! service-role profile and its identity. Init constructs it with the
//! self-root-plus-control startup, installs the registry endpoints its role
//! needs, and sends one WRSV STAGE on the control Channel: each blockmgr
//! gets a client (for its disk) and its volume's publication
//! (`volume.boot0`, `volume.root0`), fat32d and ext4d a client (for their
//! volume) and the server end of their root directory, and vfsd the
//! `system.vfs` publication with both roots' client ends: ext4d's to mount
//! read-write at `/`, fat32d's read-only at `/boot`. If ext4d cannot mount
//! the root volume it exits, vfsd drops the closed mount, and `/` is vfsd's
//! own directory with `/boot` beneath it.
//!
//! Storage is not part of the recovery root: nothing the console needs
//! depends on it. A role that fails to launch is left out, one that exits
//! is reaped without a restart, and recovery and shutdown retire them all.

use crate::jobs::EndpointKind;
use crate::*;
use deepwyrm_syscall::{DW_HANDLE_TRANSFER_MOVE, DwHandleTransferV1};
use wyrmroot_bootfs::launch_policy::{LAUNCH_POLICY_PATH, LaunchPolicy, SERVICE_ROLE_PROFILE_ID};
use wyrmroot_device_proto::manifest::PublicationPolicy;
use wyrmroot_loader::launch::CHILD_CHANNEL_RIGHTS;
use wyrmroot_loader::process::{ServiceRoleLoadRequest, load_service_role_process};
use wyrmroot_runtime::sha256;
use wyrmroot_service_proto::roles::{
    BLOCKMGR_PATH, BLOCKMGR_ROLE_ID, BOOT_VOLUME, EXT4D_PATH, EXT4D_ROLE_ID, FAT32D_PATH,
    FAT32D_ROLE_ID, ROOT_BLOCKMGR_ROLE_ID, ROOT_VOLUME, SLOT_FS_ROOT, SLOT_MOUNT, SYSTEM_VFS,
    ServiceName, VFSD_PATH, VFSD_ROLE_ID,
};
use wyrmroot_service_proto::{self as wrsv, CHANNEL_READ_ONLY, Client, Publication, Stage};

pub(crate) const SERVICE_COUNT: usize = 5;
/// Where vfsd mounts the boot volume.
pub(crate) const BOOT_MOUNT: &[u8] = b"/boot";
/// Where vfsd mounts the persistent root.
pub(crate) const ROOT_MOUNT: &[u8] = b"/";
/// The most labelled Channels one STAGE carries here.
const MAX_STAGED_CHANNELS: usize = 2;

/// One labelled Channel for a STAGE: slot, flags, label and the handle.
type StagedChannel<'a> = (u32, u32, &'a [u8], DwHandle);
/// Correlation for the services' installs and stages, above every other
/// init transaction range.
const SERVICE_TRANSACTION_BASE: u64 = 0xC5_0000;

/// One running service role.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ServiceAttempt {
    pub(crate) loaded: LoadedProcess,
    pub(crate) task_group: DwHandle,
    /// Init's end of the stage Channel; closing it retires the role.
    pub(crate) control: DwHandle,
}

struct Spec {
    role_id: u64,
    path: &'static str,
    display_path: &'static str,
    publication: Option<ServiceName>,
    client: bool,
}

const SPECS: [Spec; SERVICE_COUNT] = [
    Spec {
        role_id: BLOCKMGR_ROLE_ID,
        path: BLOCKMGR_PATH,
        display_path: "/system/blockmgr",
        publication: Some(BOOT_VOLUME),
        client: true,
    },
    Spec {
        role_id: ROOT_BLOCKMGR_ROLE_ID,
        path: BLOCKMGR_PATH,
        display_path: "/system/blockmgr",
        publication: Some(ROOT_VOLUME),
        client: true,
    },
    Spec {
        role_id: FAT32D_ROLE_ID,
        path: FAT32D_PATH,
        display_path: "/system/fat32d",
        publication: None,
        client: true,
    },
    Spec {
        role_id: EXT4D_ROLE_ID,
        path: EXT4D_PATH,
        display_path: "/system/ext4d",
        publication: None,
        client: true,
    },
    Spec {
        role_id: VFSD_ROLE_ID,
        path: VFSD_PATH,
        display_path: "/system/vfsd",
        publication: Some(SYSTEM_VFS),
        client: false,
    },
];

/// The executable for a service role: present, executable, and exactly the
/// bytes its service-role launch-policy entry names.
pub(crate) fn authorize_service<'a>(bootfs: &'a [u8], path: &str) -> Result<&'a [u8], InitError> {
    let archive = Archive::new(bootfs).map_err(InitError::Bootfs)?;
    let policy_entry = archive
        .lookup(LAUNCH_POLICY_PATH.as_bytes())
        .map_err(map_lookup)?;
    let policy =
        LaunchPolicy::parse(policy_entry.data()).map_err(|_| InitError::WrongManifestProfile)?;
    let entry = policy.find(path).ok_or(InitError::UnlaunchableRole)?;
    if entry.profile_id != SERVICE_ROLE_PROFILE_ID
        || entry.startup_abi != 1
        || entry.allow_three_streams
    {
        return Err(InitError::UnlaunchableRole);
    }
    let artifact = archive.lookup(path.as_bytes()).map_err(map_lookup)?;
    if !artifact.is_executable() || sha256::digest(artifact.data()) != entry.content_sha256 {
        return Err(InitError::NonExecutableRole);
    }
    Ok(artifact.data())
}

/// Launches and stages every service role; a role that cannot be brought
/// up is left out.
#[allow(clippy::too_many_arguments)]
pub(crate) fn launch_services<S, L, W>(
    system: &mut S,
    loader: &mut L,
    waits: &mut W,
    authority: LoadAuthority,
    bootfs: &[u8],
    registry_control: DwHandle,
    topology: &mut RegistryTopology,
    allocator: &mut PublicationAllocator,
) -> [Option<ServiceAttempt>; SERVICE_COUNT]
where
    S: ResidentPlatform,
    L: LoaderPlatform<Error = NativeError>,
    W: SupervisionPlatform<Error = NativeError>,
{
    let mut attempts = [None; SERVICE_COUNT];
    // Each filesystem's root directory: the filesystem serves one end, vfsd
    // mounts the other. If either side fails, the survivor sees the closure.
    let Ok((boot_server, boot_client)) = create_controller_channel_pair(system) else {
        return attempts;
    };
    let (root_server, root_client) = match create_controller_channel_pair(system) {
        Ok(pair) => (Some(pair.0), Some(pair.1)),
        Err(_) => (None, None),
    };
    let mut boot_ends = [Some(boot_server), Some(boot_client)];
    let mut root_ends = [root_server, root_client];
    for (index, spec) in SPECS.iter().enumerate() {
        let mut channels: [Option<StagedChannel<'_>>; MAX_STAGED_CHANNELS] =
            [None; MAX_STAGED_CHANNELS];
        match spec.role_id {
            FAT32D_ROLE_ID => {
                channels[0] = boot_ends[0]
                    .take()
                    .map(|handle| (SLOT_FS_ROOT, 0, &b""[..], handle));
            }
            EXT4D_ROLE_ID => {
                channels[0] = root_ends[0]
                    .take()
                    .map(|handle| (SLOT_FS_ROOT, 0, &b""[..], handle));
            }
            VFSD_ROLE_ID => {
                channels[0] = root_ends[1]
                    .take()
                    .map(|handle| (SLOT_MOUNT, 0, ROOT_MOUNT, handle));
                channels[1] = boot_ends[1]
                    .take()
                    .map(|handle| (SLOT_MOUNT, CHANNEL_READ_ONLY, BOOT_MOUNT, handle));
            }
            _ => {}
        }
        attempts[index] = launch_service(
            system,
            loader,
            waits,
            authority,
            bootfs,
            registry_control,
            topology,
            allocator,
            spec,
            index as u64,
            channels,
        )
        .ok();
    }
    attempts
}

/// Launches one role and stages it. `channels` are moved into the stage, or
/// closed on any failure.
#[allow(clippy::too_many_arguments)]
fn launch_service<S, L, W>(
    system: &mut S,
    loader: &mut L,
    waits: &mut W,
    authority: LoadAuthority,
    bootfs: &[u8],
    registry_control: DwHandle,
    topology: &mut RegistryTopology,
    allocator: &mut PublicationAllocator,
    spec: &Spec,
    index: u64,
    channels: [Option<StagedChannel<'_>>; MAX_STAGED_CHANNELS],
) -> Result<ServiceAttempt, InitError>
where
    S: ResidentPlatform,
    L: LoaderPlatform<Error = NativeError>,
    W: SupervisionPlatform<Error = NativeError>,
{
    let close_channel = |system: &mut S| {
        for (_, _, _, handle) in channels.into_iter().flatten() {
            let _ = system.close_handle(handle);
        }
    };
    let image = match authorize_service(bootfs, spec.path) {
        Ok(image) => image,
        Err(error) => {
            close_channel(system);
            return Err(error);
        }
    };
    let task_group = match system.create_attempt_task_group(authority.task_group) {
        Ok(group) => group,
        Err(error) => {
            close_channel(system);
            return Err(InitError::Native(error));
        }
    };
    let (control, child) = match create_controller_channel_pair(system) {
        Ok(pair) => pair,
        Err(error) => {
            close_channel(system);
            let _ = system.close_handle(task_group);
            return Err(error);
        }
    };
    let transaction_id = SERVICE_TRANSACTION_BASE + index * 0x10;
    let loaded = match load_service_role_process(
        loader,
        LoadAuthority {
            task_group,
            ..authority
        },
        ServiceRoleLoadRequest {
            image,
            display_path: spec.display_path,
            control_endpoint: child,
            role_id: spec.role_id,
            attempt_generation: 1,
            transaction_id,
        },
    ) {
        Ok(loaded) => loaded,
        Err(failure) => {
            close_channel(system);
            if !failure.control_endpoint_consumed {
                let _ = system.close_handle(child);
            }
            let _ = system.close_handle(control);
            let _ = system.close_handle(task_group);
            return Err(InitError::Loader(failure.error));
        }
    };
    let attempt = ServiceAttempt {
        loaded,
        task_group,
        control,
    };
    let staged = stage_service(
        system,
        registry_control,
        topology,
        allocator,
        spec,
        transaction_id,
        control,
        channels,
    );
    match staged {
        Ok(()) => Ok(attempt),
        Err(error) => {
            let _ = retire_service(system, waits, attempt, true);
            Err(error)
        }
    }
}

/// Installs the role's registry endpoints and sends its STAGE. Every handle
/// is moved or closed whatever happens.
#[allow(clippy::too_many_arguments)]
fn stage_service<S: ResidentPlatform>(
    system: &mut S,
    registry_control: DwHandle,
    topology: &mut RegistryTopology,
    allocator: &mut PublicationAllocator,
    spec: &Spec,
    transaction_id: u64,
    control: DwHandle,
    channels: [Option<StagedChannel<'_>>; MAX_STAGED_CHANNELS],
) -> Result<(), InitError> {
    let mut owned: [Option<DwHandle>; 2 + MAX_STAGED_CHANNELS] = [
        None,
        None,
        channels[0].map(|(_, _, _, handle)| handle),
        channels[1].map(|(_, _, _, handle)| handle),
    ];
    let result = (|| {
        let role_generation = spec.role_id;
        let publication = match spec.publication {
            Some(service) => {
                let grant = topology
                    .issue(role_generation, EndpointKind::Publication)
                    .map_err(InitError::Jobs)?;
                let correlation = allocator.issue()?;
                let (registry_end, role_end) = create_controller_channel_pair(system)?;
                owned[0] = Some(role_end);
                if let Err(error) = install_publication_with_policy(
                    system,
                    registry_control,
                    grant,
                    correlation,
                    registry_end,
                    PublicationPolicy {
                        service_name: service.name,
                        protocol_id: service.protocol_id,
                        protocol_major: service.major,
                        protocol_minor: service.minor,
                        supervisor_role_id: service.supervisor_role_id,
                    },
                ) {
                    let _ = system.close_handle(registry_end);
                    return Err(error);
                }
                Some(Publication {
                    registry_generation: grant.registry_generation,
                    endpoint_id: grant.endpoint_id,
                    endpoint_generation: grant.endpoint_generation,
                    transaction_id: transaction_id + 1,
                    service_generation: correlation.service_generation,
                })
            }
            None => None,
        };
        let client = if spec.client {
            let grant = topology
                .issue(role_generation, EndpointKind::RegistryClient)
                .map_err(InitError::Jobs)?;
            let (registry_end, role_end) = create_controller_channel_pair(system)?;
            owned[1] = Some(role_end);
            if let Err(error) = install_client(
                system,
                registry_control,
                grant,
                registry_end,
                transaction_id + 2,
            ) {
                let _ = system.close_handle(registry_end);
                return Err(error);
            }
            Some(Client {
                registry_generation: grant.registry_generation,
                endpoint_id: grant.endpoint_id,
                endpoint_generation: grant.endpoint_generation,
            })
        } else {
            None
        };
        let mut staged = [wrsv::Channel {
            slot: 0,
            flags: 0,
            label: &[],
        }; MAX_STAGED_CHANNELS];
        let mut staged_count = 0;
        for (slot, flags, label, _) in channels.into_iter().flatten() {
            staged[staged_count] = wrsv::Channel { slot, flags, label };
            staged_count += 1;
        }
        let mut bytes = [0u8; wrsv::MAX_BYTES];
        let size = wrsv::encode(
            &Stage {
                transaction_id,
                role_id: spec.role_id,
                attempt_generation: 1,
                publication,
                client,
                channels: &staged[..staged_count],
            },
            &mut bytes,
        )
        .map_err(|_| InitError::WrongManifestProfile)?;
        let mut transfers = [DwHandleTransferV1 {
            handle: DwHandle(0),
            requested_rights: CHILD_CHANNEL_RIGHTS,
            operation: DW_HANDLE_TRANSFER_MOVE,
            reserved0: 0,
            reserved: [0; 2],
        }; 2 + MAX_STAGED_CHANNELS];
        let mut count = 0;
        for handle in owned.iter().flatten() {
            transfers[count].handle = *handle;
            count += 1;
        }
        system
            .send_channel_with_handles(control, &bytes[..size], &transfers[..count])
            .map_err(InitError::Native)?;
        // Moved: nothing left to close.
        owned = [None; 2 + MAX_STAGED_CHANNELS];
        Ok(())
    })();
    for handle in owned.into_iter().flatten() {
        let _ = system.close_handle(handle);
    }
    result
}

/// Retires one role: closes its control Channel, terminates it when asked,
/// and reaps it.
pub(crate) fn retire_service<S, W>(
    system: &mut S,
    waits: &mut W,
    attempt: ServiceAttempt,
    terminate: bool,
) -> Result<(), InitError>
where
    S: InitPlatform,
    W: SupervisionPlatform<Error = NativeError>,
{
    let closed = system.close_handle(attempt.control).is_ok();
    cleanup_loaded(system, waits, attempt.loaded, attempt.task_group, terminate)?;
    if closed {
        Ok(())
    } else {
        Err(InitError::Cleanup)
    }
}

/// Retires every running role; the first failure is reported after all
/// have been tried.
pub(crate) fn retire_services<S, W>(
    resident: &mut ResidentSystemInit,
    system: &mut S,
    waits: &mut W,
) -> Result<(), InitError>
where
    S: InitPlatform,
    W: SupervisionPlatform<Error = NativeError>,
{
    let mut result = Ok(());
    let Some(state) = resident.product.as_mut() else {
        return result;
    };
    for slot in state.services.iter_mut() {
        if let Some(attempt) = slot.take()
            && let Err(error) = retire_service(system, waits, attempt, true)
            && result.is_ok()
        {
            result = Err(error);
        }
    }
    result
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::vec::Vec;
    use wyrmroot_bootfs::builder::{Builder, FileMode};
    use wyrmroot_bootfs::launch_policy::{JOB_V2_PROFILE_ID, LaunchPolicyEntry, encode};

    const VFSD: &[u8] = b"vfsd executable bytes";

    fn bootfs(entry: LaunchPolicyEntry<'_>, mode: FileMode, bytes: &[u8]) -> Vec<u8> {
        let mut policy = [0u8; 512];
        let size = encode([0x42; 32], &[entry], &mut policy).unwrap();
        let mut builder = Builder::new();
        builder
            .add(
                LAUNCH_POLICY_PATH.as_bytes(),
                &policy[..size],
                FileMode::ReadOnly,
            )
            .unwrap();
        builder.add(VFSD_PATH.as_bytes(), bytes, mode).unwrap();
        builder.build().unwrap()
    }

    fn service_entry() -> LaunchPolicyEntry<'static> {
        LaunchPolicyEntry {
            path: VFSD_PATH,
            content_sha256: sha256::digest(VFSD),
            startup_abi: 1,
            profile_id: SERVICE_ROLE_PROFILE_ID,
            allow_no_streams: true,
            allow_three_streams: false,
        }
    }

    #[test]
    fn a_service_image_must_match_its_service_role_policy_entry() {
        let good = bootfs(service_entry(), FileMode::Executable, VFSD);
        assert_eq!(authorize_service(&good, VFSD_PATH), Ok(VFSD));
        assert!(authorize_service(&good, FAT32D_PATH).is_err());

        let tampered = bootfs(service_entry(), FileMode::Executable, b"other bytes");
        assert_eq!(
            authorize_service(&tampered, VFSD_PATH),
            Err(InitError::NonExecutableRole)
        );
        let not_executable = bootfs(service_entry(), FileMode::ReadOnly, VFSD);
        assert_eq!(
            authorize_service(&not_executable, VFSD_PATH),
            Err(InitError::NonExecutableRole)
        );
        // A job entry for the same path does not make it a service.
        let job = bootfs(
            LaunchPolicyEntry {
                startup_abi: 2,
                profile_id: JOB_V2_PROFILE_ID,
                allow_three_streams: true,
                ..service_entry()
            },
            FileMode::Executable,
            VFSD,
        );
        assert_eq!(
            authorize_service(&job, VFSD_PATH),
            Err(InitError::UnlaunchableRole)
        );
    }

    #[test]
    fn every_service_role_spec_names_a_loader_admitted_path() {
        for spec in &SPECS {
            assert!(
                wyrmroot_loader::process::SERVICE_ROLE_PATHS.contains(&spec.display_path),
                "{}",
                spec.display_path
            );
            assert_eq!(&spec.display_path[1..], spec.path);
        }
    }
}
