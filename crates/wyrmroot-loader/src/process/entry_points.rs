//! One public load entry point per process profile.

use super::*;

pub fn load_process<P: LoaderPlatform>(
    platform: &mut P,
    authority: LoadAuthority,
    request: LoadRequest<'_>,
) -> Result<LoadedProcess, LoadError<P::Error>> {
    load_process_with_fault(platform, authority, request, LoadFault::None)
}

/// Launches only the D5-selected supervisor profile with the resource-domain
/// custodian. Historical callers remain on their exact three-capability path.
pub fn load_resource_domain_process<P: LoaderPlatform>(
    platform: &mut P,
    authority: LoadAuthority,
    request: ResourceDomainLoadRequest<'_>,
) -> Result<LoadedProcess, LoadError<P::Error>> {
    let mut consumed = false;
    load_process_internal(
        platform,
        authority,
        InternalLoadRequest {
            image: request.image,
            profile: LaunchProfile::SupervisorResourceDomain,
            transaction_id: request.transaction_id,
            startup: StartupSpec::Legacy(request.display_path),
            channels: &[],
            device_manifest: None,
            supervisor_generation: None,
            driver_correlation: None,
            consoled_correlation: None,
            wyrmsh_correlation: None,
            resource_domain: Some(request.resource_domain),
        },
        LoadFault::None,
        &mut consumed,
    )
}

/// Launches the selector-private resource owner in its exact resource domain.
/// The caller keeps the domain handle; only a `RESOURCE | INSPECT` duplicate
/// crosses the child startup boundary after a successful MOVE.
pub fn load_d6_resource_owner_process<P: LoaderPlatform>(
    platform: &mut P,
    mut authority: LoadAuthority,
    request: D6ResourceOwnerLoadRequest<'_>,
) -> Result<LoadedProcess, LoadError<P::Error>> {
    authority.task_group = request.resource_domain;
    let mut consumed = false;
    load_process_internal(
        platform,
        authority,
        InternalLoadRequest {
            image: request.image,
            profile: LaunchProfile::D6ResourceOwner,
            transaction_id: request.transaction_id,
            startup: StartupSpec::Legacy(request.display_path),
            channels: &[],
            device_manifest: None,
            supervisor_generation: None,
            driver_correlation: None,
            consoled_correlation: None,
            wyrmsh_correlation: None,
            resource_domain: Some(request.resource_domain),
        },
        LoadFault::None,
        &mut consumed,
    )
}

/// Runs one child-construction transaction with an explicitly test-selected
/// malformed-input boundary.
///
/// This is intentionally separate from [`load_process`] so production call
/// sites cannot opt into a negative behavior accidentally.
pub fn load_process_with_fault<P: LoaderPlatform>(
    platform: &mut P,
    authority: LoadAuthority,
    request: LoadRequest<'_>,
    fault: LoadFault,
) -> Result<LoadedProcess, LoadError<P::Error>> {
    let mut delegated_channels_consumed = false;
    load_process_internal(
        platform,
        authority,
        InternalLoadRequest {
            image: request.image,
            profile: request.profile,
            transaction_id: request.transaction_id,
            startup: StartupSpec::Legacy(request.display_path),
            channels: &[],
            device_manifest: None,
            supervisor_generation: None,
            driver_correlation: None,
            consoled_correlation: None,
            wyrmsh_correlation: None,
            resource_domain: None,
        },
        fault,
        &mut delegated_channels_consumed,
    )
}

/// Loads one policy-authorized WYR1-B job with startup ABI v2.
pub fn load_job_process<P: LoaderPlatform>(
    platform: &mut P,
    authority: LoadAuthority,
    request: JobLoadRequest<'_>,
) -> Result<LoadedProcess, JobLoadError<P::Error>> {
    let profile = match request.streams.len() {
        0 => LaunchProfile::JobV2,
        3 => LaunchProfile::JobV2Streams,
        // The three streams, then the namespace.
        4 => LaunchProfile::JobV2Namespace,
        _ => {
            return Err(JobLoadError::caller_retains(LoadError::Launch(
                LaunchError::HandleCount,
            )));
        }
    };
    let mut delegated_channels_consumed = false;
    load_process_internal(
        platform,
        authority,
        InternalLoadRequest {
            image: request.image,
            profile,
            transaction_id: request.transaction_id,
            startup: StartupSpec::JobV2 {
                path: request.policy_path,
                argv: request.argv,
                environment: request.environment,
            },
            channels: request.streams,
            device_manifest: None,
            supervisor_generation: None,
            driver_correlation: None,
            consoled_correlation: None,
            wyrmsh_correlation: None,
            resource_domain: None,
        },
        LoadFault::None,
        &mut delegated_channels_consumed,
    )
    .map_err(|error| JobLoadError {
        error,
        streams_consumed: delegated_channels_consumed,
    })
}

/// Loads one WYR1-B registry, publisher, or client using the exact
/// profile-specific controller endpoint as the second WRLP capability.
pub fn load_service_process<P: LoaderPlatform>(
    platform: &mut P,
    authority: LoadAuthority,
    request: ServiceLoadRequest<'_>,
) -> Result<LoadedProcess, ServiceLoadError<P::Error>> {
    if request.profile.channel_role().is_none() {
        return Err(ServiceLoadError::caller_retains(LoadError::Launch(
            LaunchError::HandleCount,
        )));
    }
    let channels = [request.service_channel];
    let uses_correlation = matches!(
        request.profile,
        LaunchProfile::BootstrapService | LaunchProfile::RegistryClient
    );
    let argv = [request.display_path];
    let mut environment = [""; wyrmroot_registry_proto::CORRELATION_ENVIRONMENT_COUNT];
    let startup = if uses_correlation {
        let correlation = request.correlation.ok_or_else(|| {
            ServiceLoadError::caller_retains(LoadError::Startup(
                StartupBlockError::InvalidEnvironment,
            ))
        })?;
        for (index, slot) in environment.iter_mut().enumerate() {
            *slot = correlation.entry(index).ok_or_else(|| {
                ServiceLoadError::caller_retains(LoadError::Startup(
                    StartupBlockError::InvalidEnvironment,
                ))
            })?;
        }
        StartupSpec::JobV2 {
            path: request.display_path,
            argv: &argv,
            environment: &environment,
        }
    } else if request.correlation.is_none() {
        StartupSpec::Legacy(request.display_path)
    } else {
        return Err(ServiceLoadError::caller_retains(LoadError::Startup(
            StartupBlockError::TooManyArguments,
        )));
    };
    let mut service_channel_consumed = false;
    load_process_internal(
        platform,
        authority,
        InternalLoadRequest {
            image: request.image,
            profile: request.profile,
            transaction_id: request.transaction_id,
            startup,
            channels: &channels,
            device_manifest: None,
            supervisor_generation: None,
            driver_correlation: None,
            consoled_correlation: None,
            wyrmsh_correlation: None,
            resource_domain: None,
        },
        LoadFault::None,
        &mut service_channel_consumed,
    )
    .map_err(|error| ServiceLoadError {
        error,
        service_channel_consumed,
    })
}

/// Arguments a launch client may receive after `argv[0]`.
///
/// Two is exactly the launch-client plan pair. The bound exists so this entry
/// point allocates a fixed argv on the stack, like every other `load_*` here.
pub const MAX_LAUNCH_CLIENT_ARGUMENTS: usize = 2;

/// Launches one WRLP 1.3 launch client with its self root, exactly one
/// launch-session endpoint, and the startup ABI v2 argv/environment tail.
///
/// The endpoint crosses the single atomic INIT MOVE, so a failure leaves it
/// with the caller and a success consumes it; the returned error says which.
pub fn load_launch_client_process<P: LoaderPlatform>(
    platform: &mut P,
    authority: LoadAuthority,
    request: LaunchClientLoadRequest<'_>,
) -> Result<LoadedProcess, LaunchClientLoadError<P::Error>> {
    if request.launch_session.0 == 0 {
        return Err(LaunchClientLoadError::caller_retains(LoadError::Launch(
            LaunchError::HandleCount,
        )));
    }
    if request.arguments.len() > MAX_LAUNCH_CLIENT_ARGUMENTS {
        return Err(LaunchClientLoadError::caller_retains(LoadError::Startup(
            StartupBlockError::TooManyArguments,
        )));
    }
    let mut argv = [""; MAX_LAUNCH_CLIENT_ARGUMENTS + 1];
    argv[0] = request.display_path;
    for (slot, argument) in argv[1..].iter_mut().zip(request.arguments) {
        *slot = argument;
    }
    let argc = 1 + request.arguments.len();
    let mut environment = [""; wyrmroot_registry_proto::CORRELATION_ENVIRONMENT_COUNT];
    for (index, slot) in environment.iter_mut().enumerate() {
        *slot = request.correlation.entry(index).ok_or_else(|| {
            LaunchClientLoadError::caller_retains(LoadError::Startup(
                StartupBlockError::InvalidEnvironment,
            ))
        })?;
    }
    let channels = [request.launch_session];
    let mut launch_session_consumed = false;
    load_process_internal(
        platform,
        authority,
        InternalLoadRequest {
            image: request.image,
            profile: LaunchProfile::LaunchClient,
            transaction_id: request.transaction_id,
            startup: StartupSpec::JobV2 {
                path: request.display_path,
                argv: &argv[..argc],
                environment: &environment,
            },
            channels: &channels,
            device_manifest: None,
            supervisor_generation: None,
            driver_correlation: None,
            consoled_correlation: None,
            wyrmsh_correlation: None,
            resource_domain: None,
        },
        LoadFault::None,
        &mut launch_session_consumed,
    )
    .map_err(|error| LaunchClientLoadError {
        error,
        launch_session_consumed,
    })
}

/// Launches the D4 console broker with exactly its registry-client and
/// launch-session endpoints. Both handles cross one atomic INIT MOVE, so a
/// failure leaves both with the caller and a success consumes both.
pub fn load_consoled_process<P: LoaderPlatform>(
    platform: &mut P,
    authority: LoadAuthority,
    request: ConsoledLoadRequest<'_>,
) -> Result<LoadedProcess, ConsoledLoadError<P::Error>> {
    if request.display_path != "system/consoled"
        || request.registry_endpoint.0 == 0
        || request.launch_endpoint.0 == 0
        || request.registry_endpoint == request.launch_endpoint
        || [
            request.registry_generation,
            request.registry_endpoint_id,
            request.registry_endpoint_generation,
            request.launch_connection_id,
            request.launch_connection_generation,
        ]
        .contains(&0)
    {
        return Err(ConsoledLoadError::caller_retains(LoadError::Launch(
            LaunchError::HandleCount,
        )));
    }
    let channels = [request.registry_endpoint, request.launch_endpoint];
    let mut endpoints_consumed = false;
    load_process_internal(
        platform,
        authority,
        InternalLoadRequest {
            image: request.image,
            profile: LaunchProfile::Consoled,
            transaction_id: request.transaction_id,
            startup: StartupSpec::Legacy(request.display_path),
            channels: &channels,
            device_manifest: None,
            supervisor_generation: None,
            driver_correlation: None,
            consoled_correlation: Some((
                request.registry_generation,
                request.registry_endpoint_id,
                request.registry_endpoint_generation,
                request.launch_connection_id,
                request.launch_connection_generation,
            )),
            wyrmsh_correlation: None,
            resource_domain: None,
        },
        LoadFault::None,
        &mut endpoints_consumed,
    )
    .map_err(|error| ConsoledLoadError {
        error,
        registry_endpoint_consumed: endpoints_consumed,
        launch_endpoint_consumed: endpoints_consumed,
    })
}

/// Launches one `system/wyrmsh` generation with startup ABI v2 and exactly six
/// scoped Channel roles. The returned error reports all-or-none caller custody
/// across the single kernel MOVE.
pub fn load_wyrmsh_process<P: LoaderPlatform>(
    platform: &mut P,
    authority: LoadAuthority,
    request: WyrmshLoadRequest<'_>,
) -> Result<LoadedProcess, WyrmshLoadError<P::Error>> {
    const PATH: &str = "system/wyrmsh";
    let channels = [
        request.stdin,
        request.stdout,
        request.stderr,
        request.console_status,
        request.registry_client,
        request.launch_session,
    ];
    if channels.iter().any(|handle| handle.0 == 0)
        || channels
            .iter()
            .enumerate()
            .any(|(index, handle)| channels[..index].contains(handle))
    {
        return Err(WyrmshLoadError::with_custody(
            LoadError::Launch(LaunchError::HandleCount),
            false,
        ));
    }
    let correlation = WyrmshCorrelation {
        registry_generation: request.registry_generation,
        registry_endpoint_id: request.registry_endpoint_id,
        registry_endpoint_generation: request.registry_endpoint_generation,
        launch_connection_id: request.launch_connection_id,
        launch_connection_generation: request.launch_connection_generation,
        console_generation: request.console_generation,
        status_generation: request.status_generation,
        child_generation: request.child_generation,
        outer_launch_transaction: request.outer_launch_transaction,
    };
    if [
        correlation.registry_generation,
        correlation.registry_endpoint_id,
        correlation.registry_endpoint_generation,
        correlation.launch_connection_id,
        correlation.launch_connection_generation,
        correlation.console_generation,
        correlation.status_generation,
        correlation.child_generation,
        correlation.outer_launch_transaction,
        request.transaction_id,
    ]
    .contains(&0)
    {
        return Err(WyrmshLoadError::with_custody(
            LoadError::Launch(LaunchError::ZeroTransaction),
            false,
        ));
    }
    let argv = [PATH];
    let mut consumed = false;
    load_process_internal(
        platform,
        authority,
        InternalLoadRequest {
            image: request.image,
            profile: LaunchProfile::Wyrmsh,
            transaction_id: request.transaction_id,
            startup: StartupSpec::JobV2 {
                path: PATH,
                argv: &argv,
                environment: &[],
            },
            channels: &channels,
            device_manifest: None,
            supervisor_generation: None,
            driver_correlation: None,
            consoled_correlation: None,
            wyrmsh_correlation: Some(correlation),
            resource_domain: None,
        },
        LoadFault::None,
        &mut consumed,
    )
    .map_err(|error| WyrmshLoadError::with_custody(error, consumed))
}

/// Launch the hardware-independent WYR1-C device coordinator.  Exactly one
/// publication Channel and one immutable WRDM MemoryObject are moved beside
/// the child self-root; no loader or hardware authority is included.
pub fn load_device_coordinator_process<P: LoaderPlatform>(
    platform: &mut P,
    authority: LoadAuthority,
    request: DeviceCoordinatorLoadRequest<'_>,
) -> Result<LoadedProcess, DeviceCoordinatorLoadError<P::Error>> {
    if request.publication_endpoint == request.manifest || request.supervisor_generation == 0 {
        return Err(DeviceCoordinatorLoadError::caller_retains(
            LoadError::Launch(LaunchError::HandleCount),
        ));
    }
    let channels = [request.publication_endpoint];
    let mut inputs_consumed = false;
    load_process_internal(
        platform,
        authority,
        InternalLoadRequest {
            image: request.image,
            profile: LaunchProfile::DeviceCoordinator,
            transaction_id: request.transaction_id,
            startup: StartupSpec::Legacy(request.display_path),
            channels: &channels,
            device_manifest: Some(request.manifest),
            supervisor_generation: Some(request.supervisor_generation),
            driver_correlation: None,
            consoled_correlation: None,
            wyrmsh_correlation: None,
            resource_domain: None,
        },
        LoadFault::None,
        &mut inputs_consumed,
    )
    .map_err(|error| DeviceCoordinatorLoadError {
        error,
        publication_endpoint_consumed: inputs_consumed,
        manifest_consumed: inputs_consumed,
    })
}

/// Launch the WYR1-C4 coordinator inside its generation TaskGroup and move
/// only its reduced resource-domain claim authority at the INIT boundary.
pub fn load_device_coordinator_resource_process<P: LoaderPlatform>(
    platform: &mut P,
    authority: LoadAuthority,
    request: DeviceCoordinatorResourceLoadRequest<'_>,
) -> Result<LoadedProcess, DeviceCoordinatorLoadError<P::Error>> {
    if request.publication_endpoint == request.manifest
        || request.publication_endpoint == request.resource_domain
        || request.manifest == request.resource_domain
        || request.supervisor_generation == 0
    {
        return Err(DeviceCoordinatorLoadError::caller_retains(
            LoadError::Launch(LaunchError::HandleCount),
        ));
    }
    let channels = [request.publication_endpoint];
    let mut inputs_consumed = false;
    load_process_internal(
        platform,
        authority,
        InternalLoadRequest {
            image: request.image,
            profile: LaunchProfile::DeviceCoordinatorResourceDomain,
            transaction_id: request.transaction_id,
            startup: StartupSpec::Legacy(request.display_path),
            channels: &channels,
            device_manifest: Some(request.manifest),
            supervisor_generation: Some(request.supervisor_generation),
            driver_correlation: None,
            consoled_correlation: None,
            wyrmsh_correlation: None,
            resource_domain: Some(request.resource_domain),
        },
        LoadFault::None,
        &mut inputs_consumed,
    )
    .map_err(|error| DeviceCoordinatorLoadError {
        error,
        publication_endpoint_consumed: inputs_consumed,
        manifest_consumed: inputs_consumed,
    })
}

/// The device-driver executables this loader constructs: the console's
/// serial driver and the boot disk's block driver (root `STORAGE_PLAN.md` W2).
/// A request for any other path is refused before anything is created.
pub const DEVICE_DRIVER_PATHS: [&str; 2] = ["/system/uart16550d", "/system/virtio-blkd"];

/// The bootfs service roles init stages itself (root `STORAGE_PLAN.md` W6, W7).
pub const SERVICE_ROLE_PATHS: [&str; 4] = [
    "/system/blockmgr",
    "/system/fat32d",
    "/system/ext4d",
    "/system/vfsd",
];

/// Constructs one service role with the device-driver startup shape: the
/// self root and one control Channel, the child's end of init's WRSV stage
/// Channel. The role id and attempt ride the INIT's correlation; the
/// remaining correlation fields repeat them, since no coordinator issued
/// the launch. Failure leaves the endpoint with the caller unless the
/// error says it was consumed.
pub fn load_service_role_process<P: LoaderPlatform>(
    platform: &mut P,
    authority: LoadAuthority,
    request: ServiceRoleLoadRequest<'_>,
) -> Result<LoadedProcess, DeviceDriverLoadError<P::Error>> {
    if !SERVICE_ROLE_PATHS.contains(&request.display_path)
        || request.role_id == 0
        || request.attempt_generation == 0
    {
        return Err(DeviceDriverLoadError::caller_retains(LoadError::Launch(
            LaunchError::HandleCount,
        )));
    }
    let channels = [request.control_endpoint];
    let mut consumed = false;
    load_process_internal(
        platform,
        authority,
        InternalLoadRequest {
            image: request.image,
            profile: LaunchProfile::DeviceDriver,
            transaction_id: request.transaction_id,
            startup: StartupSpec::Legacy(request.display_path),
            channels: &channels,
            device_manifest: None,
            supervisor_generation: None,
            driver_correlation: Some((
                1,
                request.role_id,
                request.attempt_generation,
                request.role_id,
                request.role_id,
                request.attempt_generation,
            )),
            consoled_correlation: None,
            wyrmsh_correlation: None,
            resource_domain: None,
        },
        LoadFault::None,
        &mut consumed,
    )
    .map_err(|error| DeviceDriverLoadError {
        error,
        control_endpoint_consumed: consumed,
    })
}

/// Constructs only the acceptance driver's process and transfers only its
/// reduced direct control endpoint. The caller supplies sender-side staging
/// authority because the loader must MOVE the endpoint once; the driver still
/// receives only `CHILD_CHANNEL_RIGHTS`. Failure leaves that endpoint with the
/// devmgr caller; hypothetical future resources are absent by type.
pub fn load_device_driver_process<P: LoaderPlatform>(
    platform: &mut P,
    authority: LoadAuthority,
    request: DeviceDriverLoadRequest<'_>,
) -> Result<LoadedProcess, DeviceDriverLoadError<P::Error>> {
    if !DEVICE_DRIVER_PATHS.contains(&request.display_path)
        || request.supervisor_generation == 0
        || request.role_id == 0
        || request.attempt_generation == 0
        || request.launch_session == 0
        || request.endpoint_id == 0
        || request.endpoint_generation == 0
    {
        return Err(DeviceDriverLoadError::caller_retains(LoadError::Launch(
            LaunchError::HandleCount,
        )));
    }
    let channels = [request.control_endpoint];
    let mut consumed = false;
    load_process_internal(
        platform,
        authority,
        InternalLoadRequest {
            image: request.image,
            profile: LaunchProfile::DeviceDriver,
            transaction_id: request.transaction_id,
            startup: StartupSpec::Legacy(request.display_path),
            channels: &channels,
            device_manifest: None,
            supervisor_generation: None,
            driver_correlation: Some((
                request.supervisor_generation,
                request.role_id,
                request.attempt_generation,
                request.launch_session,
                request.endpoint_id,
                request.endpoint_generation,
            )),
            consoled_correlation: None,
            wyrmsh_correlation: None,
            resource_domain: None,
        },
        LoadFault::None,
        &mut consumed,
    )
    .map_err(|error| DeviceDriverLoadError {
        error,
        control_endpoint_consumed: consumed,
    })
}
