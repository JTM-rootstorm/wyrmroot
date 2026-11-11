//! Building and materializing a process: transaction, startup, faults.

use super::*;

pub(crate) fn load_process_internal<P: LoaderPlatform>(
    platform: &mut P,
    authority: LoadAuthority,
    request: InternalLoadRequest<'_>,
    fault: LoadFault,
    delegated_channels_consumed: &mut bool,
) -> Result<LoadedProcess, LoadError<P::Error>> {
    let expected_channels = if request.profile == LaunchProfile::Wyrmsh {
        launch::MAX_CAPABILITIES
    } else if request.profile == LaunchProfile::Consoled {
        2
    } else if request.profile.channel_role().is_some()
        || matches!(
            request.profile,
            LaunchProfile::DeviceCoordinator
                | LaunchProfile::DeviceCoordinatorResourceDomain
                | LaunchProfile::DeviceDriver
        )
    {
        1
    } else if request.profile == LaunchProfile::JobV2Streams {
        3
    } else {
        0
    };
    if request.channels.len() != expected_channels {
        return Err(LoadError::Launch(LaunchError::HandleCount));
    }
    if matches!(
        request.profile,
        LaunchProfile::DeviceCoordinator | LaunchProfile::DeviceCoordinatorResourceDomain
    ) != request.device_manifest.is_some()
    {
        return Err(LoadError::Launch(LaunchError::HandleCount));
    }
    if (request.profile == LaunchProfile::DeviceDriver) != request.driver_correlation.is_some() {
        return Err(LoadError::Launch(LaunchError::HandleCount));
    }
    if (request.profile == LaunchProfile::Consoled) != request.consoled_correlation.is_some() {
        return Err(LoadError::Launch(LaunchError::HandleCount));
    }
    if (request.profile == LaunchProfile::Wyrmsh) != request.wyrmsh_correlation.is_some() {
        return Err(LoadError::Launch(LaunchError::HandleCount));
    }
    let mut segments = [empty_segment(); MAX_LOAD_SEGMENTS];
    if fault == LoadFault::MalformedElf {
        let malformed = [0_u8; 64];
        return match elf::plan(&malformed, &mut segments) {
            Err(error) => Err(LoadError::Elf(error)),
            Ok(_) => unreachable!("test malformed ELF was accepted"),
        };
    }
    let plan = elf::plan(request.image, &mut segments).map_err(LoadError::Elf)?;
    match request.startup {
        StartupSpec::Legacy(display_path) => load_legacy_process_materialized(
            platform,
            authority,
            request,
            display_path,
            fault,
            delegated_channels_consumed,
            plan,
        ),
        StartupSpec::JobV2 { .. } if plan.segments.len() > elf::MAX_JOB_LOAD_SEGMENTS => Err(
            LoadError::Elf(ElfError::TooManyLoadSegments(plan.segments.len())),
        ),
        StartupSpec::JobV2 {
            path,
            argv,
            environment,
        } => load_job_v2_process_materialized(
            platform,
            authority,
            request,
            path,
            argv,
            environment,
            fault,
            delegated_channels_consumed,
            plan,
        ),
    }
}

#[allow(clippy::too_many_arguments)]
#[inline(never)]
pub(crate) fn load_legacy_process_materialized<P: LoaderPlatform>(
    platform: &mut P,
    authority: LoadAuthority,
    request: InternalLoadRequest<'_>,
    display_path: &str,
    fault: LoadFault,
    delegated_channels_consumed: &mut bool,
    plan: elf::ElfLoadPlan<'_>,
) -> Result<LoadedProcess, LoadError<P::Error>> {
    let mut startup_block = [0_u8; PAGE_SIZE as usize];
    image::write_startup_block(
        &mut startup_block,
        image::INITIAL_STACK_POINTER,
        display_path,
    )
    .map_err(LoadError::Startup)?;
    apply_startup_fault(&mut startup_block, fault);
    load_process_materialized(
        platform,
        authority,
        request,
        fault,
        delegated_channels_consumed,
        plan,
        StartupMaterialization::Legacy(&startup_block),
        INITIAL_STACK.startup_page_offset,
        INITIAL_STACK.stack_pointer,
        image::STARTUP_ABI_VERSION,
    )
}

#[allow(clippy::too_many_arguments)]
#[inline(never)]
pub(crate) fn load_job_v2_process_materialized<P: LoaderPlatform>(
    platform: &mut P,
    authority: LoadAuthority,
    request: InternalLoadRequest<'_>,
    path: &str,
    argv: &[&str],
    environment: &[&str],
    fault: LoadFault,
    delegated_channels_consumed: &mut bool,
    plan: elf::ElfLoadPlan<'_>,
) -> Result<LoadedProcess, LoadError<P::Error>> {
    let startup = image::StartupBlockV2Plan::new(
        image::STARTUP_V2_BLOCK_BYTES,
        image::STARTUP_V2_BLOCK_ADDRESS,
        path,
        argv,
        environment,
    )
    .map_err(LoadError::Startup)?;
    load_process_materialized(
        platform,
        authority,
        request,
        fault,
        delegated_channels_consumed,
        plan,
        StartupMaterialization::JobV2(startup),
        INITIAL_STACK.object_size - image::STARTUP_V2_BLOCK_BYTES as u64,
        image::STARTUP_V2_BLOCK_ADDRESS,
        image::STARTUP_ABI_V2,
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn load_process_materialized<P: LoaderPlatform>(
    platform: &mut P,
    authority: LoadAuthority,
    request: InternalLoadRequest<'_>,
    fault: LoadFault,
    delegated_channels_consumed: &mut bool,
    plan: elf::ElfLoadPlan<'_>,
    startup: StartupMaterialization<'_>,
    startup_offset: u64,
    stack_pointer: u64,
    startup_abi: u64,
) -> Result<LoadedProcess, LoadError<P::Error>> {
    let mut init = [0_u8; launch::WYRMSH_BYTES];
    let init_len = if request.profile == LaunchProfile::Wyrmsh {
        let correlation = request
            .wyrmsh_correlation
            .ok_or(LoadError::Launch(LaunchError::ZeroTransaction))?;
        launch::encode_wyrmsh_init(
            request.transaction_id,
            correlation.registry_generation,
            correlation.registry_endpoint_id,
            correlation.registry_endpoint_generation,
            correlation.launch_connection_id,
            correlation.launch_connection_generation,
            correlation.console_generation,
            correlation.status_generation,
            correlation.child_generation,
            correlation.outer_launch_transaction,
            &mut init,
        )
    } else if request.profile == LaunchProfile::Consoled {
        let (registry, registry_id, registry_generation, launch_id, launch_generation) = request
            .consoled_correlation
            .ok_or(LoadError::Launch(LaunchError::ZeroTransaction))?;
        launch::encode_consoled_init(
            request.transaction_id,
            registry,
            registry_id,
            registry_generation,
            launch_id,
            launch_generation,
            &mut init,
        )
    } else if request.profile == LaunchProfile::DeviceCoordinator {
        launch::encode_device_coordinator_init(
            request.transaction_id,
            request
                .supervisor_generation
                .ok_or(LoadError::Launch(LaunchError::ZeroTransaction))?,
            &mut init,
        )
    } else if request.profile == LaunchProfile::DeviceCoordinatorResourceDomain {
        launch::encode_device_coordinator_resource_init(
            request.transaction_id,
            request
                .supervisor_generation
                .ok_or(LoadError::Launch(LaunchError::ZeroTransaction))?,
            &mut init,
        )
    } else if request.profile == LaunchProfile::DeviceDriver {
        let (supervisor, role, attempt, session, endpoint, endpoint_generation) = request
            .driver_correlation
            .ok_or(LoadError::Launch(LaunchError::ZeroTransaction))?;
        launch::encode_device_driver_init(
            request.transaction_id,
            supervisor,
            role,
            attempt,
            session,
            endpoint,
            endpoint_generation,
            &mut init,
        )
    } else {
        launch::encode_init(request.profile, request.transaction_id, &mut init)
    }
    .map_err(LoadError::Launch)?;
    apply_init_fault(&mut init[..init_len], fault);

    let mut transaction = Transaction::new(authority.parent_root);
    let (broad_parent, child_endpoint) = platform
        .channel_create(CHANNEL_BROAD_RIGHTS)
        .map_err(|cause| platform_error(LoadStage::ChannelCreate, cause, false))?;
    transaction.broad_parent = Some(broad_parent);
    transaction.child_endpoint = Some(child_endpoint);

    let parent_channel = match platform.duplicate(broad_parent, CHANNEL_RETAINED_RIGHTS) {
        Ok(handle) => handle,
        Err(cause) => {
            return Err(fail(
                platform,
                &mut transaction,
                LoadStage::ChannelReduce,
                cause,
            ));
        }
    };
    transaction.parent_channel = Some(parent_channel);
    if let Err(cause) = platform.close(broad_parent) {
        return Err(fail(
            platform,
            &mut transaction,
            LoadStage::ChannelReduce,
            cause,
        ));
    }
    transaction.broad_parent = None;

    let created = match platform.process_create(ProcessCreateRequest {
        task_group: authority.task_group,
        bootstrap_channel: child_endpoint,
        process_rights: PROCESS_RIGHTS,
        root_rights: ROOT_RIGHTS,
        child_bootstrap_rights: CHANNEL_RETAINED_RIGHTS,
    }) {
        Ok(created) => created,
        Err(cause) => {
            return Err(fail(
                platform,
                &mut transaction,
                LoadStage::ProcessCreate,
                cause,
            ));
        }
    };
    transaction.child_endpoint = None;
    transaction.process = Some(created.process);
    transaction.root = Some(created.root);

    for segment in plan.segments {
        let materialization = MaterializationPlan::from(*segment);
        let memory = match platform.memory_create(materialization.object_size, MEMORY_RIGHTS) {
            Ok(handle) => handle,
            Err(cause) => {
                return Err(fail(
                    platform,
                    &mut transaction,
                    LoadStage::MemoryCreate,
                    cause,
                ));
            }
        };
        transaction.scratch_memory = Some(memory);
        let source_start = materialization.source_offset as usize;
        let source_end = source_start + materialization.source_size as usize;
        let parent_mapping = match platform.materialize_parent(
            authority.parent_root,
            memory,
            materialization.object_size,
            materialization.destination_offset,
            &request.image[source_start..source_end],
        ) {
            Ok(mapping) => mapping,
            Err(cause) => {
                return Err(fail(
                    platform,
                    &mut transaction,
                    LoadStage::ParentMaterialize,
                    cause,
                ));
            }
        };
        transaction.parent_mapping = Some(parent_mapping);
        if let Err(cause) = platform.unmap_parent(authority.parent_root, parent_mapping) {
            return Err(fail(
                platform,
                &mut transaction,
                LoadStage::ParentUnmap,
                cause,
            ));
        }
        transaction.parent_mapping = None;
        if let Err(cause) = platform.map_child(
            created.root,
            memory,
            materialization.child_address,
            materialization.object_size,
            native_protection(materialization.protection),
        ) {
            return Err(fail(platform, &mut transaction, LoadStage::ChildMap, cause));
        }
        transaction.ranges[transaction.range_count] = Range {
            address: materialization.child_address,
            bytes: materialization.object_size,
        };
        transaction.range_count += 1;
        if let Err(cause) = platform.close(memory) {
            return Err(fail(
                platform,
                &mut transaction,
                LoadStage::SuccessCleanup,
                cause,
            ));
        }
        transaction.scratch_memory = None;
    }

    let stack = match platform.memory_create(INITIAL_STACK.object_size, MEMORY_RIGHTS) {
        Ok(handle) => handle,
        Err(cause) => {
            return Err(fail(
                platform,
                &mut transaction,
                LoadStage::MemoryCreate,
                cause,
            ));
        }
    };
    transaction.scratch_memory = Some(stack);
    let materialized = match startup {
        StartupMaterialization::Legacy(startup_block) => platform.materialize_parent(
            authority.parent_root,
            stack,
            INITIAL_STACK.object_size,
            startup_offset,
            startup_block,
        ),
        StartupMaterialization::JobV2(startup) => platform.materialize_parent_with(
            authority.parent_root,
            stack,
            INITIAL_STACK.object_size,
            startup_offset,
            image::STARTUP_V2_BLOCK_BYTES,
            |block| {
                startup.write(block);
                apply_startup_fault(block, fault);
            },
        ),
    };
    let parent_mapping = match materialized {
        Ok(mapping) => mapping,
        Err(cause) => {
            return Err(fail(
                platform,
                &mut transaction,
                LoadStage::ParentMaterialize,
                cause,
            ));
        }
    };
    transaction.parent_mapping = Some(parent_mapping);
    if let Err(cause) = platform.unmap_parent(authority.parent_root, parent_mapping) {
        return Err(fail(
            platform,
            &mut transaction,
            LoadStage::ParentUnmap,
            cause,
        ));
    }
    transaction.parent_mapping = None;
    if let Err(cause) = platform.map_child(
        created.root,
        stack,
        INITIAL_STACK.child_address,
        INITIAL_STACK.object_size,
        DwMemoryProtection(DW_MEMORY_PROTECTION_READ.0 | DW_MEMORY_PROTECTION_WRITE.0),
    ) {
        return Err(fail(platform, &mut transaction, LoadStage::ChildMap, cause));
    }
    transaction.ranges[transaction.range_count] = Range {
        address: INITIAL_STACK.child_address,
        bytes: INITIAL_STACK.object_size,
    };
    transaction.range_count += 1;
    if let Err(cause) = platform.close(stack) {
        return Err(fail(
            platform,
            &mut transaction,
            LoadStage::SuccessCleanup,
            cause,
        ));
    }
    transaction.scratch_memory = None;

    let thread = match platform.thread_create(created.process, THREAD_RIGHTS) {
        Ok(handle) => handle,
        Err(cause) => {
            return Err(fail(
                platform,
                &mut transaction,
                LoadStage::ThreadCreate,
                cause,
            ));
        }
    };
    transaction.thread = Some(thread);

    let mut transfers = [DwHandleTransferV1::default(); launch::MAX_CAPABILITIES];
    let transfer_count = if request.profile.has_loader_authority_trio()
        || request.profile.has_loader_authority_quartet()
    {
        let bootfs = match platform.duplicate(authority.bootfs, BOOTFS_RIGHTS) {
            Ok(handle) => handle,
            Err(cause) => {
                return Err(fail(
                    platform,
                    &mut transaction,
                    LoadStage::CapabilityDuplicate,
                    cause,
                ));
            }
        };
        transaction.delegated_bootfs = Some(bootfs);
        let task_group = match platform.duplicate(authority.task_group, LOADER_TASK_GROUP_RIGHTS) {
            Ok(handle) => handle,
            Err(cause) => {
                return Err(fail(
                    platform,
                    &mut transaction,
                    LoadStage::CapabilityDuplicate,
                    cause,
                ));
            }
        };
        transaction.delegated_task_group = Some(task_group);
        transfers[0] = transfer(created.root, SELF_ROOT_RIGHTS);
        transfers[1] = transfer(bootfs, BOOTFS_RIGHTS);
        transfers[2] = transfer(task_group, LOADER_TASK_GROUP_RIGHTS);
        if request.profile.has_loader_authority_quartet() {
            let domain = request
                .resource_domain
                .ok_or(LoadError::Launch(LaunchError::HandleCount))?;
            let domain = match platform.duplicate(domain, launch::RESOURCE_DOMAIN_CUSTODY_RIGHTS) {
                Ok(handle) => handle,
                Err(cause) => {
                    return Err(fail(
                        platform,
                        &mut transaction,
                        LoadStage::CapabilityDuplicate,
                        cause,
                    ));
                }
            };
            transaction.delegated_resource_domain = Some(domain);
            transfers[3] = transfer(domain, launch::RESOURCE_DOMAIN_CUSTODY_RIGHTS);
            4
        } else {
            3
        }
    } else if request.profile == LaunchProfile::D6ResourceOwner {
        let domain = request
            .resource_domain
            .ok_or(LoadError::Launch(LaunchError::HandleCount))?;
        let domain = match platform.duplicate(domain, launch::RESOURCE_DOMAIN_CLAIM_TRANSFER_RIGHTS)
        {
            Ok(handle) => handle,
            Err(cause) => {
                return Err(fail(
                    platform,
                    &mut transaction,
                    LoadStage::CapabilityDuplicate,
                    cause,
                ));
            }
        };
        transaction.delegated_resource_domain = Some(domain);
        transfers[0] = transfer(domain, launch::RESOURCE_DOMAIN_CLAIM_RIGHTS);
        1
    } else if request.profile == LaunchProfile::Dw1bProgress {
        transaction.delegated_channels[0] = Some(request.channels[0]);
        transfers[0] = transfer(request.channels[0], launch::CHILD_CHANNEL_RIGHTS);
        1
    } else if matches!(
        request.profile,
        LaunchProfile::DeviceCoordinator | LaunchProfile::DeviceCoordinatorResourceDomain
    ) {
        let manifest = request
            .device_manifest
            .ok_or(LoadError::Launch(LaunchError::HandleCount))?;
        let staged_domain = if request.profile == LaunchProfile::DeviceCoordinatorResourceDomain {
            let domain = request
                .resource_domain
                .ok_or(LoadError::Launch(LaunchError::HandleCount))?;
            let domain =
                match platform.duplicate(domain, launch::RESOURCE_DOMAIN_CLAIM_TRANSFER_RIGHTS) {
                    Ok(handle) => handle,
                    Err(cause) => {
                        return Err(fail(
                            platform,
                            &mut transaction,
                            LoadStage::CapabilityDuplicate,
                            cause,
                        ));
                    }
                };
            transaction.delegated_resource_domain = Some(domain);
            Some(domain)
        } else {
            None
        };
        transaction.delegated_channels[0] = Some(request.channels[0]);
        transaction.delegated_manifest = Some(manifest);
        transfers[0] = transfer(created.root, SELF_ROOT_RIGHTS);
        transfers[1] = transfer(request.channels[0], launch::CHILD_CHANNEL_RIGHTS);
        transfers[2] = transfer(manifest, launch::DEVICE_MANIFEST_RIGHTS);
        if let Some(domain) = staged_domain {
            transfers[3] = transfer(domain, launch::RESOURCE_DOMAIN_CLAIM_RIGHTS);
            4
        } else {
            3
        }
    } else if request.profile == LaunchProfile::Wyrmsh {
        for (index, handle) in request.channels.iter().copied().enumerate() {
            transaction.delegated_channels[index] = Some(handle);
            transfers[index] = transfer(handle, launch::CHILD_CHANNEL_RIGHTS);
        }
        launch::MAX_CAPABILITIES
    } else if request.profile == LaunchProfile::Consoled {
        for (index, handle) in request.channels.iter().copied().enumerate() {
            transaction.delegated_channels[index] = Some(handle);
        }
        transfers[0] = transfer(created.root, SELF_ROOT_RIGHTS);
        transfers[1] = transfer(request.channels[0], launch::CHILD_CHANNEL_RIGHTS);
        transfers[2] = transfer(request.channels[1], launch::CHILD_CHANNEL_RIGHTS);
        3
    } else if request.profile.channel_role().is_some() {
        transaction.delegated_channels[0] = Some(request.channels[0]);
        transfers[0] = transfer(created.root, SELF_ROOT_RIGHTS);
        transfers[1] = transfer(request.channels[0], launch::CHILD_CHANNEL_RIGHTS);
        2
    } else if request.profile.needs_self_root() {
        // WYR0-I probe children receive only their own mapping authority at
        // startup. Shared MemoryObjects are a typed controller protocol after
        // startup, not a loader launch capability.
        transfers[0] = transfer(created.root, SELF_ROOT_RIGHTS);
        1
    } else if request.profile == LaunchProfile::JobV2Streams {
        for (index, handle) in request.channels.iter().copied().enumerate() {
            transaction.delegated_channels[index] = Some(handle);
            transfers[index] = transfer(handle, launch::CHILD_CHANNEL_RIGHTS);
        }
        3
    } else {
        0
    };
    apply_capability_fault(&mut transfers[..transfer_count], fault);

    if let Err(cause) = platform.send_init(
        parent_channel,
        &init[..init_len],
        &transfers[..transfer_count],
    ) {
        // A failed MOVE consumes nothing. Stream endpoints originate with the
        // caller, so it retains every externally supplied endpoint for one
        // exact cleanup path rather than letting loader rollback take partial
        // ownership.
        transaction.delegated_channels.fill(None);
        transaction.delegated_manifest = None;
        return Err(fail(platform, &mut transaction, LoadStage::InitSend, cause));
    }
    // Successful Channel send consumed every externally supplied endpoint.
    *delegated_channels_consumed = !request.channels.is_empty();
    transaction.delegated_channels.fill(None);
    transaction.delegated_manifest = None;
    if request.profile == LaunchProfile::DeviceCoordinatorResourceDomain {
        transaction.delegated_resource_domain = None;
    }
    if request.profile.needs_self_root() {
        transaction.root = None;
        if request.profile.has_loader_authority_trio()
            || request.profile.has_loader_authority_quartet()
        {
            transaction.delegated_bootfs = None;
            transaction.delegated_task_group = None;
            transaction.delegated_resource_domain = None;
        }
    } else if request.profile == LaunchProfile::D6ResourceOwner {
        // INIT consumed the staged resource-domain duplicate, but the
        // parent-side Process root remains loader-owned.  Close it exactly as
        // for other non-self-root profiles so each completed owner retains
        // only the Process and launch Channel returned to bootstrap.
        transaction.delegated_resource_domain = None;
        if let Err(cause) = platform.close(created.root) {
            return Err(fail(
                platform,
                &mut transaction,
                LoadStage::SuccessCleanup,
                cause,
            ));
        }
        transaction.root = None;
    } else if let Err(cause) = platform.close(created.root) {
        return Err(fail(
            platform,
            &mut transaction,
            LoadStage::SuccessCleanup,
            cause,
        ));
    } else {
        transaction.root = None;
    }
    if let Err(cause) = platform.thread_start(
        thread,
        plan.entry,
        stack_pointer,
        created.child_bootstrap,
        startup_abi,
    ) {
        return Err(fail(
            platform,
            &mut transaction,
            LoadStage::ThreadStart,
            cause,
        ));
    }
    if let Err(cause) = platform.close(thread) {
        let process_terminated = platform.process_terminate(created.process).is_ok();
        let thread_terminated = !process_terminated && platform.thread_terminate(thread).is_ok();
        let rollback_failed = !(process_terminated || thread_terminated)
            | platform.close(thread).is_err()
            | platform.close(created.process).is_err()
            | platform.close(parent_channel).is_err();
        return Err(platform_error(
            LoadStage::SuccessCleanup,
            cause,
            rollback_failed,
        ));
    }
    Ok(LoadedProcess {
        process: created.process,
        launch_channel: parent_channel,
    })
}

pub(crate) fn apply_startup_fault(startup_page: &mut [u8], fault: LoadFault) {
    if fault == LoadFault::MalformedStartup {
        // WYR0-D0 requires argc = 1 for every native child.  The page was
        // otherwise built by the canonical checked constructor above.
        startup_page[..8].copy_from_slice(&2_u64.to_le_bytes());
    }
}

pub(crate) fn apply_init_fault(init: &mut [u8], fault: LoadFault) {
    if fault == LoadFault::InitCapabilityCount {
        // Offset 20 is the locked little-endian WRLP capability-count field.
        // The actual Channel transfer count remains three, so the child must
        // reject both inconsistent representations before using authority.
        init[20..24].copy_from_slice(&2_u32.to_le_bytes());
    }
}

pub(crate) fn apply_capability_fault(transfers: &mut [DwHandleTransferV1], fault: LoadFault) {
    match fault {
        LoadFault::InitCapabilityType if transfers.len() == 3 => transfers.swap(0, 2),
        LoadFault::InitCapabilityRights if !transfers.is_empty() => {
            transfers[0].requested_rights = ROOT_RIGHTS;
        }
        _ => {}
    }
}

pub(crate) fn fail<P: LoaderPlatform>(
    platform: &mut P,
    transaction: &mut Transaction,
    stage: LoadStage,
    cause: P::Error,
) -> LoadError<P::Error> {
    let rollback_failed = transaction.rollback(platform);
    platform_error(stage, cause, rollback_failed)
}

pub(crate) fn platform_error<E>(stage: LoadStage, cause: E, rollback_failed: bool) -> LoadError<E> {
    LoadError::Platform {
        stage,
        cause,
        rollback_failed,
    }
}

pub(crate) const fn native_protection(protection: SegmentProtection) -> DwMemoryProtection {
    match protection {
        SegmentProtection::Read => DW_MEMORY_PROTECTION_READ,
        SegmentProtection::ReadWrite => {
            DwMemoryProtection(DW_MEMORY_PROTECTION_READ.0 | DW_MEMORY_PROTECTION_WRITE.0)
        }
        SegmentProtection::ReadExecute => {
            DwMemoryProtection(DW_MEMORY_PROTECTION_READ.0 | DW_MEMORY_PROTECTION_EXECUTE.0)
        }
    }
}

pub(crate) const fn transfer(handle: DwHandle, rights: DwRights) -> DwHandleTransferV1 {
    DwHandleTransferV1 {
        handle,
        requested_rights: rights,
        operation: DW_HANDLE_TRANSFER_MOVE,
        reserved0: 0,
        reserved: [0; 2],
    }
}

pub(crate) const fn empty_segment() -> LoadSegment {
    LoadSegment {
        header_index: 0,
        file_offset: 0,
        file_size: 0,
        memory_size: 0,
        virtual_address: 0,
        mapping_start: 0,
        mapping_size: 0,
        leading_bytes: 0,
        protection: SegmentProtection::Read,
    }
}
