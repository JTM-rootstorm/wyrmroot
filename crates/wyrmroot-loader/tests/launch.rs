use deepwyrm_syscall::{
    DW_OBJECT_TYPE_ADDRESS_REGION, DW_OBJECT_TYPE_CHANNEL, DW_OBJECT_TYPE_MEMORY_OBJECT,
    DW_OBJECT_TYPE_TASK_GROUP, DwHandle, DwReceivedHandleInfoV1,
};
use wyrmroot_loader::launch::{
    self, BOOTFS_RIGHTS, CHILD_CHANNEL_RIGHTS, CHILD_CHANNEL_TRANSFER_RIGHTS, CONSOLED_BYTES,
    DEVICE_COORDINATOR_BYTES, DEVICE_COORDINATOR_RESOURCE_BYTES, DEVICE_DRIVER_BYTES,
    DEVICE_MANIFEST_RIGHTS, HEADER_BYTES, INIT0_BYTES, LOADER_TASK_GROUP_RIGHTS, LaunchError,
    LaunchProfile, PROBE_CHILD_BYTES, RESOURCE_DOMAIN_CLAIM_RIGHTS, SELF_ROOT_RIGHTS,
    SUPERVISOR_BYTES, WYRMSH_BYTES,
};

#[test]
fn wyrmsh_has_exact_wrlp_1_11_six_role_correlated_profile() {
    let mut init = [0xaa; WYRMSH_BYTES];
    assert_eq!(
        launch::encode_init(LaunchProfile::Wyrmsh, 1, &mut init),
        Err(LaunchError::ProfileSpecificEncoderRequired)
    );
    assert_eq!(
        launch::encode_wyrmsh_init(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, &mut init),
        Ok(WYRMSH_BYTES)
    );
    assert_eq!(&init[..4], b"WRLP");
    assert_eq!(
        (
            get16(&init, 4),
            get16(&init, 6),
            get32(&init, 8),
            get32(&init, 16),
            get32(&init, 20),
            get64(&init, 24),
        ),
        (1, 11, 1, 160, 6, 1)
    );
    assert_eq!(
        core::array::from_fn::<_, 6, _>(|index| get32(&init, 40 + index * 8)),
        [8, 9, 10, 16, 6, 7]
    );
    assert_eq!(
        core::array::from_fn::<_, 6, _>(|index| get32(&init, 44 + index * 8)),
        [0; 6]
    );
    assert_eq!(
        core::array::from_fn::<_, 9, _>(|index| get64(&init, 88 + index * 8)),
        [2, 3, 4, 5, 6, 7, 8, 9, 10]
    );
    let parsed = launch::parse_wyrmsh_init(&init, &wyrmsh_handles()).unwrap();
    assert_eq!(parsed.transaction_id, 1);
    assert_eq!(parsed.registry_generation, 2);
    assert_eq!(parsed.registry_endpoint_id, 3);
    assert_eq!(parsed.registry_endpoint_generation, 4);
    assert_eq!(parsed.launch_connection_id, 5);
    assert_eq!(parsed.launch_connection_generation, 6);
    assert_eq!(parsed.console_generation, 7);
    assert_eq!(parsed.status_generation, 8);
    assert_eq!(parsed.child_generation, 9);
    assert_eq!(parsed.outer_launch_transaction, 10);

    let mut ready = [0xaa; HEADER_BYTES];
    assert_eq!(
        launch::encode_ready_for_profile(LaunchProfile::Wyrmsh, 1, &mut ready),
        Ok(HEADER_BYTES)
    );
    assert_eq!((get16(&ready, 6), get32(&ready, 8)), (11, 2));
    assert_eq!(
        launch::parse_ready_for_profile(LaunchProfile::Wyrmsh, &ready, 1),
        Ok(())
    );
    assert_eq!(
        launch::parse_ready_for_profile(LaunchProfile::Consoled, &ready, 1),
        Err(LaunchError::BadVersion)
    );
    assert_eq!(
        launch::parse_ready_for_profile(LaunchProfile::Wyrmsh, &ready, 2),
        Err(LaunchError::TransactionMismatch)
    );
}

#[test]
fn wyrmsh_rejects_every_role_handle_and_correlation_mismatch() {
    let mut init = [0; WYRMSH_BYTES];
    launch::encode_wyrmsh_init(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, &mut init).unwrap();
    let handles = wyrmsh_handles();

    for index in 0..6 {
        let mut wrong = init;
        wrong[40 + index * 8..44 + index * 8].copy_from_slice(&99_u32.to_le_bytes());
        assert_eq!(
            launch::parse_wyrmsh_init(&wrong, &handles),
            Err(LaunchError::BadCapabilityRole { index })
        );

        let mut wrong = handles;
        wrong[index].rights = CHILD_CHANNEL_TRANSFER_RIGHTS;
        assert_eq!(
            launch::parse_wyrmsh_init(&init, &wrong),
            Err(LaunchError::HandleMetadata { index })
        );

        let mut wrong = handles;
        wrong[index].object_type = DW_OBJECT_TYPE_TASK_GROUP;
        assert_eq!(
            launch::parse_wyrmsh_init(&init, &wrong),
            Err(LaunchError::HandleMetadata { index })
        );
    }
    assert_eq!(
        launch::parse_wyrmsh_init(&init, &handles[..5]),
        Err(LaunchError::HandleCount)
    );
    for index in 0..9 {
        let mut wrong = init;
        wrong[88 + index * 8..96 + index * 8].fill(0);
        assert_eq!(
            launch::parse_wyrmsh_init(&wrong, &handles),
            Err(LaunchError::ZeroTransaction)
        );
    }
    let mut alias = init;
    alias[152..160].copy_from_slice(&1_u64.to_le_bytes());
    assert_eq!(
        launch::parse_wyrmsh_init(&alias, &handles),
        Err(LaunchError::TransactionAlias)
    );
    assert_eq!(
        launch::encode_wyrmsh_init(1, 2, 3, 4, 5, 6, 7, 8, 9, 1, &mut init),
        Err(LaunchError::TransactionAlias)
    );
    assert_eq!(
        launch::encode_wyrmsh_init(1, 2, 3, 4, 5, 6, 7, 8, 0, 10, &mut init),
        Err(LaunchError::ZeroTransaction)
    );
}

#[test]
fn wyr1_d4_consoled_has_exact_hardware_free_multi_endpoint_profile() {
    let mut init = [0xaa; CONSOLED_BYTES];
    assert_eq!(
        launch::encode_init(LaunchProfile::Consoled, 0xd400, &mut init),
        Err(LaunchError::ProfileSpecificEncoderRequired)
    );
    assert_eq!(
        launch::encode_consoled_init(0xd400, 2, 3, 4, 5, 6, &mut init),
        Ok(CONSOLED_BYTES)
    );
    assert_eq!(
        (get16(&init, 6), get32(&init, 16), get32(&init, 20)),
        (10, 128, 3)
    );
    assert_eq!(
        [get32(&init, 40), get32(&init, 48), get32(&init, 56)],
        [1, 6, 7]
    );
    let handles = [
        received(1, DW_OBJECT_TYPE_ADDRESS_REGION, SELF_ROOT_RIGHTS),
        received(2, DW_OBJECT_TYPE_CHANNEL, CHILD_CHANNEL_RIGHTS),
        received(3, DW_OBJECT_TYPE_CHANNEL, CHILD_CHANNEL_RIGHTS),
    ];
    let parsed = launch::parse_consoled_init(&init, &handles).unwrap();
    assert_eq!(
        (
            parsed.transaction_id,
            parsed.registry_generation,
            parsed.registry_endpoint_id,
            parsed.registry_endpoint_generation,
            parsed.launch_connection_id,
            parsed.launch_connection_generation,
        ),
        (0xd400, 2, 3, 4, 5, 6)
    );
    assert_eq!(
        launch::parse_consoled_init(&init, &handles[..2]),
        Err(LaunchError::HandleCount)
    );
    let mut wrong_role = init;
    wrong_role[40..44].copy_from_slice(&7_u32.to_le_bytes());
    assert_eq!(
        launch::parse_consoled_init(&wrong_role, &handles),
        Err(LaunchError::BadCapabilityRole { index: 0 })
    );
    let mut reserved_role = init;
    reserved_role[52..56].copy_from_slice(&1_u32.to_le_bytes());
    assert_eq!(
        launch::parse_consoled_init(&reserved_role, &handles),
        Err(LaunchError::BadCapabilityRole { index: 1 })
    );
    let mut wrong = handles;
    wrong[2].rights = SELF_ROOT_RIGHTS;
    assert_eq!(
        launch::parse_consoled_init(&init, &wrong),
        Err(LaunchError::HandleMetadata { index: 2 })
    );
    init[120..128].fill(0);
    assert_eq!(
        launch::parse_consoled_init(&init, &handles),
        Err(LaunchError::ZeroTransaction)
    );

    let mut ready = [0; HEADER_BYTES];
    launch::encode_ready_for_profile(LaunchProfile::Consoled, 0xd400, &mut ready).unwrap();
    assert_eq!(
        launch::parse_ready_for_profile(LaunchProfile::LaunchClient, &ready, 0xd400),
        Err(LaunchError::BadVersion)
    );
}

#[test]
fn child_channel_transfer_rights_are_sender_only_staging_authority() {
    assert_eq!(CHILD_CHANNEL_RIGHTS.0, 0x113);
    assert_eq!(CHILD_CHANNEL_TRANSFER_RIGHTS.0, 0x193);
    assert_eq!(
        CHILD_CHANNEL_TRANSFER_RIGHTS.0 & !deepwyrm_syscall::DW_RIGHT_TRANSFER.0,
        CHILD_CHANNEL_RIGHTS.0
    );
}

#[test]
fn d6_owner_is_a_private_single_claim_capability_profile() {
    let mut bytes = [0_u8; HEADER_BYTES + 8];
    assert_eq!(
        launch::encode_init(LaunchProfile::D6ResourceOwner, 0xd6_01, &mut bytes),
        Ok(HEADER_BYTES + 8)
    );
    assert_eq!(
        (get16(&bytes, 6), get32(&bytes, 20), get32(&bytes, 40)),
        (8, 1, 15)
    );
    let domain = [received(
        1,
        DW_OBJECT_TYPE_TASK_GROUP,
        RESOURCE_DOMAIN_CLAIM_RIGHTS,
    )];
    assert!(launch::parse_init(LaunchProfile::D6ResourceOwner, &bytes, &domain).is_ok());
    assert!(launch::parse_init(LaunchProfile::Supervisor, &bytes, &domain).is_err());
    let mut broad = domain;
    broad[0].rights = LOADER_TASK_GROUP_RIGHTS;
    assert_eq!(
        launch::parse_init(LaunchProfile::D6ResourceOwner, &bytes, &broad),
        Err(LaunchError::HandleMetadata { index: 0 })
    );
}

#[test]
fn wyr1_c3_driver_has_exact_reduced_direct_control_profile() {
    let mut bytes = [0; DEVICE_DRIVER_BYTES];
    let handles = [
        received(1, DW_OBJECT_TYPE_ADDRESS_REGION, SELF_ROOT_RIGHTS),
        received(2, DW_OBJECT_TYPE_CHANNEL, CHILD_CHANNEL_RIGHTS),
    ];
    launch::encode_device_driver_init(7, 1, 2, 3, 4, 5, 6, &mut bytes).unwrap();
    assert_eq!(get16(&bytes, 6), 6);
    assert_eq!(get32(&bytes, 20), 2);
    let parsed = launch::parse_device_driver_init(&bytes, &handles).unwrap();
    assert_eq!(
        (
            parsed.supervisor_generation,
            parsed.role_id,
            parsed.attempt_generation
        ),
        (1, 2, 3)
    );
    let mut wrong = handles;
    wrong[1].rights = SELF_ROOT_RIGHTS;
    assert_eq!(
        launch::parse_device_driver_init(&bytes, &wrong),
        Err(LaunchError::HandleMetadata { index: 1 })
    );
}

#[test]
fn exact_init0_round_trip_validates_roles_and_handles() {
    let mut bytes = [0xaa; INIT0_BYTES];
    assert_eq!(
        launch::encode_init(LaunchProfile::Init0, 7, &mut bytes),
        Ok(64)
    );
    assert_eq!(&bytes[..4], b"WRLP");
    assert_eq!(get16(&bytes, 4), 1);
    assert_eq!(get16(&bytes, 6), 0);
    assert_eq!(get32(&bytes, 8), 1);
    assert_eq!(get32(&bytes, 16), 64);
    assert_eq!(get32(&bytes, 20), 3);
    assert_eq!(get64(&bytes, 24), 7);
    assert_eq!(
        [get32(&bytes, 40), get32(&bytes, 48), get32(&bytes, 56)],
        [1, 2, 3]
    );
    let handles = init0_handles();
    assert_eq!(
        launch::parse_init(LaunchProfile::Init0, &bytes, &handles)
            .unwrap()
            .transaction_id,
        7
    );
}

#[test]
fn i2_stress_uses_the_same_explicit_three_capability_contract_as_init0() {
    let mut bytes = [0; INIT0_BYTES];
    let handles = init0_handles();
    assert_eq!(
        launch::encode_init(LaunchProfile::I2Stress, 0x2201, &mut bytes),
        Ok(INIT0_BYTES)
    );
    assert_eq!(
        launch::parse_init(LaunchProfile::I2Stress, &bytes, &handles)
            .unwrap()
            .transaction_id,
        0x2201
    );
    assert!(launch::parse_init(LaunchProfile::I2Stress, &bytes, &handles[..2]).is_err());
}

#[test]
fn capability_controller_retains_the_wrpl_1_0_init0_authority_trio() {
    let mut bytes = [0; INIT0_BYTES];
    let handles = init0_handles();
    assert_eq!(
        launch::encode_init(LaunchProfile::CapabilityController, 0xc0de, &mut bytes),
        Ok(INIT0_BYTES)
    );
    assert_eq!(get16(&bytes, 4), 1);
    assert_eq!(get16(&bytes, 6), 0);
    assert_eq!(get32(&bytes, 20), 3);
    assert_eq!(
        launch::parse_init(LaunchProfile::CapabilityController, &bytes, &handles)
            .unwrap()
            .transaction_id,
        0xc0de
    );
}

#[test]
fn probe_child_is_an_exact_wrpl_1_1_self_root_only_profile() {
    let mut bytes = [0xaa; PROBE_CHILD_BYTES];
    let handle = [received(1, DW_OBJECT_TYPE_ADDRESS_REGION, SELF_ROOT_RIGHTS)];
    assert_eq!(
        launch::encode_init(LaunchProfile::ProbeChild, 0xbabe, &mut bytes),
        Ok(PROBE_CHILD_BYTES)
    );
    assert_eq!(get16(&bytes, 4), 1);
    assert_eq!(get16(&bytes, 6), 1);
    assert_eq!(get32(&bytes, 16), PROBE_CHILD_BYTES as u32);
    assert_eq!(get32(&bytes, 20), 1);
    assert_eq!(get32(&bytes, 40), 1);
    assert_eq!(get32(&bytes, 44), 0);
    assert_eq!(
        launch::parse_init(LaunchProfile::ProbeChild, &bytes, &handle)
            .unwrap()
            .transaction_id,
        0xbabe
    );
}

#[test]
fn probe_child_rejects_v1_0_or_other_profile_shapes() {
    let mut probe = [0; PROBE_CHILD_BYTES];
    let root = [received(1, DW_OBJECT_TYPE_ADDRESS_REGION, SELF_ROOT_RIGHTS)];
    launch::encode_init(LaunchProfile::ProbeChild, 7, &mut probe).unwrap();
    probe[6..8].copy_from_slice(&0_u16.to_le_bytes());
    assert_eq!(
        launch::parse_init(LaunchProfile::ProbeChild, &probe, &root),
        Err(LaunchError::BadVersion)
    );

    let mut controller = [0; INIT0_BYTES];
    let controller_handles = init0_handles();
    launch::encode_init(LaunchProfile::CapabilityController, 7, &mut controller).unwrap();
    assert_eq!(
        launch::parse_init(LaunchProfile::ProbeChild, &controller, &controller_handles),
        Err(LaunchError::BufferSize)
    );
}

#[test]
fn probe_child_rejects_wrong_cardinality_role_or_root_metadata() {
    let mut bytes = [0; PROBE_CHILD_BYTES];
    let root = [received(1, DW_OBJECT_TYPE_ADDRESS_REGION, SELF_ROOT_RIGHTS)];
    launch::encode_init(LaunchProfile::ProbeChild, 1, &mut bytes).unwrap();
    assert_eq!(
        launch::parse_init(LaunchProfile::ProbeChild, &bytes, &[]),
        Err(LaunchError::HandleCount)
    );

    bytes[20..24].copy_from_slice(&2_u32.to_le_bytes());
    assert_eq!(
        launch::parse_init(LaunchProfile::ProbeChild, &bytes, &root),
        Err(LaunchError::BadCapabilityCount)
    );

    launch::encode_init(LaunchProfile::ProbeChild, 1, &mut bytes).unwrap();
    bytes[40..44].copy_from_slice(&2_u32.to_le_bytes());
    assert_eq!(
        launch::parse_init(LaunchProfile::ProbeChild, &bytes, &root),
        Err(LaunchError::BadCapabilityRole { index: 0 })
    );

    launch::encode_init(LaunchProfile::ProbeChild, 1, &mut bytes).unwrap();
    for field in 0..4 {
        let mut wrong_metadata = root;
        match field {
            0 => wrong_metadata[0].handle = DwHandle(0),
            1 => wrong_metadata[0].object_type = DW_OBJECT_TYPE_MEMORY_OBJECT,
            2 => wrong_metadata[0].rights = BOOTFS_RIGHTS,
            _ => wrong_metadata[0].reserved0 = 1,
        }
        assert_eq!(
            launch::parse_init(LaunchProfile::ProbeChild, &bytes, &wrong_metadata),
            Err(LaunchError::HandleMetadata { index: 0 })
        );
    }
}

#[test]
fn hello_and_ready_are_handle_free_exact_headers() {
    let mut init = [0xaa; HEADER_BYTES];
    launch::encode_init(LaunchProfile::Hello, 9, &mut init).unwrap();
    assert!(launch::parse_init(LaunchProfile::Hello, &init, &[]).is_ok());
    let mut ready = [0xaa; HEADER_BYTES];
    launch::encode_ready(9, &mut ready).unwrap();
    assert_eq!(get16(&ready, 4), 1);
    assert_eq!(get16(&ready, 6), 0);
    assert_eq!(get32(&ready, 8), 2);
    assert_eq!(launch::parse_ready(&ready, 9), Ok(()));
    assert_eq!(
        launch::parse_ready(&ready, 10),
        Err(LaunchError::TransactionMismatch)
    );
}

#[test]
fn profile_aware_ready_binds_probe_child_to_wrpl_1_1_and_transaction() {
    let mut ready = [0xaa; HEADER_BYTES];
    assert_eq!(
        launch::encode_ready_for_profile(LaunchProfile::ProbeChild, 0xbabe, &mut ready),
        Ok(HEADER_BYTES)
    );
    assert_eq!(get16(&ready, 4), 1);
    assert_eq!(get16(&ready, 6), 1);
    assert_eq!(get32(&ready, 8), 2);
    assert_eq!(get32(&ready, 20), 0);
    assert_eq!(
        launch::parse_ready_for_profile(LaunchProfile::ProbeChild, &ready, 0xbabe),
        Ok(())
    );
    assert_eq!(
        launch::parse_ready_for_profile(LaunchProfile::ProbeChild, &ready, 0xbeef),
        Err(LaunchError::TransactionMismatch)
    );
}

#[test]
fn supervisor_and_early_stub_are_exact_wrpl_1_2_profiles() {
    let legacy_init0 = {
        let mut bytes = [0; INIT0_BYTES];
        launch::encode_init(LaunchProfile::Init0, 7, &mut bytes).unwrap();
        bytes
    };
    let legacy_probe = {
        let mut bytes = [0; PROBE_CHILD_BYTES];
        launch::encode_init(LaunchProfile::ProbeChild, 7, &mut bytes).unwrap();
        bytes
    };
    let handles = init0_handles();
    let mut supervisor = [0xaa; SUPERVISOR_BYTES];
    assert_eq!(
        launch::encode_init(LaunchProfile::Supervisor, 0x1200, &mut supervisor),
        Ok(SUPERVISOR_BYTES)
    );
    assert_eq!(
        (
            get16(&supervisor, 6),
            get32(&supervisor, 16),
            get32(&supervisor, 20)
        ),
        (2, 64, 3)
    );
    assert_eq!(
        launch::parse_init(LaunchProfile::Supervisor, &supervisor, &handles)
            .unwrap()
            .transaction_id,
        0x1200
    );

    let mut stub = [0xaa; HEADER_BYTES];
    launch::encode_init(LaunchProfile::EarlyBootStub, 0x1201, &mut stub).unwrap();
    assert_eq!(
        (get16(&stub, 6), get32(&stub, 16), get32(&stub, 20)),
        (2, 40, 0)
    );
    assert!(launch::parse_init(LaunchProfile::EarlyBootStub, &stub, &[]).is_ok());
    let mut ready = [0xaa; HEADER_BYTES];
    launch::encode_ready_for_profile(LaunchProfile::EarlyBootStub, 0x1201, &mut ready).unwrap();
    assert_eq!(
        launch::parse_ready_for_profile(LaunchProfile::EarlyBootStub, &ready, 0x1201),
        Ok(())
    );
    assert_eq!(
        launch::parse_ready_for_profile(LaunchProfile::Hello, &ready, 0x1201),
        Err(LaunchError::BadVersion)
    );

    // Adding 1.2 profiles must not perturb the exact established bytes.
    let mut after_init0 = [0; INIT0_BYTES];
    let mut after_probe = [0; PROBE_CHILD_BYTES];
    launch::encode_init(LaunchProfile::Init0, 7, &mut after_init0).unwrap();
    launch::encode_init(LaunchProfile::ProbeChild, 7, &mut after_probe).unwrap();
    assert_eq!(after_init0, legacy_init0);
    assert_eq!(after_probe, legacy_probe);
}

#[test]
fn profile_aware_ready_rejects_minor_mismatch_without_relaxing_v1_0_compatibility() {
    let mut probe_ready = [0; HEADER_BYTES];
    launch::encode_ready_for_profile(LaunchProfile::ProbeChild, 7, &mut probe_ready).unwrap();
    assert_eq!(
        launch::parse_ready_for_profile(LaunchProfile::CapabilityController, &probe_ready, 7),
        Err(LaunchError::BadVersion)
    );
    assert_eq!(
        launch::parse_ready(&probe_ready, 7),
        Err(LaunchError::BadVersion)
    );

    let mut legacy_ready = [0; HEADER_BYTES];
    launch::encode_ready(7, &mut legacy_ready).unwrap();
    assert_eq!(
        launch::parse_ready_for_profile(LaunchProfile::ProbeChild, &legacy_ready, 7),
        Err(LaunchError::BadVersion)
    );
    assert_eq!(
        launch::parse_ready_for_profile(LaunchProfile::CapabilityController, &legacy_ready, 7),
        Ok(())
    );
}

#[test]
fn wyr1_b_profiles_are_exact_wrlp_1_3_shapes() {
    for profile in [
        LaunchProfile::BootstrapRegistry,
        LaunchProfile::BootstrapService,
        LaunchProfile::RegistryClient,
        LaunchProfile::LaunchClient,
    ] {
        let mut init = [0xaa; 56];
        launch::encode_init(profile, 0x1300, &mut init).unwrap();
        assert_eq!(
            (get16(&init, 6), get32(&init, 16), get32(&init, 20)),
            (3, 56, 2)
        );
        let handles = [
            received(1, DW_OBJECT_TYPE_ADDRESS_REGION, SELF_ROOT_RIGHTS),
            received(2, DW_OBJECT_TYPE_CHANNEL, CHILD_CHANNEL_RIGHTS),
        ];
        assert!(launch::parse_init(profile, &init, &handles).is_ok());
    }

    let mut no_streams = [0xaa; HEADER_BYTES];
    launch::encode_init(LaunchProfile::JobV2, 0x1301, &mut no_streams).unwrap();
    assert_eq!((get16(&no_streams, 6), get32(&no_streams, 20)), (3, 0));
    assert!(launch::parse_init(LaunchProfile::JobV2, &no_streams, &[]).is_ok());

    let mut streams = [0xaa; 64];
    launch::encode_init(LaunchProfile::JobV2Streams, 0x1302, &mut streams).unwrap();
    assert_eq!((get16(&streams, 6), get32(&streams, 20)), (3, 3));
    assert_eq!(
        [
            get32(&streams, 40),
            get32(&streams, 48),
            get32(&streams, 56)
        ],
        [8, 9, 10]
    );
    let handles = [
        received(3, DW_OBJECT_TYPE_CHANNEL, CHILD_CHANNEL_RIGHTS),
        received(4, DW_OBJECT_TYPE_CHANNEL, CHILD_CHANNEL_RIGHTS),
        received(5, DW_OBJECT_TYPE_CHANNEL, CHILD_CHANNEL_RIGHTS),
    ];
    assert!(launch::parse_init(LaunchProfile::JobV2Streams, &streams, &handles).is_ok());
}

#[test]
fn wyr1_c_device_coordinator_has_exact_hardware_free_startup_roles() {
    let mut init = [0u8; DEVICE_COORDINATOR_BYTES];
    assert_eq!(
        launch::encode_init(LaunchProfile::DeviceCoordinator, 0xc100, &mut init),
        Err(LaunchError::ProfileSpecificEncoderRequired)
    );
    assert_eq!(
        launch::encode_device_coordinator_init(0xc100, 7, &mut init),
        Ok(DEVICE_COORDINATOR_BYTES)
    );
    assert_eq!(get16(&init, 6), 5);
    assert_eq!(
        [get32(&init, 40), get32(&init, 48), get32(&init, 56)],
        [1, 5, 12]
    );
    let handles = [
        received(1, DW_OBJECT_TYPE_ADDRESS_REGION, SELF_ROOT_RIGHTS),
        received(2, DW_OBJECT_TYPE_CHANNEL, CHILD_CHANNEL_RIGHTS),
        received(3, DW_OBJECT_TYPE_MEMORY_OBJECT, DEVICE_MANIFEST_RIGHTS),
    ];
    assert_eq!(
        launch::parse_device_coordinator_init(&init, &handles)
            .unwrap()
            .supervisor_generation,
        7
    );

    let mut wrong_manifest = handles;
    wrong_manifest[2].rights = CHILD_CHANNEL_RIGHTS;
    assert_eq!(
        launch::parse_init(LaunchProfile::DeviceCoordinator, &init, &wrong_manifest),
        Err(LaunchError::HandleMetadata { index: 2 })
    );

    let mut ready = [0u8; HEADER_BYTES];
    launch::encode_ready_for_profile(LaunchProfile::DeviceCoordinator, 0xc100, &mut ready).unwrap();
    assert!(
        launch::parse_ready_for_profile(LaunchProfile::DeviceCoordinator, &ready, 0xc100).is_ok()
    );
    assert!(launch::parse_ready_for_profile(LaunchProfile::EarlyBootStub, &ready, 0xc100).is_err());

    init[64..72].fill(0);
    assert_eq!(
        launch::parse_device_coordinator_init(&init, &handles),
        Err(LaunchError::ZeroTransaction)
    );
}

#[test]
fn wyr1_c4_resource_profile_is_exact_and_does_not_reinterpret_c3() {
    let mut init = [0u8; DEVICE_COORDINATOR_RESOURCE_BYTES];
    assert_eq!(
        launch::encode_init(
            LaunchProfile::DeviceCoordinatorResourceDomain,
            0xc400,
            &mut init
        ),
        Err(LaunchError::ProfileSpecificEncoderRequired)
    );
    assert_eq!(
        launch::encode_device_coordinator_resource_init(0xc400, 9, &mut init),
        Ok(DEVICE_COORDINATOR_RESOURCE_BYTES)
    );
    assert_eq!((get16(&init, 6), get32(&init, 20)), (9, 4));
    assert_eq!(
        [
            get32(&init, 40),
            get32(&init, 48),
            get32(&init, 56),
            get32(&init, 64),
        ],
        [1, 5, 12, 14]
    );
    let handles = [
        received(1, DW_OBJECT_TYPE_ADDRESS_REGION, SELF_ROOT_RIGHTS),
        received(2, DW_OBJECT_TYPE_CHANNEL, CHILD_CHANNEL_RIGHTS),
        received(3, DW_OBJECT_TYPE_MEMORY_OBJECT, DEVICE_MANIFEST_RIGHTS),
        received(4, DW_OBJECT_TYPE_TASK_GROUP, RESOURCE_DOMAIN_CLAIM_RIGHTS),
    ];
    assert_eq!(
        launch::parse_device_coordinator_resource_init(&init, &handles)
            .unwrap()
            .supervisor_generation,
        9
    );
    assert!(launch::parse_device_coordinator_init(&init, &handles[..3]).is_err());
    let mut broad = handles;
    broad[3].rights = LOADER_TASK_GROUP_RIGHTS;
    assert_eq!(
        launch::parse_device_coordinator_resource_init(&init, &broad),
        Err(LaunchError::HandleMetadata { index: 3 })
    );
}

#[test]
fn dw1b_progress_has_one_exact_test_private_data_channel() {
    let mut init = [0xaa; PROBE_CHILD_BYTES];
    launch::encode_init(LaunchProfile::Dw1bProgress, 0xD1B0_0002, &mut init).unwrap();
    assert_eq!((get16(&init, 6), get32(&init, 20)), (4, 1));
    let handles = [received(77, DW_OBJECT_TYPE_CHANNEL, CHILD_CHANNEL_RIGHTS)];
    assert!(launch::parse_init(LaunchProfile::Dw1bProgress, &init, &handles).is_ok());
    assert!(launch::parse_init(LaunchProfile::Hello, &init, &handles).is_err());
    let mut ready = [0_u8; HEADER_BYTES];
    launch::encode_ready_for_profile(LaunchProfile::Dw1bProgress, 0xD1B0_0002, &mut ready).unwrap();
    assert!(
        launch::parse_ready_for_profile(LaunchProfile::Dw1bProgress, &ready, 0xD1B0_0002).is_ok()
    );
    assert!(launch::parse_ready_for_profile(LaunchProfile::Hello, &ready, 0xD1B0_0002).is_err());
}

#[test]
fn malformed_headers_fail_closed() {
    let handles = init0_handles();
    for offset in [0, 4, 6, 8, 12, 16, 20, 32] {
        let mut bytes = [0; INIT0_BYTES];
        launch::encode_init(LaunchProfile::Init0, 7, &mut bytes).unwrap();
        bytes[offset] ^= 0x55;
        assert!(
            launch::parse_init(LaunchProfile::Init0, &bytes, &handles).is_err(),
            "offset {offset}"
        );
    }
    let mut bytes = [0; INIT0_BYTES];
    launch::encode_init(LaunchProfile::Init0, 7, &mut bytes).unwrap();
    bytes[24..32].fill(0);
    assert_eq!(
        launch::parse_init(LaunchProfile::Init0, &bytes, &handles),
        Err(LaunchError::ZeroTransaction)
    );
    let mut short = [0; HEADER_BYTES];
    assert_eq!(
        launch::encode_init(LaunchProfile::Init0, 1, &mut short),
        Err(LaunchError::BufferSize)
    );
    let mut bytes = [0; INIT0_BYTES];
    assert_eq!(
        launch::encode_init(LaunchProfile::Init0, 0, &mut bytes),
        Err(LaunchError::ZeroTransaction)
    );
}

#[test]
fn wrong_roles_counts_types_rights_and_reserved_data_fail_closed() {
    let mut bytes = [0; INIT0_BYTES];
    launch::encode_init(LaunchProfile::Init0, 1, &mut bytes).unwrap();
    let handles = init0_handles();
    bytes[40] = 2;
    assert_eq!(
        launch::parse_init(LaunchProfile::Init0, &bytes, &handles),
        Err(LaunchError::BadCapabilityRole { index: 0 })
    );

    launch::encode_init(LaunchProfile::Init0, 1, &mut bytes).unwrap();
    assert_eq!(
        launch::parse_init(LaunchProfile::Init0, &bytes, &handles[..2]),
        Err(LaunchError::HandleCount)
    );
    for field in 0..4 {
        let mut bad = handles;
        match field {
            0 => bad[1].handle = DwHandle(0),
            1 => bad[1].object_type = DW_OBJECT_TYPE_TASK_GROUP,
            2 => bad[1].rights = SELF_ROOT_RIGHTS,
            _ => bad[1].reserved0 = 1,
        }
        assert_eq!(
            launch::parse_init(LaunchProfile::Init0, &bytes, &bad),
            Err(LaunchError::HandleMetadata { index: 1 })
        );
    }
}

fn init0_handles() -> [DwReceivedHandleInfoV1; 3] {
    [
        received(1, DW_OBJECT_TYPE_ADDRESS_REGION, SELF_ROOT_RIGHTS),
        received(2, DW_OBJECT_TYPE_MEMORY_OBJECT, BOOTFS_RIGHTS),
        received(3, DW_OBJECT_TYPE_TASK_GROUP, LOADER_TASK_GROUP_RIGHTS),
    ]
}

fn wyrmsh_handles() -> [DwReceivedHandleInfoV1; 6] {
    core::array::from_fn(|index| {
        received(
            index as u64 + 1,
            DW_OBJECT_TYPE_CHANNEL,
            CHILD_CHANNEL_RIGHTS,
        )
    })
}

fn received(
    handle: u64,
    object_type: deepwyrm_syscall::DwObjectType,
    rights: deepwyrm_syscall::DwRights,
) -> DwReceivedHandleInfoV1 {
    DwReceivedHandleInfoV1 {
        handle: DwHandle(handle),
        rights,
        object_type,
        reserved0: 0,
        reserved: [0; 2],
    }
}
fn get32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
}
fn get16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes(bytes[offset..offset + 2].try_into().unwrap())
}
fn get64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())
}
