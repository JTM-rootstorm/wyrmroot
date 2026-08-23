use deepwyrm_syscall::{
    DW_OBJECT_TYPE_ADDRESS_REGION, DW_OBJECT_TYPE_MEMORY_OBJECT, DW_OBJECT_TYPE_TASK_GROUP,
    DwHandle, DwReceivedHandleInfoV1,
};
use wyrmroot_loader::launch::{
    self, BOOTFS_RIGHTS, HEADER_BYTES, INIT0_BYTES, LOADER_TASK_GROUP_RIGHTS, LaunchError,
    LaunchProfile, SELF_ROOT_RIGHTS,
};

#[test]
fn exact_init0_round_trip_validates_roles_and_handles() {
    let mut bytes = [0xaa; INIT0_BYTES];
    assert_eq!(
        launch::encode_init(LaunchProfile::Init0, 7, &mut bytes),
        Ok(64)
    );
    assert_eq!(&bytes[..4], b"WRLP");
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
fn hello_and_ready_are_handle_free_exact_headers() {
    let mut init = [0xaa; HEADER_BYTES];
    launch::encode_init(LaunchProfile::Hello, 9, &mut init).unwrap();
    assert!(launch::parse_init(LaunchProfile::Hello, &init, &[]).is_ok());
    let mut ready = [0xaa; HEADER_BYTES];
    launch::encode_ready(9, &mut ready).unwrap();
    assert_eq!(get32(&ready, 8), 2);
    assert_eq!(launch::parse_ready(&ready, 9), Ok(()));
    assert_eq!(
        launch::parse_ready(&ready, 10),
        Err(LaunchError::TransactionMismatch)
    );
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
fn get64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())
}
