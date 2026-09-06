// SPDX-License-Identifier: GPL-3.0-or-later

use deepwyrm_syscall::{
    DW_OBJECT_TYPE_CHANNEL, DW_OBJECT_TYPE_TASK_GROUP, DwHandle, DwReceivedHandleInfoV1,
};
use wyrmroot_loader::launch::{
    self, CHILD_CHANNEL_RIGHTS, CHILD_CHANNEL_TRANSFER_RIGHTS, HEADER_BYTES, LaunchProfile,
    WYRMSH_BYTES,
};

fn handles() -> [DwReceivedHandleInfoV1; 6] {
    core::array::from_fn(|index| DwReceivedHandleInfoV1 {
        handle: DwHandle(index as u64 + 1),
        rights: CHILD_CHANNEL_RIGHTS,
        object_type: DW_OBJECT_TYPE_CHANNEL,
        reserved0: 0,
        reserved: [0; 2],
    })
}

fn init() -> [u8; WYRMSH_BYTES] {
    let mut bytes = [0; WYRMSH_BYTES];
    launch::encode_wyrmsh_init(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, &mut bytes).unwrap();
    bytes
}

#[test]
fn wyrmsh_init_exhausts_truncation_descriptor_and_metadata_shapes() {
    let bytes = init();
    let received = handles();
    for cut in 0..WYRMSH_BYTES {
        assert!(launch::parse_wyrmsh_init(&bytes[..cut], &received).is_err());
    }

    let fixed = (0..24).chain(32..88);
    let mut mutations = 0;
    for offset in fixed {
        let mut malformed = bytes;
        malformed[offset] ^= 1;
        assert!(
            launch::parse_wyrmsh_init(&malformed, &received).is_err(),
            "offset {offset}"
        );
        mutations += 1;
    }
    assert_eq!(mutations, 80);

    for index in 0..9 {
        let mut malformed = bytes;
        malformed[88 + index * 8..96 + index * 8].fill(0);
        assert!(launch::parse_wyrmsh_init(&malformed, &received).is_err());
    }

    let mut metadata_cases = 0;
    for index in 0..received.len() {
        let mut malformed = received;
        malformed[index].handle = DwHandle(0);
        assert!(launch::parse_wyrmsh_init(&bytes, &malformed).is_err());
        metadata_cases += 1;

        let mut malformed = received;
        malformed[index].rights = CHILD_CHANNEL_TRANSFER_RIGHTS;
        assert!(launch::parse_wyrmsh_init(&bytes, &malformed).is_err());
        metadata_cases += 1;

        let mut malformed = received;
        malformed[index].object_type = DW_OBJECT_TYPE_TASK_GROUP;
        assert!(launch::parse_wyrmsh_init(&bytes, &malformed).is_err());
        metadata_cases += 1;

        let mut malformed = received;
        malformed[index].reserved0 = 1;
        assert!(launch::parse_wyrmsh_init(&bytes, &malformed).is_err());
        metadata_cases += 1;

        let mut malformed = received;
        malformed[index].reserved[1] = 1;
        assert!(launch::parse_wyrmsh_init(&bytes, &malformed).is_err());
        metadata_cases += 1;
    }
    assert_eq!(metadata_cases, 30);
}

#[test]
fn wyrmsh_ready_exhausts_truncations_and_rejects_old_whole_tuple() {
    let mut ready = [0; HEADER_BYTES];
    launch::encode_ready_for_profile(LaunchProfile::Wyrmsh, 0x701, &mut ready).unwrap();
    for cut in 0..HEADER_BYTES {
        assert!(
            launch::parse_ready_for_profile(LaunchProfile::Wyrmsh, &ready[..cut], 0x701).is_err()
        );
    }
    for offset in (0..24).chain(32..HEADER_BYTES) {
        let mut malformed = ready;
        malformed[offset] ^= 1;
        assert!(launch::parse_ready_for_profile(LaunchProfile::Wyrmsh, &malformed, 0x701).is_err());
    }
    assert!(launch::parse_ready_for_profile(LaunchProfile::Wyrmsh, &ready, 0x801).is_err());

    let old = launch::parse_wyrmsh_init(&init(), &handles()).unwrap();
    let mut current_bytes = [0; WYRMSH_BYTES];
    launch::encode_wyrmsh_init(11, 12, 13, 14, 15, 16, 17, 18, 19, 20, &mut current_bytes).unwrap();
    let current = launch::parse_wyrmsh_init(&current_bytes, &handles()).unwrap();
    assert_ne!(old, current);
    assert_eq!(old.transaction_id, 1);
    assert_eq!(current.transaction_id, 11);
}
