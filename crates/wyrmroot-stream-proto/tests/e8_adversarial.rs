// SPDX-License-Identifier: GPL-3.0-or-later

use wyrmroot_stream_proto::{
    HEADER_BYTES, MAX_PAYLOAD_BYTES, MAX_RECORD_BYTES, decode_data, encode_data,
};

#[test]
fn wrst_exhausts_truncations_header_shapes_and_declared_sizes() {
    let mut bytes = [0; MAX_RECORD_BYTES];
    let payload = [0x5a; MAX_PAYLOAD_BYTES];
    let size = encode_data(&payload, &mut bytes).unwrap();
    assert_eq!(size, MAX_RECORD_BYTES);
    for cut in 0..size {
        assert!(decode_data(&bytes[..cut]).is_err());
    }

    let mut cases = 0;
    for offset in 0..HEADER_BYTES {
        if (16..20).contains(&offset) {
            continue;
        }
        let mut malformed = bytes;
        malformed[offset] ^= 1;
        assert!(decode_data(&malformed).is_err(), "header offset {offset}");
        cases += 1;
    }
    assert_eq!(cases, 20);

    for declared in [0_u32, (MAX_PAYLOAD_BYTES as u32) + 1, u32::MAX] {
        let mut malformed = bytes;
        malformed[16..20].copy_from_slice(&declared.to_le_bytes());
        assert!(decode_data(&malformed).is_err());
    }
    assert!(decode_data(&[]).is_err());
    let mut trailing = bytes.to_vec();
    trailing.push(0);
    assert!(decode_data(&trailing).is_err());
}

#[test]
fn every_fragment_boundary_reassembles_only_after_complete_record() {
    let mut bytes = [0; MAX_RECORD_BYTES];
    let size = encode_data(b"control\x1b[Ax", &mut bytes).unwrap();
    for split in 0..=size {
        let mut reassembled = Vec::new();
        reassembled.extend_from_slice(&bytes[..split]);
        if split != size {
            assert!(decode_data(&reassembled).is_err());
        }
        reassembled.extend_from_slice(&bytes[split..size]);
        assert_eq!(
            decode_data(&reassembled).unwrap().payload(),
            b"control\x1b[Ax"
        );
    }
}
