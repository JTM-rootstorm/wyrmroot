// SPDX-License-Identifier: GPL-3.0-or-later

use wyrmroot_console_proto::{
    ERROR_BYTES, ErrorCode, FLAG_CHILD_PRESENT, FLAG_SERIAL_PRESENT, HEADER_BYTES, Header,
    LastFailure, Message, SNAPSHOT_BYTES, Snapshot, State, decode, encode_error, encode_query,
    encode_snapshot,
};

fn snapshot() -> Snapshot {
    Snapshot {
        state: State::Active,
        flags: FLAG_SERIAL_PRESENT | FLAG_CHILD_PRESENT,
        serial_registry_generation: 11,
        publication_generation: 12,
        device_bundle: 13,
        driver_attempt: 14,
        raw_stream_generation: 15,
        child_generation: 16,
        outer_job: 17,
        outer_launch_transaction: 18,
        live_peer_mask: 7,
        input_queue_bytes: 19,
        stdout_queue_bytes: 20,
        stderr_queue_bytes: 21,
        child_failures: 1,
        serial_failures: 1,
        last_failure: LastFailure::None,
    }
}

fn frame(header: Header) -> [u8; SNAPSHOT_BYTES] {
    let mut bytes = [0; SNAPSHOT_BYTES];
    encode_snapshot(header, snapshot(), &mut bytes).unwrap();
    bytes
}

#[test]
fn status_snapshot_exhausts_truncations_reserved_and_relation_mutations() {
    let header = Header {
        transaction_id: 21,
        console_generation: 22,
        status_generation: 23,
    };
    let bytes = frame(header);
    for cut in 0..SNAPSHOT_BYTES {
        assert!(decode(&bytes[..cut], 0).is_err());
    }
    assert!(decode(&bytes, 1).is_err());

    let fixed = (0..24).chain(148..SNAPSHOT_BYTES);
    let mut fixed_cases = 0;
    for offset in fixed {
        let mut malformed = bytes;
        malformed[offset] ^= 1;
        assert!(decode(&malformed, 0).is_err(), "offset {offset}");
        fixed_cases += 1;
    }
    assert_eq!(fixed_cases, 36);

    for range in [24..32, 32..40, 40..48] {
        let mut malformed = bytes;
        malformed[range].fill(0);
        assert!(decode(&malformed, 0).is_err());
    }
    for offset in [48, 52, 120, 124, 128, 132, 136, 140, 144] {
        let mut malformed = bytes;
        malformed[offset..offset + 4].fill(0xff);
        assert!(decode(&malformed, 0).is_err(), "relation offset {offset}");
    }

    for (flag, start, end) in [(FLAG_SERIAL_PRESENT, 56, 96), (FLAG_CHILD_PRESENT, 96, 120)] {
        let mut malformed = bytes;
        let flags = u32::from_le_bytes(malformed[52..56].try_into().unwrap()) & !flag;
        malformed[52..56].copy_from_slice(&flags.to_le_bytes());
        assert!(malformed[start..end].iter().any(|byte| *byte != 0));
        assert!(decode(&malformed, 0).is_err());
    }
}

#[test]
fn internally_consistent_old_status_tuple_remains_distinct() {
    let old = Header {
        transaction_id: 31,
        console_generation: 32,
        status_generation: 33,
    };
    let current = Header {
        transaction_id: 41,
        console_generation: 42,
        status_generation: 43,
    };
    let Message::Snapshot(observed_old, _) = decode(&frame(old), 0).unwrap() else {
        panic!("expected snapshot")
    };
    let Message::Snapshot(observed_current, _) = decode(&frame(current), 0).unwrap() else {
        panic!("expected snapshot")
    };
    assert_eq!(observed_old, old);
    assert_eq!(observed_current, current);
    assert_ne!(observed_old, observed_current);
}

#[test]
fn query_and_error_exhaust_truncations_handles_and_reserved_bytes() {
    let header = Header {
        transaction_id: 51,
        console_generation: 52,
        status_generation: 53,
    };
    let mut query = [0; HEADER_BYTES];
    encode_query(header, &mut query).unwrap();
    for cut in 0..HEADER_BYTES {
        assert!(decode(&query[..cut], 0).is_err());
    }
    assert!(decode(&query, 1).is_err());

    let mut error = [0; ERROR_BYTES];
    encode_error(header, ErrorCode::StaleGeneration, &mut error).unwrap();
    for cut in 0..ERROR_BYTES {
        assert!(decode(&error[..cut], 0).is_err());
    }
    for offset in 52..ERROR_BYTES {
        let mut malformed = error;
        malformed[offset] ^= 1;
        assert!(
            decode(&malformed, 0).is_err(),
            "error reserved offset {offset}"
        );
    }
}
