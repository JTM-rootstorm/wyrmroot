// SPDX-License-Identifier: GPL-3.0-or-later

use wyrmroot_launch_proto::{
    CLEANUP_RESULT_MASK, Message, Reservation, SHELL_V1_HANDLE_COUNT, SHELL_V1_REPLY_BYTES,
    SHELL_V1_REQUEST_BYTES, ShellV1Request, TerminationClassification, TerminationResult,
    encode_job_list, encode_job_result, encode_shell_v1_accepted, encode_shell_v1_request,
    parse_message, parse_shell_v1_reply, parse_shell_v1_request,
};

const CURRENT: Reservation = Reservation {
    connection_id: 0x101,
    generation: 0x102,
    transaction_id: 0x103,
};

fn shell_request(reservation: Reservation) -> [u8; SHELL_V1_REQUEST_BYTES] {
    let mut bytes = [0; SHELL_V1_REQUEST_BYTES];
    encode_shell_v1_request(
        reservation,
        ShellV1Request {
            console_generation: 0x201,
            status_generation: 0x202,
            requested_child_generation: 0x203,
        },
        &mut bytes,
    )
    .unwrap();
    bytes
}

#[test]
fn shell_v1_exhausts_truncations_fixed_fields_and_handle_counts() {
    let bytes = shell_request(CURRENT);
    let mut cases = 0;
    for cut in 0..SHELL_V1_REQUEST_BYTES {
        assert!(parse_shell_v1_request(&bytes[..cut], SHELL_V1_HANDLE_COUNT).is_err());
        cases += 1;
    }
    assert_eq!(cases, 128);

    let fixed = (0..8)
        .chain(32..48)
        .chain(72..80)
        .chain(80..112)
        .chain(112..SHELL_V1_REQUEST_BYTES);
    let mut mutations = 0;
    for offset in fixed {
        let mut malformed = bytes;
        malformed[offset] ^= 1;
        assert!(
            parse_shell_v1_request(&malformed, SHELL_V1_HANDLE_COUNT).is_err(),
            "accepted fixed-field mutation at {offset}"
        );
        mutations += 1;
    }
    assert_eq!(mutations, 80);

    let mut handle_shapes = 0;
    for count in 0..=SHELL_V1_HANDLE_COUNT + 1 {
        if count == SHELL_V1_HANDLE_COUNT {
            continue;
        }
        assert!(parse_shell_v1_request(&bytes, count).is_err());
        handle_shapes += 1;
    }
    assert_eq!(handle_shapes, 5);
}

#[test]
fn shell_v1_consistent_wrong_tuple_is_preserved_for_stateful_rejection() {
    let old = Reservation {
        connection_id: 0x301,
        generation: 0x302,
        transaction_id: 0x303,
    };
    let parsed = parse_shell_v1_request(&shell_request(old), SHELL_V1_HANDLE_COUNT).unwrap();
    assert_eq!(parsed.reservation, old);
    assert_ne!(parsed.reservation, CURRENT);

    let mut reply = [0; SHELL_V1_REPLY_BYTES];
    encode_shell_v1_accepted(old, 0x401, &mut reply).unwrap();
    for cut in 0..SHELL_V1_REPLY_BYTES {
        assert!(parse_shell_v1_reply(&reply[..cut], 0).is_err());
    }
    assert_eq!(parse_shell_v1_reply(&reply, 0).unwrap().reservation, old);
    assert!(parse_shell_v1_reply(&reply, 1).is_err());
}

#[test]
fn job_list_and_result_corpus_rejects_shape_but_never_guesses_values() {
    let mut list = [0; 312];
    let size = encode_job_list(CURRENT, &[0x501, 0x502, 0x503], &mut list).unwrap();
    for cut in 0..size {
        assert!(parse_message(&list[..cut], 0).is_err());
    }

    for (offset, replacement) in [(48, 4_u32), (52, 1_u32)] {
        let mut malformed = list[..size].to_vec();
        malformed[offset..offset + 4].copy_from_slice(&replacement.to_le_bytes());
        assert!(parse_message(&malformed, 0).is_err());
    }
    for offset in [56, 64, 72] {
        let mut malformed = list[..size].to_vec();
        malformed[offset..offset + 8].fill(0);
        assert!(parse_message(&malformed, 0).is_err());
    }

    let mut reordered = [0; 312];
    let reordered_size = encode_job_list(CURRENT, &[0x503, 0x501, 0x502], &mut reordered).unwrap();
    let Message::JobList(ids) = parse_message(&reordered[..reordered_size], 0)
        .unwrap()
        .message
    else {
        panic!("expected job list")
    };
    assert_eq!(
        [ids.get(0), ids.get(1), ids.get(2)],
        [Some(0x503), Some(0x501), Some(0x502)]
    );

    let result = TerminationResult {
        classification: TerminationClassification::UnhandledException,
        application_code: 0x601,
        exception_class: 0x602,
        exception_detail: 0x603,
        exception_address: 0x604,
        cleanup_result: CLEANUP_RESULT_MASK,
    };
    let mut bytes = [0; 88];
    encode_job_result(CURRENT, 0x605, result, &mut bytes).unwrap();
    for cut in 0..bytes.len() {
        assert!(parse_message(&bytes[..cut], 0).is_err());
    }
    let Message::JobResult {
        job_id,
        result: parsed,
    } = parse_message(&bytes, 0).unwrap().message
    else {
        panic!("expected result")
    };
    assert_eq!((job_id, parsed), (0x605, result));

    for (offset, width) in [(56, 4), (80, 4)] {
        let mut malformed = bytes;
        malformed[offset..offset + width].fill(0xff);
        assert!(parse_message(&malformed, 0).is_err());
    }
    let mut wrong_job = bytes;
    wrong_job[48..56].fill(0x5a);
    let Message::JobResult {
        job_id: observed, ..
    } = parse_message(&wrong_job, 0).unwrap().message
    else {
        panic!("expected wrong-job result")
    };
    assert_ne!(observed, 0x605);
    for (offset, width) in [(60, 4), (64, 4), (68, 4), (72, 8)] {
        let mut changed = bytes;
        changed[offset..offset + width].fill(0x5a);
        let Message::JobResult {
            result: observed, ..
        } = parse_message(&changed, 0).unwrap().message
        else {
            panic!("expected changed result")
        };
        assert_ne!(observed, result);
    }
}
