extern crate std;

use super::*;
use std::{string::String, vec, vec::Vec};
const R: Reservation = Reservation {
    connection_id: 7,
    generation: 9,
    transaction_id: 11,
};

#[test]
fn legacy_envelope_remains_exact() {
    let mut bytes = [0xaa; ENVELOPE_BYTES];
    assert_eq!(encode(R, &mut bytes), Ok(ENVELOPE_BYTES));
    assert_eq!(parse(&bytes), Ok(R));
    for offset in [0, 4, 6, 32] {
        let mut malformed = bytes;
        malformed[offset] ^= 1;
        assert!(parse(&malformed).is_err());
    }
    let mut complete = [0_u8; HEADER_BYTES];
    complete[..ENVELOPE_BYTES].copy_from_slice(&bytes);
    assert_eq!(parse_reservation_prefix(&complete), Ok(R));
    assert_eq!(
        parse_reservation_prefix(&complete[..ENVELOPE_BYTES - 1]),
        Err(Error::WrongSize)
    );
}

#[test]
fn legacy_launch_golden_vector_remains_minor_zero() {
    let mut bytes = [0_u8; 128];
    let size = encode_launch(R, "bin/hello", &["bin/hello"], &[], false, &mut bytes).unwrap();
    assert_eq!(size, 98);
    let mut expected = [0_u8; 98];
    expected[..4].copy_from_slice(b"WRLJ");
    expected[4..6].copy_from_slice(&1_u16.to_le_bytes());
    expected[6..8].copy_from_slice(&0_u16.to_le_bytes());
    expected[8..16].copy_from_slice(&7_u64.to_le_bytes());
    expected[16..24].copy_from_slice(&9_u64.to_le_bytes());
    expected[24..32].copy_from_slice(&11_u64.to_le_bytes());
    expected[40..44].copy_from_slice(&1_u32.to_le_bytes());
    expected[48..52].copy_from_slice(&98_u32.to_le_bytes());
    expected[56..58].copy_from_slice(&9_u16.to_le_bytes());
    expected[58..60].copy_from_slice(&1_u16.to_le_bytes());
    expected[64..68].copy_from_slice(&9_u32.to_le_bytes());
    expected[72..76].copy_from_slice(&0_u32.to_le_bytes());
    expected[76..78].copy_from_slice(&9_u16.to_le_bytes());
    expected[80..89].copy_from_slice(b"bin/hello");
    expected[89..98].copy_from_slice(b"bin/hello");
    assert_eq!(&bytes[..size], &expected);
    assert!(matches!(
        parse_message(&expected, 0),
        Ok(ParsedMessage {
            message: Message::Launch(_),
            ..
        })
    ));
    assert_eq!(
        parse_shell_v1_reservation_prefix(&expected),
        Err(Error::UnsupportedVersion)
    );
}

#[test]
fn shell_v1_request_has_the_frozen_golden_layout() {
    let request = ShellV1Request {
        console_generation: 13,
        status_generation: 15,
        requested_child_generation: 17,
    };
    let mut bytes = [0xaa; SHELL_V1_REQUEST_BYTES];
    assert_eq!(
        encode_shell_v1_request(R, request, &mut bytes),
        Ok(SHELL_V1_REQUEST_BYTES)
    );
    let mut expected = [0_u8; SHELL_V1_REQUEST_BYTES];
    expected[..4].copy_from_slice(b"WRLJ");
    expected[4..6].copy_from_slice(&1_u16.to_le_bytes());
    expected[6..8].copy_from_slice(&1_u16.to_le_bytes());
    expected[8..16].copy_from_slice(&7_u64.to_le_bytes());
    expected[16..24].copy_from_slice(&9_u64.to_le_bytes());
    expected[24..32].copy_from_slice(&11_u64.to_le_bytes());
    expected[40..44].copy_from_slice(&16_u32.to_le_bytes());
    expected[48..56].copy_from_slice(&13_u64.to_le_bytes());
    expected[56..64].copy_from_slice(&15_u64.to_le_bytes());
    expected[64..72].copy_from_slice(&17_u64.to_le_bytes());
    expected[72..74].copy_from_slice(&13_u16.to_le_bytes());
    expected[74..76].copy_from_slice(&2_u16.to_le_bytes());
    expected[76..78].copy_from_slice(&2_u16.to_le_bytes());
    for (index, role) in [1_u32, 2, 3, 4].into_iter().enumerate() {
        expected[80 + index * 8..84 + index * 8].copy_from_slice(&role.to_le_bytes());
    }
    expected[112..125].copy_from_slice(b"system/wyrmsh");
    assert_eq!(bytes, expected);
    assert_eq!(
        parse_shell_v1_request(&bytes, SHELL_V1_HANDLE_COUNT),
        Ok(ParsedShellV1Request {
            reservation: R,
            request,
        })
    );
    assert_eq!(
        parse_reservation_prefix(&bytes),
        Err(Error::UnsupportedVersion)
    );
    assert_eq!(parse_message(&bytes, 4), Err(Error::UnsupportedVersion));
}

#[test]
fn shell_v1_rejects_malformed_fixed_fields_and_handle_shapes() {
    let request = ShellV1Request {
        console_generation: 13,
        status_generation: 15,
        requested_child_generation: 17,
    };
    let mut bytes = [0_u8; SHELL_V1_REQUEST_BYTES];
    encode_shell_v1_request(R, request, &mut bytes).unwrap();
    assert_eq!(
        parse_shell_v1_request(&bytes, 3),
        Err(Error::WrongHandleCount)
    );
    assert_eq!(
        parse_shell_v1_request(&bytes[..127], 4),
        Err(Error::WrongSize)
    );
    for offset in [
        40, 44, 72, 74, 76, 78, 80, 84, 88, 92, 96, 100, 104, 108, 112, 125,
    ] {
        let mut malformed = bytes;
        malformed[offset] ^= 1;
        assert!(
            parse_shell_v1_request(&malformed, 4).is_err(),
            "offset {offset}"
        );
    }
    for offset in [48, 56, 64] {
        let mut malformed = bytes;
        malformed[offset..offset + 8].fill(0);
        assert_eq!(
            parse_shell_v1_request(&malformed, 4),
            Err(Error::ZeroIdentity)
        );
    }
    assert_eq!(
        encode_shell_v1_request(
            R,
            ShellV1Request {
                console_generation: 0,
                ..request
            },
            &mut bytes,
        ),
        Err(Error::ZeroIdentity)
    );
}

#[test]
fn shell_v1_replies_are_handle_free_minor_one_only() {
    let mut bytes = [0_u8; SHELL_V1_REPLY_BYTES];
    assert_eq!(encode_shell_v1_accepted(R, 19, &mut bytes), Ok(56));
    assert_eq!(
        parse_shell_v1_reply(&bytes, 0),
        Ok(ParsedShellV1Reply {
            reservation: R,
            reply: ShellV1Reply::LaunchAccepted { job_id: 19 },
        })
    );
    assert_eq!(parse_message(&bytes, 0), Err(Error::UnsupportedVersion));
    assert_eq!(
        parse_shell_v1_reply(&bytes, 1),
        Err(Error::WrongHandleCount)
    );
    assert_eq!(
        encode_shell_v1_error(R, ErrorCode::PolicyRejected, &mut bytes),
        Ok(56)
    );
    assert_eq!(
        parse_shell_v1_reply(&bytes, 0).unwrap().reply,
        ShellV1Reply::Error {
            code: ErrorCode::PolicyRejected,
        }
    );
    bytes[52] = 1;
    assert_eq!(parse_shell_v1_reply(&bytes, 0), Err(Error::NonzeroReserved));
}

#[test]
fn launch_round_trip_binds_arguments_environment_and_streams() {
    let argv = ["bin/hello", "kobold"];
    let environment = ["MODE=gate", "WYRMROOT_TEST=1"];
    let mut bytes = [0u8; 512];
    let size = encode_launch(R, "bin/hello", &argv, &environment, true, &mut bytes).unwrap();
    let parsed = parse_message(&bytes[..size], 3).unwrap();
    let Message::Launch(request) = parsed.message else {
        panic!("wrong message")
    };
    assert_eq!(request.path, "bin/hello");
    assert_eq!(request.arg(1), Some("kobold"));
    assert_eq!(request.environment(1), Some("WYRMROOT_TEST=1"));
    assert_eq!(request.stream_count, 3);
}

#[test]
fn maximum_launch_message_size_is_exact_for_encode_and_parse() {
    let path = "p".repeat(MAX_PATH_BYTES);
    let environment: Vec<String> = (0..MAX_ENVIRONMENT)
        .map(|index| std::format!("E{index:02}="))
        .collect();
    let environment: Vec<&str> = environment.iter().map(String::as_str).collect();
    let environment_bytes = environment.iter().map(|value| value.len()).sum::<usize>();
    let mut argv = vec![String::new(); MAX_ARGV];
    argv[0] = path.clone();
    argv[1] = "a".repeat(MAX_STRING_BYTES - path.len() - environment_bytes);
    let argv: Vec<&str> = argv.iter().map(String::as_str).collect();
    assert_eq!(
        argv.iter()
            .chain(environment.iter())
            .map(|value| value.len())
            .sum::<usize>(),
        MAX_STRING_BYTES
    );

    let mut bytes = vec![0; MAX_LAUNCH_MESSAGE_BYTES];
    assert_eq!(
        encode_launch(R, &path, &argv, &environment, true, &mut bytes),
        Ok(MAX_LAUNCH_MESSAGE_BYTES)
    );
    assert!(matches!(
        parse_message(&bytes, STREAM_COUNT),
        Ok(ParsedMessage {
            message: Message::Launch(_),
            ..
        })
    ));
    assert_eq!(
        encode_launch(
            R,
            &path,
            &argv,
            &environment,
            true,
            &mut bytes[..MAX_LAUNCH_MESSAGE_BYTES - 1],
        ),
        Err(Error::WrongSize)
    );
    bytes.push(0);
    assert_eq!(parse_message(&bytes, STREAM_COUNT), Err(Error::WrongSize));
}

#[test]
fn malformed_launch_fails_before_construction() {
    let mut bytes = [0u8; 256];
    assert_eq!(
        encode_launch(R, "../hello", &["../hello"], &[], false, &mut bytes),
        Err(Error::InvalidPath)
    );
    assert_eq!(
        encode_launch(
            R,
            "bin/hello",
            &["bin/hello"],
            &["bad=value"],
            false,
            &mut bytes
        ),
        Err(Error::InvalidEnvironment)
    );
    let size = encode_launch(R, "bin/hello", &["bin/hello"], &["A=1"], false, &mut bytes).unwrap();
    assert_eq!(
        parse_message(&bytes[..size], 1),
        Err(Error::WrongHandleCount)
    );
    bytes[68] = 1;
    assert_eq!(
        parse_message(&bytes[..size], 0),
        Err(Error::NonzeroReserved)
    );
}

#[test]
fn job_operations_remain_connection_scoped() {
    let mut bytes = [0u8; 56];
    let list_size = encode_list_jobs(R, &mut bytes).unwrap();
    assert_eq!(list_size, HEADER_BYTES);
    assert_eq!(
        parse_message(&bytes[..list_size], 0).unwrap(),
        ParsedMessage {
            reservation: R,
            message: Message::ListJobs,
        }
    );
    assert_eq!(
        encode_list_jobs(R, &mut bytes[..HEADER_BYTES - 1]),
        Err(Error::WrongSize)
    );

    let size = encode_job_message(R, MessageType::Query, 17, &mut bytes).unwrap();
    assert_eq!(
        parse_message(&bytes[..size], 0).unwrap().message,
        Message::Query { job_id: 17 }
    );
    assert_eq!(
        encode_job_message(R, MessageType::ListJobs, 17, &mut bytes),
        Err(Error::UnknownMessageType)
    );
}

#[test]
fn typed_responses_round_trip_without_posix_translation() {
    let mut bytes = [0u8; 88];
    let result = TerminationResult {
        classification: TerminationClassification::UnhandledException,
        application_code: 0,
        exception_class: 7,
        exception_detail: 9,
        exception_address: 0xfeed_beef,
        cleanup_result: 0b1_0100,
    };
    let size = encode_job_result(R, 17, result, &mut bytes).unwrap();
    assert_eq!(
        parse_message(&bytes[..size], 0).unwrap().message,
        Message::JobResult { job_id: 17, result }
    );
    let size = encode_error(R, ErrorCode::ForeignOrUnknownJob, &mut bytes).unwrap();
    assert_eq!(
        parse_message(&bytes[..size], 0).unwrap().message,
        Message::Error {
            code: ErrorCode::ForeignOrUnknownJob
        }
    );
}

#[test]
fn resource_policy_termination_has_the_exact_deepwyrm_wire_value() {
    let mut bytes = [0u8; 88];
    let result = TerminationResult {
        classification: TerminationClassification::ResourcePolicy,
        application_code: 0,
        exception_class: 0,
        exception_detail: 0,
        exception_address: 0,
        cleanup_result: 0,
    };
    let size = encode_job_result(R, 17, result, &mut bytes).unwrap();
    assert_eq!(&bytes[56..60], &4_u32.to_le_bytes());
    assert_eq!(
        parse_message(&bytes[..size], 0).unwrap().message,
        Message::JobResult { job_id: 17, result }
    );
}

#[test]
fn error_and_result_enums_reject_unknown_or_unowned_values() {
    let mut bytes = [0u8; 88];
    let size = encode_error(R, ErrorCode::Capacity, &mut bytes).unwrap();
    bytes[48..52].copy_from_slice(&0_u32.to_le_bytes());
    assert_eq!(
        parse_message(&bytes[..size], 0),
        Err(Error::InvalidErrorCode)
    );

    let result = TerminationResult {
        classification: TerminationClassification::NormalExit,
        application_code: 0,
        exception_class: 0,
        exception_detail: 0,
        exception_address: 0,
        cleanup_result: CLEANUP_RESULT_MASK + 1,
    };
    assert_eq!(
        encode_job_result(R, 17, result, &mut bytes),
        Err(Error::InvalidCleanupResult)
    );
    let valid = TerminationResult {
        cleanup_result: 0,
        ..result
    };
    let size = encode_job_result(R, 17, valid, &mut bytes).unwrap();
    bytes[56..60].copy_from_slice(&6_u32.to_le_bytes());
    assert_eq!(
        parse_message(&bytes[..size], 0),
        Err(Error::InvalidTerminationClassification)
    );
    bytes[56..60].copy_from_slice(&(TerminationClassification::NormalExit as u32).to_le_bytes());
    bytes[80..84].copy_from_slice(&(CLEANUP_RESULT_MASK + 1).to_le_bytes());
    assert_eq!(
        parse_message(&bytes[..size], 0),
        Err(Error::InvalidCleanupResult)
    );
}

#[test]
fn canonical_job_state_and_list_encoders_reject_bad_identities() {
    let mut bytes = [0u8; 320];
    let size = encode_job_state(R, 17, JobPhase::Terminating, &mut bytes).unwrap();
    assert_eq!(
        parse_message(&bytes[..size], 0).unwrap().message,
        Message::JobState {
            job_id: 17,
            phase: JobPhase::Terminating,
        }
    );
    let size = encode_job_list(R, &[17, 18], &mut bytes).unwrap();
    let Message::JobList(ids) = parse_message(&bytes[..size], 0).unwrap().message else {
        panic!("wrong message");
    };
    assert_eq!([ids.get(0), ids.get(1)], [Some(17), Some(18)]);
    assert_eq!(
        encode_job_list(R, &[0], &mut bytes),
        Err(Error::ZeroIdentity)
    );
}

#[test]
fn launch_image_carries_streams_image_and_namespace_handles() {
    let mut bytes = [0_u8; 512];
    let path = "boot/EFI/WYRMROOT/HELLO.ELF";
    let size = encode_launch_image(R, path, &[path, "x"], &[], &mut bytes).unwrap();
    assert_eq!(
        u32::from_le_bytes(bytes[52..56].try_into().unwrap()),
        LAUNCH_IMAGE_HANDLE_COUNT as u32
    );
    let parsed = parse_message(&bytes[..size], LAUNCH_IMAGE_HANDLE_COUNT).unwrap();
    let Message::LaunchImage(request) = parsed.message else {
        panic!("expected LAUNCH_IMAGE")
    };
    assert_eq!(request.path, path);
    assert_eq!(request.stream_count, STREAM_COUNT);
    assert_eq!((request.argc(), request.arg(1)), (2, Some("x")));
    // The handle count is exact, and it is never a plain LAUNCH.
    for handles in [0, 3, 4, 6] {
        assert_eq!(
            parse_message(&bytes[..size], handles),
            Err(Error::WrongHandleCount)
        );
    }
    let mut as_launch = bytes;
    as_launch[40..44].copy_from_slice(&(MessageType::Launch as u32).to_le_bytes());
    assert_eq!(
        parse_message(&as_launch[..size], LAUNCH_IMAGE_HANDLE_COUNT),
        Err(Error::InvalidStreamRoles)
    );
    // A plain three-stream LAUNCH relabelled as an image launch lacks the image.
    let size = encode_launch(R, "bin/hello", &["bin/hello"], &[], true, &mut bytes).unwrap();
    let mut relabelled = bytes;
    relabelled[40..44].copy_from_slice(&(MessageType::LaunchImage as u32).to_le_bytes());
    assert_eq!(
        parse_message(&relabelled[..size], 3),
        Err(Error::InvalidStreamRoles)
    );
    // Absolute display paths are carried without their leading slash.
    assert_eq!(
        encode_launch_image(R, "/boot/x", &["/boot/x"], &[], &mut bytes),
        Err(Error::InvalidPath)
    );
}

#[test]
fn argv0_is_independent_of_the_path() {
    // POSIX programs choose their own argv[0] (root
    // `TOOLCHAIN_POSIX_LAYER_DESIGN.md` W3); the path alone selects the image.
    let mut bytes = [0_u8; 512];
    let size = encode_launch(R, "bin/hello", &["hello", "x"], &[], true, &mut bytes).unwrap();
    let Message::Launch(request) = parse_message(&bytes[..size], STREAM_COUNT).unwrap().message
    else {
        panic!("expected LAUNCH")
    };
    assert_eq!((request.path, request.arg(0)), ("bin/hello", Some("hello")));

    let path = "boot/EFI/WYRMROOT/HELLO.ELF";
    let size =
        encode_launch_image(R, path, &["/boot/EFI/WYRMROOT/HELLO.ELF"], &[], &mut bytes).unwrap();
    let Message::LaunchImage(request) = parse_message(&bytes[..size], LAUNCH_IMAGE_HANDLE_COUNT)
        .unwrap()
        .message
    else {
        panic!("expected LAUNCH_IMAGE")
    };
    assert_eq!(request.arg(0), Some("/boot/EFI/WYRMROOT/HELLO.ELF"));
    // An empty argv[0] is still an argument; argc stays at least one.
    assert!(encode_launch(R, "bin/hello", &[""], &[], false, &mut bytes).is_ok());
    assert_eq!(
        encode_launch(R, "bin/hello", &[], &[], false, &mut bytes),
        Err(Error::InvalidArgumentCount)
    );
}
