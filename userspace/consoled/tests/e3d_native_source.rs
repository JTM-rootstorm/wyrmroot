use wyrmroot_console_proto as _;
use wyrmroot_consoled as _;

const NATIVE: &str = include_str!("../src/main.rs");
const MODEL: &str = include_str!("../src/lib.rs");
const TRANSFER: &str = include_str!("../src/stream_transfer.rs");

#[test]
fn shell_policy_uses_exact_four_handle_move_and_correlations() {
    for required in [
        "ChildPolicy::Wyrmsh => encode_shell_v1_request(",
        "console_generation: model_launch.console_generation()",
        "status_generation,",
        "requested_child_generation: model_launch.child_generation()",
        "move_transfer(child[0])",
        "move_transfer(child[1])",
        "move_transfer(child[2])",
        "move_transfer(status_child)",
        "if policy == ChildPolicy::Wyrmsh { 4 } else { 3 }",
    ] {
        assert!(
            NATIVE.contains(required),
            "missing native contract: {required}"
        );
    }
    assert!(TRANSFER.contains("requested_rights: CHILD_CHANNEL_TRANSFER_RIGHTS"));
    assert!(TRANSFER.contains("operation: DW_HANDLE_TRANSFER_MOVE"));
}

#[test]
fn historical_policy_remains_an_explicit_three_stream_launch() {
    for required in [
        "ChildPolicy::ConsoleEcho => encode_launch(",
        "policy.path(),\n            &[policy.path()],\n            &[],\n            true",
        "Self::ConsoleEcho => \"bin/console-echo\"",
        "Self::Wyrmsh => wyrmroot_console_proto::SHELL_PATH",
    ] {
        assert!(
            NATIVE.contains(required) || MODEL.contains(required),
            "missing historical contract: {required}"
        );
    }
}

#[test]
fn retained_status_endpoint_is_closed_before_streams_and_replacement() {
    let close_function = NATIVE
        .split_once("fn close_child_streams")
        .expect("close function")
        .1;
    let status = close_function.find("close_child_status(child)").unwrap();
    let streams = close_function
        .find("child.stdin.endpoint().handle()")
        .unwrap();
    assert!(status < streams);
    assert!(NATIVE.contains("ChildFault::Status => model.status_peer_closed"));
    assert!(NATIVE.contains("status: status_session.map(|session| StatusChannel"));
}

#[test]
fn status_transport_has_bounded_wait_and_no_handle_acceptance() {
    for required in [
        "let mut handles = [DwReceivedHandleInfoV1::default(); 1]",
        "if counts.handles != 0",
        "StatusSession",
        "STATUS_SEND_TIMEOUT_NS",
        "DW_STATUS_WOULD_BLOCK",
        "ErrorCode::Unavailable",
        "parse_header(message, 0)",
        "Message::Query(header)",
    ] {
        assert!(
            NATIVE.contains(required),
            "missing WRCN transport rule: {required}"
        );
    }
}
