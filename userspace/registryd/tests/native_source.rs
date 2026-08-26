// SPDX-License-Identifier: GPL-3.0-or-later

use {wyrmroot_registry_proto as _, wyrmroot_registryd as _};

const NATIVE: &str = include_str!("../src/main.rs");

#[test]
fn native_registry_is_resident_and_uses_only_channel_routing_primitives() {
    assert!(NATIVE.contains("LaunchProfile::BootstrapRegistry"));
    assert!(NATIVE.contains("loop {"));
    assert!(NATIVE.contains("wait_many"));
    assert!(NATIVE.contains("Message::InstallPublication"));
    assert!(NATIVE.contains("Message::InstallClient"));
    assert!(NATIVE.contains("Message::LookupConnect"));
    assert!(NATIVE.contains("MessageType::ConnectOffer"));
    assert!(NATIVE.contains("DW_HANDLE_TRANSFER_MOVE"));
    for forbidden in [
        "load_process",
        "task_group",
        "bootfs",
        "filesystem",
        "device",
    ] {
        assert!(
            !NATIVE.contains(forbidden),
            "registryd contains {forbidden}"
        );
    }
}
