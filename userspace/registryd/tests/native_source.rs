// SPDX-License-Identifier: GPL-3.0-or-later

use {
    deepwyrm_syscall as _, wyrmroot_loader as _, wyrmroot_registry_proto as _,
    wyrmroot_registryd as _, wyrmroot_runtime as _,
};

const NATIVE: &str = concat!(include_str!("../src/main.rs"), include_str!("../src/role.rs"));
const SERVICE: &str = include_str!("../src/service.rs");

/// Source text because `main.rs` plus `role.rs` is the guest binary's whole
/// native role: registryd's transport has no host seam of its own yet, only
/// the platform family's (S2U step 3 moved bootstrap and the transport into
/// the library, in `main.rs`'s old text order).
#[test]
fn native_registry_is_resident_and_uses_only_channel_routing_primitives() {
    let compact: String = NATIVE.split_whitespace().collect();
    assert!(NATIVE.contains("LaunchProfile::BootstrapRegistry"));
    assert!(NATIVE.contains("loop {"));
    assert!(NATIVE.contains("wait_many"));
    assert!(NATIVE.contains("fn probe("));
    assert!(NATIVE.contains("DwDeadline(0)"));
    assert!(NATIVE.contains("DW_SIGNAL_PEER_CLOSED"));
    assert!(NATIVE.contains("DW_STATUS_TIMED_OUT"));
    assert!(compact.contains("close_handle(DwHandle(handle)).map_err"));
    assert!(NATIVE.contains("RegistryService::new"));
    assert!(NATIVE.contains("service.step"));
    assert!(SERVICE.contains("Message::InstallPublication"));
    assert!(SERVICE.contains("Message::InstallClient"));
    assert!(SERVICE.contains("Message::LookupConnect"));
    assert!(SERVICE.contains("MessageType::ConnectOffer"));
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
