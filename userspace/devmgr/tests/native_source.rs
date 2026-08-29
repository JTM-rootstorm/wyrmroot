use {wyrmroot_device_proto as _, wyrmroot_devmgr as _};

const NATIVE: &str = include_str!("../src/main.rs");

#[test]
fn native_path_validates_manifest_before_operational_ready_and_blocks_afterward() {
    let run = &NATIVE[NATIVE.find("fn run(").unwrap()..];
    let parse = run.find("parse_device_coordinator_init").unwrap();
    let map = run.find("map_bootfs_read_only").unwrap();
    let prepare = run.find("prepare_operational").unwrap();
    let unmap = run.find("unmap_bootfs(mapping)").unwrap();
    let ready = run.find("encode_ready_for_profile").unwrap();
    let wait = run.find("wait_many(&waits, DW_DEADLINE_INFINITE)").unwrap();
    assert!(parse < map);
    assert!(map < prepare);
    assert!(prepare < unmap);
    assert!(unmap < ready);
    assert!(ready < wait);
}

#[test]
fn native_path_has_only_the_hardware_free_c1_startup_surface() {
    assert!(NATIVE.contains("LaunchProfile::DeviceCoordinator"));
    assert!(NATIVE.contains("DEVICE_MANIFEST_RIGHTS"));
    assert!(NATIVE.contains("DW_OBJECT_TYPE_MEMORY_OBJECT"));
    assert!(NATIVE.contains("send_channel(bootstrap, &ready[..ready_len], &[])"));
    assert!(!NATIVE.contains("DW_OBJECT_TYPE_DEVICE_RESOURCE"));
    assert!(!NATIVE.contains("DW_OBJECT_TYPE_INTERRUPT"));
    assert!(!NATIVE.contains("pio_"));
}

#[test]
fn registry_peer_close_preserves_the_devmgr_supervisor_generation() {
    let replacement = NATIVE
        .find("Registry replacement closes only the old publication binding")
        .unwrap();
    let tail = &NATIVE[replacement..];
    let close_publication = tail.find("close_handle(publication)").unwrap();
    let wait_controller = tail.find("wait_many(&controller_wait").unwrap();
    let close_bootstrap = tail.find("close_handle(bootstrap)").unwrap();
    assert!(close_publication < wait_controller);
    assert!(wait_controller < close_bootstrap);
}
