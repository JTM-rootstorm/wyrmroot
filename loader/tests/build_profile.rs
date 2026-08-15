use wyrmroot_efi_loader::{LoaderExecutionEnvironment, WYR0_A_UEFI_LOADER_PROFILE};

#[test]
fn phase_a_profile_keeps_the_loader_outside_host_and_guest_runtime() {
    let profile = core::hint::black_box(WYR0_A_UEFI_LOADER_PROFILE);

    assert_eq!(
        profile.execution_environment,
        LoaderExecutionEnvironment::X86_64Uefi
    );
    assert!(!profile.permits_host_os_services);
    assert!(!profile.permits_wyrmroot_runtime);
    assert!(profile.permits_host_validation);
}
