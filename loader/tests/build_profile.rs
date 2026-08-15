use core::mem::size_of;

use wyrmroot_efi_loader::{
    LoaderExecutionEnvironment, WYR0_A_UEFI_LOADER_PROFILE,
    abi::{DW_ABI_VERSION, DW_BOOT_INFO_V1_SIZE, DwBootInfoV1},
};

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

#[test]
fn phase_a_consumes_the_generated_deepwyrm_boot_contract() {
    assert_eq!(DW_ABI_VERSION, 0);
    assert_eq!(size_of::<DwBootInfoV1>(), DW_BOOT_INFO_V1_SIZE as usize);
}
