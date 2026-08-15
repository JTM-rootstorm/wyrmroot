#![no_main]
#![no_std]
#![deny(unsafe_op_in_unsafe_fn)]

#[allow(dead_code)] // Invoked only by the target-only final transfer after EBS.
mod handoff_x86_64;
mod uefi_app;
#[allow(dead_code)] // Activated by the pending ownership-complete handoff builder.
mod uefi_page_table;

#[cfg(all(feature = "firmware", target_arch = "x86_64", target_os = "uefi"))]
#[allow(dead_code)] // The generated manifest intentionally carries facts consumed by peer seams.
mod deep_layout_policy {
    include!(env!("WYRMROOT_DEEP_LAYOUT_POLICY_RS"));
}

#[cfg(all(feature = "firmware", target_arch = "x86_64", target_os = "uefi"))]
fn generated_handoff_policy() -> uefi_app::GeneratedHandoffPolicy {
    uefi_app::GeneratedHandoffPolicy {
        link_base: deep_layout_policy::DEEPWYRM_LINK_BASE,
        base_page_size: deep_layout_policy::DEEPWYRM_BASE_PAGE_SIZE,
        elf_window_start: deep_layout_policy::DEEPWYRM_ELF_WINDOW_START,
        elf_window_end_exclusive: deep_layout_policy::DEEPWYRM_ELF_WINDOW_END_EXCLUSIVE,
        transition_stack_size: deep_layout_policy::DEEPWYRM_LOADER_TRANSITION_STACK_SIZE,
        transition_stack_alignment: deep_layout_policy::DEEPWYRM_LOADER_TRANSITION_STACK_ALIGNMENT,
        stack_pointer_mod_16: deep_layout_policy::DEEPWYRM_ENTRY_STATE_LOADER_STACK_RSP_MOD_16,
        boot_info_alignment: deep_layout_policy::DEEPWYRM_ENTRY_STATE_BOOT_INFO_ALIGNMENT,
        max_normalized_memory_map_entries:
            deep_layout_policy::DEEPWYRM_EARLY_INTAKE_MAX_NORMALIZED_MEMORY_MAP_ENTRIES,
        max_module_entries: deep_layout_policy::DEEPWYRM_EARLY_INTAKE_MAX_MODULE_ENTRIES,
        max_acpi_rsdp_intersecting_pages:
            deep_layout_policy::DEEPWYRM_EARLY_INTAKE_ACPI_RSDP_MAX_INTERSECTING_PAGES,
    }
}

#[uefi::entry]
fn main() -> uefi::Status {
    // The entry macro initializes the UEFI crate's image/system-table state.
    // Helper initialization remains before all firmware protocol use.
    if uefi::helpers::init().is_err() {
        return uefi::Status::ABORTED;
    }
    uefi::println!("wyrmroot-loader: UEFI adapter online");

    #[cfg(all(feature = "firmware", target_arch = "x86_64", target_os = "uefi"))]
    return uefi_app::run_handoff(generated_handoff_policy());

    #[allow(unreachable_code)]
    uefi::Status::ABORTED
}
