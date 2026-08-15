#![no_main]
#![no_std]
#![deny(unsafe_op_in_unsafe_fn)]

#[allow(dead_code)] // Invoked only by the target-only final transfer after EBS.
mod handoff_x86_64;
mod uefi_app;
#[allow(dead_code)] // Activated by the pending ownership-complete handoff builder.
mod uefi_page_table;

#[uefi::entry]
fn main() -> uefi::Status {
    // The entry macro initializes the UEFI crate's image/system-table state.
    // Helper initialization remains before all firmware protocol use.
    if uefi::helpers::init().is_err() {
        return uefi::Status::ABORTED;
    }
    uefi::println!("wyrmroot-loader: UEFI adapter online");

    match uefi_app::prepare_pre_exit() {
        Ok(prepared) => {
            // Do not take the irreversible ExitBootServices boundary until the
            // transition and canonical BootInfo owners have added their page
            // allocations to this same pre-exit state.
            prepared.release_before_exit();
            uefi::Status::ABORTED
        }
        Err(_) => uefi::Status::ABORTED,
    }
}
