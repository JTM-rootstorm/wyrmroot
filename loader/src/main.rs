#![no_main]
#![no_std]
#![deny(unsafe_op_in_unsafe_fn)]

mod uefi_app;

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
