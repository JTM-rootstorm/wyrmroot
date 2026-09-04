//! First-hop JobV2 stream descriptors shared by native consoled and host tests.

use deepwyrm_syscall::{DW_HANDLE_TRANSFER_MOVE, DwHandle, DwHandleTransferV1};
use wyrmroot_loader::launch::CHILD_CHANNEL_TRANSFER_RIGHTS;

/// Init must retain TRANSFER to forward the endpoint through the loader.
/// The loader removes it at the final child boundary; DUPLICATE never leaves
/// consoled's local construction handles.
pub(crate) fn move_transfer(handle: DwHandle) -> DwHandleTransferV1 {
    DwHandleTransferV1 {
        handle,
        requested_rights: CHILD_CHANNEL_TRANSFER_RIGHTS,
        operation: DW_HANDLE_TRANSFER_MOVE,
        reserved0: 0,
        reserved: [0; 2],
    }
}
