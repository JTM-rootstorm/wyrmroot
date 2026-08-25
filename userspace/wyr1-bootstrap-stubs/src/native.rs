use deepwyrm_syscall::{DwHandle, DwObjectType, DwReceivedHandleInfoV1, DwRights};
use wyrmroot_runtime::{CapabilityInfo, NativeError, ReceiveCounts};

pub struct NativeSystem;
impl wyrmroot_wyr1_bootstrap_stubs::StubSystem for NativeSystem {
    fn query_capability_info(
        &mut self,
        h: DwHandle,
    ) -> Result<CapabilityInfo<DwObjectType, DwRights>, NativeError> {
        wyrmroot_runtime::query_capability_info(h)
    }
    fn receive_channel(
        &mut self,
        h: DwHandle,
        b: &mut [u8],
        r: &mut [DwReceivedHandleInfoV1],
    ) -> Result<ReceiveCounts, NativeError> {
        wyrmroot_runtime::receive_channel(h, b, r)
    }
    fn send_channel(&mut self, h: DwHandle, b: &[u8]) -> Result<(), NativeError> {
        wyrmroot_runtime::send_channel(h, b, &[])
    }
    fn close_handle(&mut self, h: DwHandle) -> Result<(), NativeError> {
        wyrmroot_runtime::close_handle(h)
    }
}
