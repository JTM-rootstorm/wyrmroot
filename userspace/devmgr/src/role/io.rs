//! Channel, wait and handle helpers.

use super::*;

pub(crate) fn wait_readable<P: DevmgrPlatform>(
    platform: &mut P,
    handle: DwHandle,
    deadline: deepwyrm_syscall::DwDeadline,
    stage: u32,
) -> Result<(), u32> {
    let observed = platform
        .wait_many(core::slice::from_ref(&wait_item(handle)), deadline)
        .map_err(|_| failure(stage))?;
    if observed.index != 0 || observed.observed.0 & DW_SIGNAL_READABLE.0 == 0 {
        return Err(failure(stage));
    }
    Ok(())
}

pub(crate) fn send_publication_acknowledgement<P: DevmgrPlatform>(
    platform: &mut P,
    bootstrap: DwHandle,
    resident: &crate::ResidentController,
) -> Result<(), u32> {
    let bytes = resident
        .publication_acknowledgement()
        .map_err(|error| match error {
            crate::PublicationAcknowledgementError::Lifecycle(_) => failure(35),
            crate::PublicationAcknowledgementError::Encoding(_) => failure(36),
        })?;
    send_bootstrap_channel(platform, bootstrap, &bytes, &[], 37)
}

pub(crate) fn send_resident_status<P: DevmgrPlatform>(
    platform: &mut P,
    bootstrap: DwHandle,
    resident: &crate::ResidentController,
    status: StatusCode,
) -> Result<(), u32> {
    let message = resident.report(status).map_err(|_| failure(35))?;
    let mut bytes = [0u8; STATUS_BYTES];
    encode_controller(message, &mut bytes).map_err(|_| failure(36))?;
    send_bootstrap_channel(platform, bootstrap, &bytes, &[], 37)
}

pub(crate) fn send_bootstrap_channel<P: DevmgrPlatform>(
    platform: &mut P,
    bootstrap: DwHandle,
    bytes: &[u8],
    transfers: &[DwHandleTransferV1],
    stage: u32,
) -> Result<(), u32> {
    platform
        .send_channel(bootstrap, bytes, transfers)
        .map_err(|_| failure(stage))
}

pub(crate) fn validate_fresh<P: DevmgrPlatform>(
    platform: &mut P,
    handle: DwHandle,
    object_type: DwObjectType,
    rights: DwRights,
) -> Result<(), ()> {
    let actual: CapabilityInfo<DwObjectType, DwRights> =
        platform.query_capability_info(handle).map_err(|_| ())?;
    if actual.object_type != object_type || actual.rights != rights {
        return Err(());
    }
    Ok(())
}

pub(crate) fn wait_item(handle: DwHandle) -> DwWaitItemV1 {
    DwWaitItemV1 {
        handle,
        signals: deepwyrm_syscall::DwSignals(DW_SIGNAL_READABLE.0 | DW_SIGNAL_PEER_CLOSED.0),
    }
}

pub(crate) fn close_received<P: DevmgrPlatform>(
    platform: &mut P,
    handles: &[DwReceivedHandleInfoV1],
    count: usize,
) {
    for info in handles.iter().take(count.min(handles.len())) {
        let _ = platform.close_handle(info.handle);
    }
}

pub(crate) fn close_optional<P: DevmgrPlatform>(platform: &mut P, handle: Option<DwHandle>) {
    if let Some(handle) = handle {
        let _ = platform.close_handle(handle);
    }
}

pub(crate) const fn failure(stage: u32) -> u32 {
    FAILURE_BASE | stage
}
