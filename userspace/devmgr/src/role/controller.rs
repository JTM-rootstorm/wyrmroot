//! Receiving and validating controller publication messages.

use super::*;

pub(crate) fn receive_controller<P: DevmgrPlatform>(
    platform: &mut P,
    bootstrap: DwHandle,
    resident: &mut crate::ResidentController,
) -> Result<ControllerInput, u32> {
    let mut bytes = [0u8; wyrmroot_device_proto::controller_v1_1::RECORD_BYTES];
    let mut handles = [DwReceivedHandleInfoV1::default(); 1];
    let counts = platform
        .receive_channel(bootstrap, &mut bytes, &mut handles)
        .map_err(|_| failure(27))?;
    if counts.bytes > bytes.len() || counts.handles > handles.len() {
        close_received(platform, &handles, counts.handles);
        return Err(failure(28));
    }
    let publication = match wyrmroot_device_proto::controller_v1_1::parse(&bytes[..counts.bytes]) {
        Ok(publication) => publication,
        Err(_) => {
            close_received(platform, &handles, counts.handles);
            return Err(failure(29));
        }
    };
    let message = publication.controller;
    if counts.handles as u32 != message.handle_count() {
        close_received(platform, &handles, counts.handles);
        return Err(failure(30));
    }
    let replacement = match message {
        ControllerMessage::InstallPublication { .. } => {
            if counts.handles != 0 {
                close_received(platform, &handles, counts.handles);
                return Err(failure(31));
            }
            None
        }
        ControllerMessage::RebindPublication { .. } => {
            if counts.handles != 1
                || validate_fresh(
                    platform,
                    handles[0].handle,
                    DW_OBJECT_TYPE_CHANNEL,
                    CHILD_CHANNEL_RIGHTS,
                )
                .is_err()
            {
                close_received(platform, &handles, counts.handles);
                return Err(failure(32));
            }
            Some(handles[0].handle)
        }
        ControllerMessage::Status { .. } => {
            close_received(platform, &handles, counts.handles);
            return Err(failure(33));
        }
    };
    let accepted = resident.accept_publication(publication, counts.handles as u32);
    let action = match accepted {
        Ok(action) => action,
        Err(_) => {
            if counts.handles == 1
                && let Some(replacement) = replacement
            {
                let _ = platform.close_handle(replacement);
            }
            return Err(failure(34));
        }
    };
    Ok((replacement, action))
}

pub(crate) fn published_driver(
    resident: &crate::ResidentController,
    request: wyrmroot_device_proto::DriverLaunchRequest,
) -> Result<PublishedDriver, u32> {
    if resident.active_driver_request() != Some(request) || !resident.driver_ready() {
        return Err(failure(242));
    }
    Ok(PublishedDriver {
        publication_generation: resident
            .publication_service_generation()
            .ok_or(failure(243))?,
        control: ControlIdentityV1_1 {
            role_id: request.role_id,
            bundle_generation: resident.bundle_generation().ok_or(failure(244))?,
            attempt_generation: request.attempt_generation,
            endpoint: request.endpoint,
            transaction_id: request.transaction_id,
        },
    })
}
