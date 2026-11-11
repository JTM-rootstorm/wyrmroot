//! vfsd as a service role: init's stage, the boot mounts, publication of
//! `system.vfs`, and the serve loop.

use deepwyrm_syscall::{
    DW_DEADLINE_INFINITE, DW_HANDLE_INVALID, DW_SIGNAL_PEER_CLOSED, DW_SIGNAL_READABLE, DwHandle,
    DwSignals, DwWaitItemV1,
};
use wyrmroot_runtime::{ClockPlatform, WYR0_I_SUPERVISION_POLICY};
use wyrmroot_service::{ServicePlatform, accept_offer, publish, receive_stage, startup};
use wyrmroot_service_proto::CHANNEL_READ_ONLY;
use wyrmroot_service_proto::roles::{SLOT_MOUNT, SYSTEM_VFS, VFSD_ROLE_ID};

use crate::server::{Event, Vfs};

pub const FAILURE_BASE: u32 = 0xF5D0_0000;
const READABLE_OR_CLOSED: DwSignals = DwSignals(DW_SIGNAL_READABLE.0 | DW_SIGNAL_PEER_CLOSED.0);

/// Runs vfsd; returns its exit code (0 when init asks it to retire).
pub fn vfsd_main<P: ServicePlatform + ClockPlatform>(platform: &mut P, bootstrap: DwHandle) -> u32 {
    let mut vfs = Vfs::new(DW_HANDLE_INVALID);
    let result = run(platform, bootstrap, &mut vfs);
    vfs.shutdown(platform);
    match result {
        Ok(()) => 0,
        Err(step) => FAILURE_BASE | step,
    }
}

fn run<P: ServicePlatform>(
    platform: &mut P,
    bootstrap: DwHandle,
    vfs: &mut Vfs,
) -> Result<(), u32> {
    let launch = startup(platform, bootstrap)?;
    if launch.role_id != VFSD_ROLE_ID {
        return Err(6);
    }
    let deadline = platform
        .monotonic_deadline_after(WYR0_I_SUPERVISION_POLICY.ready_timeout_ns)
        .map_err(|_| 7u32)?;
    let staged = receive_stage(platform, &launch, deadline)?;
    let (Some((publication, grant)), None) = (staged.publication, staged.client) else {
        return Err(16);
    };
    for channel in staged.channels() {
        if channel.slot != SLOT_MOUNT
            || vfs
                .mount(
                    channel.label(),
                    channel.handle,
                    channel.flags & CHANNEL_READ_ONLY != 0,
                )
                .is_err()
        {
            return Err(17);
        }
    }
    publish(platform, publication, grant, deadline)?;
    let extra = [
        DwWaitItemV1 {
            handle: launch.control,
            signals: READABLE_OR_CLOSED,
        },
        DwWaitItemV1 {
            handle: publication,
            signals: READABLE_OR_CLOSED,
        },
    ];
    loop {
        match vfs.step(platform, &extra, DW_DEADLINE_INFINITE) {
            Ok(Some(Event::Extra { index: 0, observed })) => {
                // Init sends nothing after STAGE; its closure retires us.
                return if observed.0 & DW_SIGNAL_READABLE.0 != 0 {
                    Err(102)
                } else {
                    Ok(())
                };
            }
            Ok(Some(Event::Extra { index: 1, observed })) => {
                if observed.0 & DW_SIGNAL_READABLE.0 == 0 {
                    // The registry is gone: no new clients, but keep serving.
                    return Err(103);
                }
                if let Some(client) = accept_offer(platform, publication, grant, SYSTEM_VFS)? {
                    vfs.accept_client(platform, client);
                }
            }
            Ok(Some(_)) | Ok(None) => {}
            Err(_) => return Err(100),
        }
    }
}
