//! Native WYR1-C resident device-coordinator ownership and construction.
//!
//! Historical C3 keeps its direct, hardware-free construction path. The C4
//! profile instead parents each devmgr generation under retained resource-
//! domain custody and delegates only its reduced claim authority.

use super::*;
#[cfg(feature = "wyr1d-selector32")]
#[path = "wyr1d_native.rs"]
mod selector32;
#[cfg(feature = "wyr1e-production")]
#[path = "wyr1e_native.rs"]
mod wyr1e;
use crate::wyr1b::{EndpointKind, RegistryTopology};
#[cfg(all(test, feature = "wyr1e8-selector33"))]
use crate::wyr1b_job::JobDispatcher;
#[cfg(all(test, any(feature = "wyr1e8-selector33", feature = "wyr1f-closure")))]
use crate::wyr1b_native::InstalledPeer;
#[cfg(all(test, feature = "wyr1e8-selector33"))]
use crate::wyr1b_native::ShellControllerState;
#[cfg(all(test, feature = "wyr1e-production"))]
use crate::wyr1b_native::registry_native_attempt_for_fixture;
#[cfg(feature = "dw1e3-selector31")]
use crate::wyr1b_native::{InstalledPeer, launch_registry_client_actor};
use crate::wyr1b_native::{
    RegistryNativeAttempt, create_controller_channel_pair, establish_registry_topology,
    launch_registry_until_ready, launch_registry_until_ready_before, poison_registry_generation,
    poison_registry_generation_before, restart_topology_or_poison_before,
    retire_registry_for_recovery_before,
};
use deepwyrm_syscall::{DW_HANDLE_TRANSFER_MOVE, DW_OBJECT_TYPE_CHANNEL, DwHandleTransferV1};
#[cfg(any(
    feature = "dw1e3-selector31",
    feature = "wyr1d-selector32",
    feature = "wyr1e-production"
))]
use wyrmroot_device_proto::SERIAL_CONSOLE_CONNECTOR_PUBLICATION_POLICY;
#[cfg(not(any(
    feature = "dw1e3-selector31",
    feature = "wyr1d-selector32",
    feature = "wyr1e-production"
)))]
use wyrmroot_device_proto::SERIAL_CONSOLE_PUBLICATION_POLICY;
#[cfg(any(
    test,
    not(any(feature = "wyr1d-selector32", feature = "wyr1e-production"))
))]
use wyrmroot_device_proto::controller::encode as encode_controller;
use wyrmroot_device_proto::coordinator::{
    RegistryEndpoint, RegistryEndpointGeneration, RegistryEndpointId, RegistryGeneration,
    SupervisorGeneration,
};
#[cfg(any(
    feature = "wyr1c6-production",
    feature = "dw1e3-selector31",
    feature = "wyr1d-selector32"
))]
use wyrmroot_device_proto::driver_launch::encode_reaped;
#[cfg(any(
    feature = "wyr1c6-production",
    feature = "dw1e3-selector31",
    feature = "wyr1d-selector32"
))]
use wyrmroot_device_proto::driver_launch::parse_driver_retired;
#[cfg(feature = "wyr1c6-selector29")]
use wyrmroot_device_proto::driver_launch::{C6_FACT_BYTES, C6Fact, parse_c6_fact};
use wyrmroot_device_proto::{
    DriverLaunchRequest,
    controller::{ControllerMessage, StatusCode, parse as parse_controller},
    driver_launch::{
        DRIVER_RETIRED_BYTES, LAUNCH_REQUEST_BYTES, LAUNCH_RESPONSE_BYTES, encode_constructed,
        parse_request,
    },
    manifest::{COM2_ROLE_ID, ContentIdentity, Manifest as DeviceManifest},
};
#[cfg(any(test, not(feature = "wyr1c5-production")))]
use wyrmroot_loader::launch::CHILD_CHANNEL_RIGHTS;
#[cfg(feature = "wyr1c5-production")]
use wyrmroot_loader::launch::CHILD_CHANNEL_TRANSFER_RIGHTS;
#[cfg(test)]
use wyrmroot_loader::launch::DEVICE_MANIFEST_RIGHTS;
use wyrmroot_loader::{
    launch::{DEVICE_MANIFEST_TRANSFER_RIGHTS, LaunchProfile},
    process::{
        DeviceCoordinatorLoadRequest, DeviceCoordinatorResourceLoadRequest,
        DeviceDriverLoadRequest, load_device_coordinator_process,
        load_device_coordinator_resource_process, load_device_driver_process,
    },
};

#[cfg(feature = "wyr1c5-production")]
const DRIVER_CONTROL_INGRESS_RIGHTS: DwRights = CHILD_CHANNEL_TRANSFER_RIGHTS;
#[cfg(not(feature = "wyr1c5-production"))]
const DRIVER_CONTROL_INGRESS_RIGHTS: DwRights = CHILD_CHANNEL_RIGHTS;
#[cfg(feature = "dw1e3-selector31")]
use wyrmroot_dw1e3_com2_test::{
    CHALLENGE_BYTES as E3A_CHALLENGE_BYTES, CHALLENGE_GENERATION as E3A_CHALLENGE_GENERATION,
    CONTROL_BYTES as E3A_CONTROL_BYTES, ChallengeBinding,
    ControllerMessage as E3AControllerMessage, DevmgrConfig, DevmgrReady,
    RESPONSE_BYTES as E3A_RESPONSE_BYTES, TRANSPORT_EMPTY_FACT_BYTES, TransportEmptyFact,
    challenge as e3a_challenge, encode as encode_e3a_controller, encode_begin_retire,
    encode_challenge_binding, encode_devmgr_config as encode_e3a_devmgr_config,
    encode_finalize_retire, fnv1a64 as e3a_fnv1a64, parse as parse_e3a_controller,
    parse_binding_ready, parse_devmgr_ready, parse_retire_stage1_ready, parse_transport_empty_fact,
    response as e3a_response,
};
use wyrmroot_registry_proto::{
    Header as RegistryHeader, MessageType as RegistryMessageType, ProtocolVersion,
    encode_install_publication,
};

pub(crate) const MARKER_BYTES: &[u8] = b"WYR1-C1";
pub(crate) const MARKER_PATH: &str = "system/bootstrap/wyr1-c-gate-v1";
pub(crate) const DEVICE_MANIFEST_PATH: &str = "system/bootstrap/wyr1-c-device-manifest-v1";
const DEVMGR_PATH: &str = "system/devmgr";
const PUBLICATION_ID_BASE: u64 = 0xC1_0000;
const SERVICE_GENERATION_BASE: u64 = 0xC1_0800;
const PUBLICATION_TRANSACTION_BASE: u64 = 0xC1_1000;
#[cfg(feature = "dw1e3-selector31")]
const E3A_PROBE_PATH: &str = "test/dw1e3/com2-probe";
#[cfg(feature = "dw1e3-selector31")]
const E3A_PROBE_TRANSACTION_ID: u64 = 0xE3A0_0001;
#[cfg(feature = "dw1e3-selector31")]
const E3A_PROBE_CLIENT_ID_BASE: u64 = 0x2_E3A0;

#[cfg(feature = "dw1e3-selector31")]
fn e3a_probe_client_id(challenge_generation: u64) -> Result<u64, InitError> {
    match challenge_generation {
        1 | 2 => E3A_PROBE_CLIENT_ID_BASE
            .checked_add(challenge_generation)
            .ok_or(InitError::Accounting),
        _ => Err(InitError::WrongActivationOrder),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PublicationCorrelation {
    publication_id: u64,
    service_generation: u64,
    transaction_id: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PublicationAllocator {
    next: PublicationCorrelation,
}

impl PublicationAllocator {
    const fn new() -> Self {
        Self {
            next: PublicationCorrelation {
                publication_id: PUBLICATION_ID_BASE + 1,
                service_generation: SERVICE_GENERATION_BASE + 1,
                transaction_id: PUBLICATION_TRANSACTION_BASE + 1,
            },
        }
    }

    fn issue(&mut self) -> Result<PublicationCorrelation, InitError> {
        let issued = self.next;
        self.next = PublicationCorrelation {
            publication_id: issued
                .publication_id
                .checked_add(1)
                .ok_or(InitError::Accounting)?,
            service_generation: issued
                .service_generation
                .checked_add(1)
                .ok_or(InitError::Accounting)?,
            transaction_id: issued
                .transaction_id
                .checked_add(1)
                .ok_or(InitError::Accounting)?,
        };
        Ok(issued)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DriverNativeAttempt {
    loaded: LoadedProcess,
    task_group: DwHandle,
    request: DriverLaunchRequest,
}

/// The resident endpoint allocator, for card R1's scenario driver.
///
/// The driver issues its probe's launch-session grant from the same allocator
/// every other resident endpoint comes from, so a launch session cannot collide
/// with a registry endpoint id. It is exposed rather than duplicated because a
/// second private allocator would be exactly that collision waiting to happen.
#[cfg(feature = "r1-selector34")]
pub(crate) fn resident_topology(
    resident: &mut ResidentSystemInit,
) -> Result<&mut RegistryTopology, InitError> {
    Ok(&mut resident
        .wyr1c
        .as_mut()
        .ok_or(InitError::AbsentState(0x10))?
        .topology)
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct ResidentState {
    #[cfg(feature = "wyr1d-selector32")]
    d5: Option<selector32::State>,
    #[cfg(feature = "wyr1e-production")]
    e6: Option<wyr1e::State>,
    resource_domain: Option<ResourceDomainCustody>,
    registry: Option<RegistryNativeAttempt>,
    topology: RegistryTopology,
    devmgr: Option<ActiveNativeRole>,
    binding: Option<wyrmroot_device_proto::RegistryBinding>,
    publication_service_generation: u64,
    waiting_registry_observed: bool,
    publication_allocator: PublicationAllocator,
    last_controller_transaction: u64,
    next_controller_transaction: u64,
    driver: Option<DriverNativeAttempt>,
    last_reaped_driver: Option<DriverLaunchRequest>,
    #[cfg(feature = "dw1e3-selector31")]
    e3a_probe: Option<InstalledPeer>,
    #[cfg(feature = "dw1e3-selector31")]
    e3a_stream_generation: Option<u64>,
    #[cfg(feature = "dw1e3-selector31")]
    e3a_binding: Option<ChallengeBinding>,
    #[cfg(feature = "dw1e3-selector31")]
    e3a_response_committed: bool,
    #[cfg(feature = "dw1e3-selector31")]
    e3a_transport_empty: Option<TransportEmptyFact>,
    #[cfg(feature = "dw1e3-selector31")]
    e3a_begin_retire_sent: bool,
    #[cfg(feature = "dw1e3-selector31")]
    e3a_stage1_ready: bool,
    #[cfg(feature = "dw1e3-selector31")]
    e3a_peer_closed: bool,
    #[cfg(feature = "dw1e3-selector31")]
    e3a_finalize_retire_sent: bool,
    #[cfg(feature = "dw1e3-selector31")]
    e3a_next_challenge_generation: u64,
    #[cfg(feature = "dw1e3-selector31")]
    e3a_terminal_claimed: bool,
    #[cfg(feature = "dw1e3-selector31")]
    e3a_u2_probe_reaped_successfully: bool,
    #[cfg(feature = "wyr1c6-selector29")]
    c6_gate_config: crate::wyr1c6_gate::GateConfig,
    #[cfg(feature = "wyr1c6-selector29")]
    pub(crate) c6_evidence: Option<crate::wyr1c6_gate::EvidenceLog>,
    #[cfg(feature = "wyr1c6-selector29")]
    c6_d1_lease: Option<u64>,
    #[cfg(feature = "wyr1c6-selector29")]
    c6_d1_supervisor: Option<u64>,
    #[cfg(feature = "wyr1c6-selector29")]
    c6_d1_cleanup_complete: bool,
    #[cfg(feature = "wyr1c6-selector29")]
    c6_d1_driver_failures: u64,
    #[cfg(feature = "wyr1c6-selector29")]
    c6_d2_lease: Option<u64>,
    #[cfg(feature = "wyr1c6-selector29")]
    c6_d2_supervisor: Option<u64>,
    #[cfg(feature = "wyr1c6-selector29")]
    c6_d2_role: Option<u64>,
    #[cfg(feature = "wyr1c6-selector29")]
    c6_u1_irq: Option<u64>,
    #[cfg(feature = "wyr1c6-selector29")]
    c6_u1_attempt: Option<u64>,
    #[cfg(feature = "wyr1c6-selector29")]
    c6_u1_endpoint: Option<u64>,
    #[cfg(feature = "wyr1c6-selector29")]
    c6_p1_service_generation: u64,
    #[cfg(feature = "wyr1c6-selector29")]
    c6_p1_registry_generation: u64,
    #[cfg(feature = "wyr1c6-selector29")]
    c6_p1_endpoint_generation: u64,
    #[cfg(feature = "wyr1c6-selector29")]
    c6_u2_irq: Option<u64>,
    #[cfg(feature = "wyr1c6-selector29")]
    c6_u2_attempt: Option<u64>,
    #[cfg(feature = "wyr1c6-selector29")]
    c6_u2_endpoint: Option<u64>,
    #[cfg(feature = "wyr1c6-selector29")]
    c6_p2_service_generation: u64,
    #[cfg(feature = "wyr1c6-selector29")]
    c6_p2_registry_generation: u64,
    #[cfg(feature = "wyr1c6-selector29")]
    c6_p2_endpoint_generation: u64,
    last_driver_attempt: u64,
    last_driver_session: u64,
    last_driver_endpoint: u64,
    last_driver_transaction: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DevmgrNativeAttempt {
    active: ActiveNativeRole,
    binding: wyrmroot_device_proto::RegistryBinding,
    publication_service_generation: u64,
    last_controller_transaction: u64,
    next_controller_transaction: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ResidentPollEvent {
    DevmgrExited,
    DevmgrControlLost,
    DevmgrControlReadable,
    /// The registry's control channel peer-closed.
    RegistryControlLost,
    /// The registry's process exited.
    RegistryExited,
    DriverExited,
    #[cfg(feature = "dw1e3-selector31")]
    ProbeControlReadable,
    #[cfg(feature = "dw1e3-selector31")]
    ProbeControlLost,
    #[cfg(feature = "dw1e3-selector31")]
    ProbeExited,
}

fn classify_resident_poll(
    result: DwWaitResultV1,
    registry_present: bool,
    driver_present: bool,
    #[cfg(feature = "dw1e3-selector31")] probe_present: bool,
) -> Result<ResidentPollEvent, InitError> {
    let item_count = 2 + usize::from(registry_present) * 2 + usize::from(driver_present) + {
        #[cfg(feature = "dw1e3-selector31")]
        {
            usize::from(probe_present) * 2
        }
        #[cfg(not(feature = "dw1e3-selector31"))]
        {
            0
        }
    };
    if result.index >= item_count as u32 {
        return Err(InitError::Supervision);
    }
    match result.index {
        0 if result.observed.0 & DW_SIGNAL_EXITED.0 != 0 => Ok(ResidentPollEvent::DevmgrExited),
        1 if result.observed.0 & DW_SIGNAL_PEER_CLOSED.0 != 0 => {
            Ok(ResidentPollEvent::DevmgrControlLost)
        }
        1 if result.observed.0 & DW_SIGNAL_READABLE.0 != 0 => {
            Ok(ResidentPollEvent::DevmgrControlReadable)
        }
        // F3A.6h. These were one `RegistryLost` variant, which made a closed
        // channel and a dead process the same word: the first points at the
        // channel's other end or a handle lifetime, the second at registryd
        // itself, and F3A.6g could say the registry was lost four times
        // without saying how. Devmgr's two are named separately directly
        // above, and always were.
        2 if registry_present && result.observed.0 & DW_SIGNAL_PEER_CLOSED.0 != 0 => {
            Ok(ResidentPollEvent::RegistryControlLost)
        }
        3 if registry_present && result.observed.0 & DW_SIGNAL_EXITED.0 != 0 => {
            Ok(ResidentPollEvent::RegistryExited)
        }
        index
            if driver_present
                && index == 2 + u32::from(registry_present) * 2
                && result.observed.0 & DW_SIGNAL_EXITED.0 != 0 =>
        {
            Ok(ResidentPollEvent::DriverExited)
        }
        #[cfg(feature = "dw1e3-selector31")]
        index
            if probe_present
                && index == 2 + u32::from(registry_present) * 2 + u32::from(driver_present)
                && result.observed.0 & DW_SIGNAL_READABLE.0 != 0 =>
        {
            // A probe may write ResponseCommitted and close immediately. On
            // a combined READABLE|PEER_CLOSED wake, consume that queued,
            // exact message first; a fresh close wake then classifies the
            // post-response lifetime normally.
            Ok(ResidentPollEvent::ProbeControlReadable)
        }
        #[cfg(feature = "dw1e3-selector31")]
        index
            if probe_present
                && index == 2 + u32::from(registry_present) * 2 + u32::from(driver_present)
                && result.observed.0 & DW_SIGNAL_PEER_CLOSED.0 != 0 =>
        {
            Ok(ResidentPollEvent::ProbeControlLost)
        }
        #[cfg(feature = "dw1e3-selector31")]
        index
            if probe_present
                && index == 3 + u32::from(registry_present) * 2 + u32::from(driver_present)
                && result.observed.0 & DW_SIGNAL_EXITED.0 != 0 =>
        {
            Ok(ResidentPollEvent::ProbeExited)
        }
        _ => Err(InitError::Supervision),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RegistryRecoveryStep {
    Degraded,
    AwaitStatus,
    Restart,
}

/// Why a registry recovery gave up without installing a replacement.
///
/// Both exits used to `return Ok(())`, which made them indistinguishable from
/// a status: F3A.6f could say the smp profile's registry slot had been emptied
/// and not which exit emptied it. `InitError::RegistryAbandoned` carries one
/// of these.
// The reason is only *reported* under `wyr1e-production`, but every caller
// names its trigger regardless, so the names exist in every build.
#[cfg_attr(not(feature = "wyr1e-production"), allow(dead_code))]
pub(crate) mod abandoned {
    // Which exit gave up is not in the reason byte: it is the operation field
    // of the same status. `registry_recovery_step`'s `Degraded` exit -- the
    // controller's restart budget for the registry exhausted -- is attributed
    // `RetireRegistry` (0x0b), and the exit where
    // `launch_registry_until_ready_before` returned `Ok(None)` rather than an
    // owner is attributed `LaunchRegistry` (0x0c). One for one.
    //
    // F3A.6j needed the whole low nibble for the poll phase and found the exit
    // already encoded eight bits above it. Per
    // `DIAGNOSTIC_CAUSE_CARRIAGE_CONTRACT.md` §3.1 a collapse is permitted
    // when the fact survives on the reader's channel, and here it survives in
    // the same word; `wyr1e_product_source.rs` pins the correspondence so the
    // redundancy cannot quietly stop being true.

    /// What asked for the recovery that gave up, in the reason's high nibble.
    ///
    /// F3A.6h. The exit alone says the budget ran out; it does not say what
    /// kept spending it, and the callers are not interchangeable -- a
    /// peer-closed channel, a dead process and a shell-side poisoning have
    /// different causes. The final call's trigger is the one reported, which
    /// is the loss that exhausted the budget.
    // Each trigger belongs to a different caller, and the callers are behind
    // different features: `WYR1E_POLL_E8` needs `wyr1e8-selector33` and
    // `NONE` is only reached by host fixtures. Naming the whole set in one
    // place is what makes the reason byte readable, so the set is allowed to
    // be wider than any single build's callers rather than split across cfgs
    // that would drift out of step with them.
    #[allow(dead_code)]
    pub(crate) mod trigger {
        /// Not loss-driven: startup, a fallback, or a host fixture.
        pub(crate) const NONE: u8 = 0x00;
        /// `ResidentPollEvent::RegistryControlLost`.
        pub(crate) const CONTROL_LOST: u8 = 0x01;
        /// `ResidentPollEvent::RegistryExited`.
        pub(crate) const EXITED: u8 = 0x02;
        /// Devmgr reported waiting-for-registry while an owner still existed.
        pub(crate) const DEVMGR_WAITING: u8 = 0x03;
        /// `wyr1e::PollOutcome::RecoverRegistry`.
        pub(crate) const WYR1E_POLL: u8 = 0x04;
        /// `wyr1e::PollOutcome::RecoverRegistryForE8`.
        pub(crate) const WYR1E_POLL_E8: u8 = 0x05;
        /// `start_wyr1e_or_recover_registry`'s fallback after a failed start.
        pub(crate) const WYR1E_START_FALLBACK: u8 = 0x06;
    }

    /// Which part of `wyr1e::poll` asked, in the reason's low nibble.
    ///
    /// F3A.6j. `WYR1E_POLL` covers twenty product sites across three
    /// functions, which is most of the poll, so on its own it named a file
    /// rather than a cause. These name the site. `NONE` is every trigger that
    /// is not the wyr1e poll.
    #[allow(dead_code)]
    pub(crate) mod phase {
        /// Not a wyr1e-poll trigger.
        pub(crate) const NONE: u8 = 0x00;
        /// A publication datagram that did not parse, or was not the expected
        /// message or generation.
        pub(crate) const PUBLICATION_DATAGRAM: u8 = 0x01;
        /// The publication observer's own lifecycle: a lost or unreadable
        /// observer channel, or a refused rebind.
        pub(crate) const PUBLICATION_OBSERVER: u8 = 0x02;
        /// The job dispatcher failed and left the shell registry poisoned.
        pub(crate) const DISPATCHER_POISONED: u8 = 0x03;
        /// The console's READY deadline had already passed on entry.
        pub(crate) const READY_DEADLINE_BEFORE_WAIT: u8 = 0x04;
        /// The console wait timed out and the READY deadline had passed.
        pub(crate) const READY_DEADLINE_AFTER_WAIT: u8 = 0x05;
        /// The console wait reported an index that is not the launch channel.
        pub(crate) const CONSOLE_WAIT_INDEX: u8 = 0x06;
        /// The console wrote when no READY was outstanding.
        pub(crate) const CONSOLE_UNSOLICITED: u8 = 0x07;
        /// Retired. `0x08` was "receiving the console's message failed",
        /// which is where F3A.6j found the F bring-up dying. That site now
        /// returns the kernel status instead of laundering it into a registry
        /// recovery, so the phase can no longer be produced. The number stays
        /// spent so an older transcript still reads correctly.
        /// The console's message carried handles, which READY never does.
        pub(crate) const CONSOLE_UNEXPECTED_HANDLES: u8 = 0x09;
        /// The console's READY message failed validation.
        pub(crate) const CONSOLE_READY_INVALID: u8 = 0x0a;
        /// A recovery episode was still live when READY arrived.
        pub(crate) const CONSOLE_RECOVERY_LIVE: u8 = 0x0b;
        /// A console signal matched none of the handled cases.
        pub(crate) const CONSOLE_EVENT_UNMATCHED: u8 = 0x0c;
    }

    /// One reason byte: the trigger in the high nibble, the poll phase in the
    /// low. The exit is the operation field of the same status; see the note
    /// above the phase module.
    #[must_use]
    pub(crate) const fn reason(trigger: u8, phase: u8) -> u8 {
        (trigger & 0x0f) << 4 | (phase & 0x0f)
    }
}

const fn registry_recovery_step(
    exhausted: bool,
    status_already_consumed: bool,
) -> RegistryRecoveryStep {
    if exhausted {
        RegistryRecoveryStep::Degraded
    } else if status_already_consumed {
        RegistryRecoveryStep::Restart
    } else {
        RegistryRecoveryStep::AwaitStatus
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn activate_in_place<'a, S, L, W>(
    system: &mut S,
    loader: &mut L,
    waits: &mut W,
    slot: &'a mut MaybeUninit<ResidentSystemInit>,
    authority: LoadAuthority,
    resource_domain: Option<ResourceDomainCustody>,
    parent_profile: LaunchProfile,
    bootstrap_channel: DwHandle,
    parent_transaction: u64,
    bootfs: &[u8],
) -> Result<&'a mut ResidentSystemInit, InitError>
where
    S: Wyr1BPlatform,
    L: LoaderPlatform<Error = NativeError>,
    W: SupervisionPlatform<Error = NativeError>,
{
    let archive = Archive::new(bootfs).map_err(InitError::Bootfs)?;
    if archive
        .lookup(MARKER_PATH.as_bytes())
        .map_err(map_lookup)?
        .data()
        != MARKER_BYTES
    {
        return Err(InitError::WrongManifestProfile);
    }
    let manifest_entry = archive
        .lookup(DEVICE_MANIFEST_PATH.as_bytes())
        .map_err(map_lookup)?;
    if manifest_entry.is_executable() {
        return Err(InitError::WrongManifestProfile);
    }
    let device_manifest = DeviceManifest::parse(manifest_entry.data())
        .map_err(|_| InitError::WrongManifestProfile)?;
    let (manifest, uart_identity) = crate::wyr1b_native::validate_retained_bootfs_c1(bootfs)?;
    #[cfg(feature = "wyr1c6-selector29")]
    let (c6_gate_config, c6_evidence) = {
        let entry = archive
            .lookup(crate::wyr1c6_gate::GATE_PATH.as_bytes())
            .map_err(map_lookup)?;
        let config =
            crate::wyr1c6_gate::parse_config(entry.data()).map_err(InitError::Wyr1C6GateConfig)?;
        let evidence = Some(
            crate::wyr1c6_gate::EvidenceLog::new(config.nonce)
                .map_err(InitError::Wyr1C6GateConfig)?,
        );
        (config, evidence)
    };
    validate_device_identity(device_manifest, uart_identity)?;
    #[cfg(feature = "wyr1f-closure")]
    let wyr1f = crate::wyr1f_closure::ClosureEpisode::new(manifest.gate_config());
    let resident = slot.write(ResidentSystemInit {
        controller: manifest,
        authority,
        result: RecoveryResult::Degraded,
        active: [None; EARLY_ROLE_COUNT],
        evidence_finalized: false,
        session_complete: false,
        last_tick_ns: 0,
        wyr1b: None,
        wyr1b_evidence: None,
        wyr1c: None,
        #[cfg(feature = "wyr1f-closure")]
        wyr1f,
    });
    resident.controller.become_operational()?;
    let mut ready = [0u8; HEADER_BYTES];
    let ready_len = encode_ready_for_profile(parent_profile, parent_transaction, &mut ready)
        .map_err(InitError::Launch)?;
    system
        .send_channel(bootstrap_channel, &ready[..ready_len])
        .map_err(InitError::Native)?;
    resident
        .controller
        .begin_registry(system.now().map_err(InitError::Native)?, 1, 0xC1_0000)?;
    // Startup phases name themselves, so a bring-up failure says which role
    // was being brought up. Before F3A.6e these reached the host as
    // `operation = 0x0f`, and F3A.6d could locate a site without being able to
    // say whether the site ran during startup or during an ordinary tick.
    let registry = attribute_failure(
        RecoveryOperation::ActivateRegistry,
        launch_registry_until_ready(
            system,
            loader,
            waits,
            &mut resident.controller,
            authority,
            bootfs,
        ),
    )?
    .ok_or(InitError::AbsentState(0x11))?;
    let (registry, mut topology) = attribute_failure(
        RecoveryOperation::ActivateRegistry,
        establish_registry_topology(system, waits, &mut resident.controller, registry),
    )?;
    let mut publication_allocator = PublicationAllocator::new();
    let devmgr = match launch_devmgr(
        system,
        loader,
        waits,
        &mut resident.controller,
        authority,
        resource_domain,
        bootfs,
        registry,
        &mut topology,
        &mut publication_allocator,
        manifest_entry.data(),
    ) {
        Ok(devmgr) => devmgr,
        Err(error) => {
            let error =
                attribute_failure::<()>(RecoveryOperation::ActivateDevmgr, Err(error)).unwrap_err();
            let poison = poison_registry_generation(
                system,
                waits,
                &mut resident.controller,
                registry,
                false,
            );
            return Err(poison.err().unwrap_or(error));
        }
    };
    #[cfg(feature = "wyr1e-production")]
    let e6 = Some(wyr1e::State::new(topology.generation())?);
    let state = ResidentState {
        #[cfg(feature = "wyr1d-selector32")]
        d5: Some(selector32::State::new(bootfs)?),
        #[cfg(feature = "wyr1e-production")]
        e6,
        resource_domain,
        registry: Some(registry),
        topology,
        devmgr: Some(devmgr.active),
        binding: Some(devmgr.binding),
        publication_service_generation: devmgr.publication_service_generation,
        waiting_registry_observed: false,
        publication_allocator,
        last_controller_transaction: devmgr.last_controller_transaction,
        next_controller_transaction: devmgr.next_controller_transaction,
        driver: None,
        last_reaped_driver: None,
        #[cfg(feature = "dw1e3-selector31")]
        e3a_probe: None,
        #[cfg(feature = "dw1e3-selector31")]
        e3a_stream_generation: None,
        #[cfg(feature = "dw1e3-selector31")]
        e3a_binding: None,
        #[cfg(feature = "dw1e3-selector31")]
        e3a_response_committed: false,
        #[cfg(feature = "dw1e3-selector31")]
        e3a_transport_empty: None,
        #[cfg(feature = "dw1e3-selector31")]
        e3a_begin_retire_sent: false,
        #[cfg(feature = "dw1e3-selector31")]
        e3a_stage1_ready: false,
        #[cfg(feature = "dw1e3-selector31")]
        e3a_peer_closed: false,
        #[cfg(feature = "dw1e3-selector31")]
        e3a_finalize_retire_sent: false,
        #[cfg(feature = "dw1e3-selector31")]
        e3a_next_challenge_generation: E3A_CHALLENGE_GENERATION,
        #[cfg(feature = "dw1e3-selector31")]
        e3a_terminal_claimed: false,
        #[cfg(feature = "dw1e3-selector31")]
        e3a_u2_probe_reaped_successfully: false,
        #[cfg(feature = "wyr1c6-selector29")]
        c6_gate_config,
        #[cfg(feature = "wyr1c6-selector29")]
        c6_evidence,
        #[cfg(feature = "wyr1c6-selector29")]
        c6_d1_lease: None,
        #[cfg(feature = "wyr1c6-selector29")]
        c6_d1_supervisor: None,
        #[cfg(feature = "wyr1c6-selector29")]
        c6_d1_cleanup_complete: false,
        #[cfg(feature = "wyr1c6-selector29")]
        c6_d1_driver_failures: 0,
        #[cfg(feature = "wyr1c6-selector29")]
        c6_d2_lease: None,
        #[cfg(feature = "wyr1c6-selector29")]
        c6_d2_supervisor: None,
        #[cfg(feature = "wyr1c6-selector29")]
        c6_d2_role: None,
        #[cfg(feature = "wyr1c6-selector29")]
        c6_u1_irq: None,
        #[cfg(feature = "wyr1c6-selector29")]
        c6_u1_attempt: None,
        #[cfg(feature = "wyr1c6-selector29")]
        c6_u1_endpoint: None,
        #[cfg(feature = "wyr1c6-selector29")]
        c6_p1_service_generation: 0,
        #[cfg(feature = "wyr1c6-selector29")]
        c6_p1_registry_generation: 0,
        #[cfg(feature = "wyr1c6-selector29")]
        c6_p1_endpoint_generation: 0,
        #[cfg(feature = "wyr1c6-selector29")]
        c6_u2_irq: None,
        #[cfg(feature = "wyr1c6-selector29")]
        c6_u2_attempt: None,
        #[cfg(feature = "wyr1c6-selector29")]
        c6_u2_endpoint: None,
        #[cfg(feature = "wyr1c6-selector29")]
        c6_p2_service_generation: 0,
        #[cfg(feature = "wyr1c6-selector29")]
        c6_p2_registry_generation: 0,
        #[cfg(feature = "wyr1c6-selector29")]
        c6_p2_endpoint_generation: 0,
        last_driver_attempt: 0,
        last_driver_session: 0,
        last_driver_endpoint: 0,
        last_driver_transaction: 0,
    };
    resident.active = [Some(registry.active), Some(devmgr.active)];
    resident.result = RecoveryResult::Recovered;
    resident.wyr1c = Some(state);
    Ok(resident)
}

fn validate_device_identity(
    manifest: DeviceManifest<'_>,
    uart_identity: [u8; 32],
) -> Result<(), InitError> {
    manifest
        .match_com2(ContentIdentity(uart_identity))
        .map(|_| ())
        .map_err(|_| InitError::WrongManifestProfile)
}

#[allow(clippy::too_many_arguments)]
fn launch_devmgr<S, L, W>(
    system: &mut S,
    loader: &mut L,
    waits: &mut W,
    controller: &mut SystemInit,
    authority: LoadAuthority,
    resource_domain: Option<ResourceDomainCustody>,
    bootfs: &[u8],
    registry: RegistryNativeAttempt,
    topology: &mut RegistryTopology,
    publication_allocator: &mut PublicationAllocator,
    manifest_bytes: &[u8],
) -> Result<DevmgrNativeAttempt, InitError>
where
    S: Wyr1BPlatform,
    L: LoaderPlatform<Error = NativeError>,
    W: SupervisionPlatform<Error = NativeError>,
{
    let RestartState::Starting {
        generation,
        transaction_id,
        ..
    } = controller
        .role_state(RoleId::Devmgr)
        .ok_or(InitError::AbsentState(0x12))?
    else {
        return Err(InitError::WrongActivationOrder);
    };
    let grant = topology
        .issue(generation, EndpointKind::Publication)
        .map_err(InitError::Wyr1BModel)?;
    let publication = publication_allocator.issue()?;
    let binding = wyrmroot_device_proto::RegistryBinding {
        generation: RegistryGeneration(grant.registry_generation),
        endpoint: RegistryEndpoint {
            id: RegistryEndpointId(grant.endpoint_id),
            generation: RegistryEndpointGeneration(grant.endpoint_generation),
        },
    };
    let archive = Archive::new(bootfs).map_err(InitError::Bootfs)?;
    let image = archive.lookup(DEVMGR_PATH.as_bytes()).map_err(map_lookup)?;
    let identity = controller.executable_identity(RoleId::Devmgr)?;
    if !image.is_executable() || wyrmroot_runtime::sha256::digest(image.data()) != identity {
        return Err(InitError::ArtifactIdentityMismatch(RoleId::Devmgr));
    }
    let (registry_endpoint, devmgr_endpoint) = create_controller_channel_pair(system)?;
    let manifest = match system
        .materialize_read_only_memory(
            authority.parent_root,
            manifest_bytes,
            DEVICE_MANIFEST_TRANSFER_RIGHTS,
        )
        .map_err(InitError::Native)
    {
        Ok(manifest) => manifest,
        Err(error) => {
            let cleanup_failed = system.close_handle(registry_endpoint).is_err()
                | system.close_handle(devmgr_endpoint).is_err();
            return Err(if cleanup_failed {
                InitError::Cleanup
            } else {
                error
            });
        }
    };
    let task_group_parent = resource_domain
        .map(ResourceDomainCustody::handle)
        .unwrap_or(authority.task_group);
    let task_group = match system
        .create_attempt_task_group(task_group_parent)
        .map_err(InitError::Native)
    {
        Ok(task_group) => task_group,
        Err(error) => {
            let cleanup_failed = system.close_handle(registry_endpoint).is_err()
                | system.close_handle(devmgr_endpoint).is_err()
                | system.close_handle(manifest).is_err();
            return Err(if cleanup_failed {
                InitError::Cleanup
            } else {
                error
            });
        }
    };
    let reservation = match controller.reserve_attempt(RoleId::Devmgr, generation, transaction_id) {
        Ok(reservation) => reservation,
        Err(error) => {
            let cleanup_failed = system.close_handle(registry_endpoint).is_err()
                | system.close_handle(devmgr_endpoint).is_err()
                | system.close_handle(manifest).is_err()
                | system.close_handle(task_group).is_err();
            return Err(if cleanup_failed {
                InitError::Cleanup
            } else {
                error
            });
        }
    };
    if let Err(error) = install_publication(
        system,
        registry.control_channel,
        grant,
        publication,
        registry_endpoint,
    ) {
        let cleanup_failed = system.close_handle(registry_endpoint).is_err()
            | system.close_handle(devmgr_endpoint).is_err()
            | system.close_handle(manifest).is_err()
            | system.close_handle(task_group).is_err()
            | controller.abort_reservation(reservation).is_err();
        return Err(if cleanup_failed {
            InitError::Cleanup
        } else {
            error
        });
    }
    let generation_authority = LoadAuthority {
        task_group,
        ..authority
    };
    let loaded_result = if let Some(custody) = resource_domain {
        let reduced = custody
            .devmgr_claim_authority(ResourceDomainMembership::DevmgrGenerationDescendant)
            .map_err(|_| InitError::WrongActivationOrder)?;
        load_device_coordinator_resource_process(
            loader,
            generation_authority,
            DeviceCoordinatorResourceLoadRequest {
                image: image.data(),
                display_path: DEVMGR_PATH,
                publication_endpoint: devmgr_endpoint,
                manifest,
                resource_domain: reduced.handle(),
                supervisor_generation: generation,
                transaction_id,
            },
        )
    } else {
        load_device_coordinator_process(
            loader,
            generation_authority,
            DeviceCoordinatorLoadRequest {
                image: image.data(),
                display_path: DEVMGR_PATH,
                publication_endpoint: devmgr_endpoint,
                manifest,
                supervisor_generation: generation,
                transaction_id,
            },
        )
    };
    let loaded = match loaded_result {
        Ok(loaded) => loaded,
        Err(failure) => {
            let mut cleanup_failed = system.close_handle(task_group).is_err()
                | controller.abort_reservation(reservation).is_err();
            if !failure.publication_endpoint_consumed {
                cleanup_failed |= system.close_handle(devmgr_endpoint).is_err();
            }
            if !failure.manifest_consumed {
                cleanup_failed |= system.close_handle(manifest).is_err();
            }
            return Err(if cleanup_failed {
                InitError::Cleanup
            } else {
                InitError::Loader(failure.error)
            });
        }
    };
    let resources = AttemptResources {
        role: RoleId::Devmgr,
        generation,
        transaction_id,
        executable_identity: identity,
        startup_profile: StartupProfile::DeviceCoordinator,
        task_group,
        process: loaded.process,
        launch_channel: loaded.launch_channel,
        mappings: 0,
        reservation,
    };
    if let Err(error) = controller.install_attempt(resources) {
        let cleanup_failed = cleanup_loaded(system, waits, loaded, task_group, true).is_err();
        return Err(if cleanup_failed {
            InitError::Cleanup
        } else {
            error
        });
    }
    let started = match system.now().map_err(InitError::Native) {
        Ok(value) => value,
        Err(error) => {
            return fail_loaded_devmgr(
                system,
                waits,
                controller,
                loaded,
                task_group,
                generation,
                transaction_id,
                error,
            );
        }
    };
    if let Err(error) =
        controller.child_started(RoleId::Devmgr, generation, transaction_id, started)
    {
        return fail_loaded_devmgr(
            system,
            waits,
            controller,
            loaded,
            task_group,
            generation,
            transaction_id,
            error,
        );
    }
    let deadline = started
        .checked_add(WYR0_I_SUPERVISION_POLICY.ready_timeout_ns)
        .ok_or(InitError::Accounting)?;
    let launch_profile = if resource_domain.is_some() {
        LaunchProfile::DeviceCoordinatorResourceDomain
    } else {
        LaunchProfile::DeviceCoordinator
    };
    if await_child_ready_profile_observed(
        waits,
        loaded.process,
        loaded.launch_channel,
        launch_profile,
        transaction_id,
        DwDeadline(deadline),
    )
    .is_err()
    {
        return fail_loaded_devmgr(
            system,
            waits,
            controller,
            loaded,
            task_group,
            generation,
            transaction_id,
            InitError::Supervision,
        );
    }
    if let Err(error) = controller.ready(
        RoleId::Devmgr,
        generation,
        transaction_id,
        system.now().map_err(InitError::Native)?,
    ) {
        return fail_loaded_devmgr(
            system,
            waits,
            controller,
            loaded,
            task_group,
            generation,
            transaction_id,
            error,
        );
    }
    let request = ControllerMessage::InstallPublication {
        supervisor_generation: SupervisorGeneration(generation),
        binding,
        transaction_id,
    };
    let bytes = match encode_publication_request(request, publication.service_generation) {
        Ok(bytes) => bytes,
        Err(()) => {
            return fail_loaded_devmgr(
                system,
                waits,
                controller,
                loaded,
                task_group,
                generation,
                transaction_id,
                InitError::WrongManifestProfile,
            );
        }
    };
    if let Err(error) = system
        .send_channel(loaded.launch_channel, &bytes)
        .map_err(InitError::Native)
    {
        return fail_loaded_devmgr(
            system,
            waits,
            controller,
            loaded,
            task_group,
            generation,
            transaction_id,
            error,
        );
    }
    let now = match system.now().map_err(InitError::Native) {
        Ok(value) => value,
        Err(error) => {
            return fail_loaded_devmgr(
                system,
                waits,
                controller,
                loaded,
                task_group,
                generation,
                transaction_id,
                error,
            );
        }
    };
    let status_deadline = match now.checked_add(WYR0_I_SUPERVISION_POLICY.ready_timeout_ns) {
        Some(value) => value,
        None => {
            return fail_loaded_devmgr(
                system,
                waits,
                controller,
                loaded,
                task_group,
                generation,
                transaction_id,
                InitError::Accounting,
            );
        }
    };
    let observed = match system
        .wait_many(
            core::slice::from_ref(&DwWaitItemV1 {
                handle: loaded.launch_channel,
                signals: DW_SIGNAL_READABLE,
            }),
            DwDeadline(status_deadline),
        )
        .map_err(InitError::Native)
    {
        Ok(value) => value,
        Err(error) => {
            return fail_loaded_devmgr(
                system,
                waits,
                controller,
                loaded,
                task_group,
                generation,
                transaction_id,
                error,
            );
        }
    };
    if observed.index != 0 || observed.observed.0 & DW_SIGNAL_READABLE.0 == 0 {
        return fail_loaded_devmgr(
            system,
            waits,
            controller,
            loaded,
            task_group,
            generation,
            transaction_id,
            InitError::Supervision,
        );
    }
    let response = match receive_controller_status(system, loaded.launch_channel) {
        Ok(value) => value,
        Err(error) => {
            return fail_loaded_devmgr(
                system,
                waits,
                controller,
                loaded,
                task_group,
                generation,
                transaction_id,
                error,
            );
        }
    };
    let expected_status = if resource_domain.is_some() {
        StatusCode::OperationalResourceOwned
    } else {
        StatusCode::OperationalWaitingForDeviceBundle
    };
    if response
        != (ControllerMessage::Status {
            supervisor_generation: SupervisorGeneration(generation),
            binding: Some(binding),
            transaction_id,
            status: expected_status,
            attempt_generation: None,
        })
    {
        return fail_loaded_devmgr(
            system,
            waits,
            controller,
            loaded,
            task_group,
            generation,
            transaction_id,
            InitError::WrongManifestProfile,
        );
    }
    Ok(DevmgrNativeAttempt {
        active: ActiveNativeRole {
            role: RoleId::Devmgr,
            generation,
            transaction_id,
            loaded,
            task_group,
        },
        binding,
        publication_service_generation: publication.service_generation,
        last_controller_transaction: transaction_id,
        next_controller_transaction: transaction_id.checked_add(1).ok_or(InitError::Accounting)?,
    })
}

#[cfg(any(feature = "wyr1d-selector32", feature = "wyr1e-production"))]
const PUBLICATION_REQUEST_BYTES: usize = wyrmroot_device_proto::controller_v1_1::RECORD_BYTES;
#[cfg(not(any(feature = "wyr1d-selector32", feature = "wyr1e-production")))]
const PUBLICATION_REQUEST_BYTES: usize = wyrmroot_device_proto::controller::INSTALL_BYTES;

fn encode_publication_request(
    controller: ControllerMessage,
    service_generation: u64,
) -> Result<[u8; PUBLICATION_REQUEST_BYTES], ()> {
    let mut bytes = [0u8; PUBLICATION_REQUEST_BYTES];
    #[cfg(any(feature = "wyr1d-selector32", feature = "wyr1e-production"))]
    wyrmroot_device_proto::controller_v1_1::encode(
        wyrmroot_device_proto::controller_v1_1::PublicationMessage {
            controller,
            service_generation,
        },
        &mut bytes,
    )
    .map_err(|_| ())?;
    #[cfg(not(any(feature = "wyr1d-selector32", feature = "wyr1e-production")))]
    {
        let _ = service_generation;
        encode_controller(controller, &mut bytes).map_err(|_| ())?;
    }
    Ok(bytes)
}

fn install_publication<S: Wyr1BPlatform>(
    system: &mut S,
    control: DwHandle,
    grant: crate::wyr1b::EndpointGrant,
    correlation: PublicationCorrelation,
    endpoint: DwHandle,
) -> Result<(), InitError> {
    let mut bytes = [0u8; 256];
    #[cfg(any(
        feature = "dw1e3-selector31",
        feature = "wyr1d-selector32",
        feature = "wyr1e-production"
    ))]
    let policy = SERIAL_CONSOLE_CONNECTOR_PUBLICATION_POLICY;
    #[cfg(not(any(
        feature = "dw1e3-selector31",
        feature = "wyr1d-selector32",
        feature = "wyr1e-production"
    )))]
    let policy = SERIAL_CONSOLE_PUBLICATION_POLICY;
    let size = encode_install_publication(
        RegistryHeader {
            message_type: RegistryMessageType::InstallPublication,
            registry_generation: grant.registry_generation,
            endpoint_id: 0,
            endpoint_generation: 0,
            transaction_id: correlation.transaction_id,
        },
        grant.endpoint_id,
        grant.endpoint_generation,
        policy.supervisor_role_id,
        correlation.publication_id,
        correlation.service_generation,
        policy.protocol_id,
        &[ProtocolVersion {
            major: policy.protocol_major,
            minor: policy.protocol_minor,
        }],
        policy.service_name,
        &mut bytes,
    )
    .map_err(InitError::RegistryProtocol)?;
    let transfer = DwHandleTransferV1 {
        handle: endpoint,
        requested_rights: wyrmroot_loader::launch::CHILD_CHANNEL_RIGHTS,
        operation: DW_HANDLE_TRANSFER_MOVE,
        reserved0: 0,
        reserved: [0; 2],
    };
    system
        .send_channel_with_handles(control, &bytes[..size], core::slice::from_ref(&transfer))
        .map_err(InitError::Native)
}

#[allow(clippy::too_many_arguments)]
fn fail_loaded_devmgr<S, W>(
    system: &mut S,
    waits: &mut W,
    controller: &mut SystemInit,
    loaded: LoadedProcess,
    task_group: DwHandle,
    generation: u64,
    transaction_id: u64,
    original: InitError,
) -> Result<DevmgrNativeAttempt, InitError>
where
    S: Wyr1BPlatform,
    W: SupervisionPlatform<Error = NativeError>,
{
    let now = system.now().unwrap_or(0);
    let transition_failed = controller
        .fail(
            RoleId::Devmgr,
            generation,
            transaction_id,
            now,
            AttemptFailure::WaitFailed,
        )
        .is_err();
    let cleanup_failed = cleanup_loaded(system, waits, loaded, task_group, true).is_err();
    let retired_at = now.checked_add(1).unwrap_or(now);
    let controller_cleanup_failed = transition_failed
        || retired_at == now
        || controller
            .cleanup_complete(RoleId::Devmgr, generation, transaction_id, retired_at)
            .is_err();
    Err(if cleanup_failed || controller_cleanup_failed {
        InitError::Cleanup
    } else {
        original
    })
}

fn await_waiting_for_registry<S, W>(
    system: &mut S,
    waits: &mut W,
    devmgr: ActiveNativeRole,
    supervisor_generation: u64,
    last_controller_transaction: u64,
    deadline_cap: Option<u64>,
) -> Result<(), InitError>
where
    S: InitPlatform,
    W: SupervisionPlatform<Error = NativeError>,
{
    let now = system.now().map_err(InitError::Native)?;
    if deadline_cap.is_some_and(|deadline| now >= deadline) {
        return Err(InitError::Supervision);
    }
    let deadline = now
        .checked_add(WYR0_I_SUPERVISION_POLICY.ready_timeout_ns)
        .ok_or(InitError::Accounting)?;
    let deadline = deadline_cap.map_or(deadline, |cap| deadline.min(cap));
    let observed = waits
        .wait_many(
            core::slice::from_ref(&DwWaitItemV1 {
                handle: devmgr.loaded.launch_channel,
                signals: DW_SIGNAL_READABLE,
            }),
            DwDeadline(deadline),
        )
        .map_err(InitError::Native)?;
    if observed.index != 0 || observed.observed.0 & DW_SIGNAL_READABLE.0 == 0 {
        return Err(InitError::Supervision);
    }
    receive_waiting_for_registry(
        system,
        devmgr,
        supervisor_generation,
        last_controller_transaction,
    )?;
    if let Some(deadline) = deadline_cap {
        let validated_at = system.now().map_err(InitError::Native)?;
        if validated_at >= deadline {
            return Err(InitError::Supervision);
        }
    }
    Ok(())
}

fn receive_waiting_for_registry<S: InitPlatform>(
    system: &mut S,
    devmgr: ActiveNativeRole,
    supervisor_generation: u64,
    last_controller_transaction: u64,
) -> Result<(), InitError> {
    let message = receive_controller_status(system, devmgr.loaded.launch_channel)?;
    match message {
        ControllerMessage::Status {
            supervisor_generation: received,
            binding: None,
            transaction_id,
            status: StatusCode::OperationalWaitingForRegistry,
            attempt_generation: None,
        } if received == SupervisorGeneration(supervisor_generation)
            && transaction_id == last_controller_transaction =>
        {
            Ok(())
        }
        _ => Err(InitError::WrongManifestProfile),
    }
}

fn receive_controller_status<S: InitPlatform>(
    system: &mut S,
    channel: DwHandle,
) -> Result<ControllerMessage, InitError> {
    let mut bytes = [0u8; wyrmroot_device_proto::controller::STATUS_BYTES];
    let mut handles = [DwReceivedHandleInfoV1::default(); 1];
    let counts = system
        .receive_channel(channel, &mut bytes, &mut handles)
        .map_err(InitError::Native)?;
    if counts.handles != 0 {
        let mut cleanup_failed = false;
        for info in handles.iter().take(counts.handles.min(handles.len())).rev() {
            cleanup_failed |= system.close_handle(info.handle).is_err();
        }
        return Err(if cleanup_failed {
            InitError::Cleanup
        } else {
            InitError::WrongManifestProfile
        });
    }
    if counts.bytes != bytes.len() {
        return Err(InitError::WrongManifestProfile);
    }
    parse_controller(&bytes).map_err(|_| InitError::WrongManifestProfile)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DevmgrControlInput {
    #[cfg(feature = "wyr1d-selector32")]
    D5Ready(wyrmroot_device_proto::d5_controller::D5DriverIdentity),
    #[cfg(feature = "wyr1d-selector32")]
    D5TxDrained(wyrmroot_device_proto::d5_controller::D5DrainIdentity),
    Status(ControllerMessage),
    #[cfg(feature = "wyr1c6-selector29")]
    C6Fact(C6Fact),
    #[cfg(feature = "dw1e3-selector31")]
    TransportEmpty(TransportEmptyFact),
    #[cfg(feature = "dw1e3-selector31")]
    BindingReady(ChallengeBinding),
    #[cfg(feature = "dw1e3-selector31")]
    RetireStage1Ready(ChallengeBinding),
    DriverLaunch {
        request: DriverLaunchRequest,
        child_endpoint: DwHandle,
    },
    DriverRetired {
        bytes: [u8; DRIVER_RETIRED_BYTES],
    },
}

fn receive_devmgr_control<S: InitPlatform>(
    system: &mut S,
    channel: DwHandle,
) -> Result<DevmgrControlInput, InitError> {
    let mut bytes = [0u8; LAUNCH_REQUEST_BYTES];
    let mut handles = [DwReceivedHandleInfoV1::default(); 1];
    let counts = system
        .receive_channel(channel, &mut bytes, &mut handles)
        .map_err(InitError::Native)?;
    if counts.bytes < 4 || counts.bytes > bytes.len() || counts.handles > handles.len() {
        close_received_native(system, &handles, counts.handles)?;
        return Err(InitError::WrongManifestProfile);
    }
    match &bytes[..4] {
        #[cfg(feature = "wyr1d-selector32")]
        b"WDR5" => {
            if counts.handles != 0 {
                close_received_native(system, &handles, counts.handles)?;
                return Err(InitError::WrongManifestProfile);
            }
            match wyrmroot_device_proto::d5_controller::parse(&bytes[..counts.bytes])
                .map_err(|_| InitError::WrongManifestProfile)?
            {
                wyrmroot_device_proto::d5_controller::D5ControllerMessage::DriverReady(
                    identity,
                ) => Ok(DevmgrControlInput::D5Ready(identity)),
                wyrmroot_device_proto::d5_controller::D5ControllerMessage::TxDrained(identity) => {
                    Ok(DevmgrControlInput::D5TxDrained(identity))
                }
                _ => Err(InitError::WrongManifestProfile),
            }
        }
        #[cfg(feature = "dw1e3-selector31")]
        b"WDE3" => {
            if counts.handles != 0 || counts.bytes != TRANSPORT_EMPTY_FACT_BYTES {
                close_received_native(system, &handles, counts.handles)?;
                return Err(InitError::WrongManifestProfile);
            }
            match u16::from_le_bytes([bytes[6], bytes[7]]) {
                3 => parse_transport_empty_fact(&bytes[..counts.bytes])
                    .map(DevmgrControlInput::TransportEmpty)
                    .map_err(|_| InitError::WrongManifestProfile),
                5 => parse_binding_ready(&bytes[..counts.bytes])
                    .map(DevmgrControlInput::BindingReady)
                    .map_err(|_| InitError::WrongManifestProfile),
                8 => parse_retire_stage1_ready(&bytes[..counts.bytes])
                    .map(DevmgrControlInput::RetireStage1Ready)
                    .map_err(|_| InitError::WrongManifestProfile),
                _ => Err(InitError::WrongManifestProfile),
            }
        }
        #[cfg(feature = "wyr1c6-selector29")]
        b"WRCF" => {
            if counts.handles != 0 || counts.bytes != C6_FACT_BYTES {
                close_received_native(system, &handles, counts.handles)?;
                return Err(InitError::WrongManifestProfile);
            }
            let fact = parse_c6_fact(&bytes[..counts.bytes])
                .map_err(|_| InitError::WrongManifestProfile)?;
            Ok(DevmgrControlInput::C6Fact(fact))
        }
        b"WRCS" => {
            if counts.handles != 0 {
                close_received_native(system, &handles, counts.handles)?;
                return Err(InitError::WrongManifestProfile);
            }
            let message = parse_controller(&bytes[..counts.bytes])
                .map_err(|_| InitError::WrongManifestProfile)?;
            if !matches!(message, ControllerMessage::Status { .. }) {
                return Err(InitError::WrongManifestProfile);
            }
            Ok(DevmgrControlInput::Status(message))
        }
        b"WRDL" => {
            if counts.handles != 1 || counts.bytes != LAUNCH_REQUEST_BYTES {
                close_received_native(system, &handles, counts.handles)?;
                return Err(InitError::WrongManifestProfile);
            }
            let info = handles[0];
            let metadata_valid = info.handle.0 != 0
                && info.object_type == DW_OBJECT_TYPE_CHANNEL
                && info.rights == DRIVER_CONTROL_INGRESS_RIGHTS
                && info.reserved0 == 0
                && info.reserved == [0; 2];
            let queried = system.query_capability_info(info.handle);
            if !metadata_valid
                || !matches!(
                    queried,
                    Ok(actual)
                        if actual.object_type == DW_OBJECT_TYPE_CHANNEL
                            && actual.rights == DRIVER_CONTROL_INGRESS_RIGHTS
                )
            {
                system
                    .close_handle(info.handle)
                    .map_err(|_| InitError::Cleanup)?;
                return Err(InitError::ResourceIdentityMismatch);
            }
            let request = match parse_request(&bytes[..counts.bytes]) {
                Ok(request) => request,
                Err(_) => {
                    system
                        .close_handle(info.handle)
                        .map_err(|_| InitError::Cleanup)?;
                    return Err(InitError::WrongManifestProfile);
                }
            };
            Ok(DevmgrControlInput::DriverLaunch {
                request,
                child_endpoint: info.handle,
            })
        }
        b"WRDT" => {
            if counts.bytes != DRIVER_RETIRED_BYTES || counts.handles != 0 {
                close_received_native(system, &handles, counts.handles)?;
                return Err(InitError::WrongManifestProfile);
            }
            let mut retired = [0u8; DRIVER_RETIRED_BYTES];
            retired.copy_from_slice(&bytes[..DRIVER_RETIRED_BYTES]);
            Ok(DevmgrControlInput::DriverRetired { bytes: retired })
        }
        _ => {
            close_received_native(system, &handles, counts.handles)?;
            Err(InitError::WrongManifestProfile)
        }
    }
}

fn close_received_native<S: InitPlatform>(
    system: &mut S,
    handles: &[DwReceivedHandleInfoV1],
    count: usize,
) -> Result<(), InitError> {
    let mut failed = false;
    for info in handles.iter().take(count.min(handles.len())).rev() {
        failed |= system.close_handle(info.handle).is_err();
    }
    if failed {
        Err(InitError::Cleanup)
    } else {
        Ok(())
    }
}

#[cfg(feature = "wyr1c6-selector29")]
fn accept_c6_fact(resident: &mut ResidentSystemInit, fact: C6Fact) -> Result<(), InitError> {
    #[cfg(feature = "wyr1c6-selector29")]
    if fact.event == 19 {
        let (d1_lease, cleanup_complete) = resident
            .wyr1c
            .as_ref()
            .map(|state| (state.c6_d1_lease, state.c6_d1_cleanup_complete))
            .ok_or(InitError::AbsentState(0x13))?;
        let d1_lease = d1_lease.ok_or(InitError::AbsentState(0x14))?;
        if !cleanup_complete
            || fact.lease <= d1_lease
            || fact.binding != 1
            || fact.value == 0
            || fact.aux != COM2_ROLE_ID.0
        {
            return Err(InitError::WrongManifestProfile);
        }
        let state = resident
            .wyr1c
            .as_mut()
            .ok_or(InitError::AbsentState(0x15))?;
        state
            .c6_evidence
            .as_mut()
            .ok_or(InitError::AbsentState(0x16))?
            .record(
                crate::wyr1c6_gate::GateEvent::D1GrantAvailable,
                d1_lease,
                0,
                1,
                0,
            )
            .map_err(|_| InitError::WrongManifestProfile)?;
    }
    let state = resident
        .wyr1c
        .as_mut()
        .ok_or(InitError::AbsentState(0x17))?;
    let valid = match fact.event {
        1 => fact.lease != 0 && fact.binding == 1 && fact.value != 0 && fact.aux == COM2_ROLE_ID.0,
        2 => Some(fact.lease) == state.c6_d1_lease && fact.binding == 1,
        3 => {
            fact.lease == state.c6_d1_lease.unwrap_or(0)
                && fact.binding != 0
                && fact.value != 0
                && fact.aux != 0
        }
        4 | 6 | 8 => {
            fact.lease == state.c6_d1_lease.unwrap_or(0)
                && Some(fact.binding) == state.c6_u1_irq
                && Some(fact.value) == state.c6_u1_attempt
                && Some(fact.aux) == state.c6_u1_endpoint
        }
        5 => {
            let binding = state.binding;
            fact.lease == state.c6_d1_lease.unwrap_or(0)
                && binding.is_some_and(|binding| {
                    fact.binding == binding.generation.0
                        && fact.aux == binding.endpoint.generation.0
                })
                && fact.value == state.c6_u1_attempt.unwrap_or(0)
                && state.publication_service_generation != 0
        }
        7 => {
            fact.lease == state.c6_d1_lease.unwrap_or(0)
                && fact.binding == state.c6_p1_registry_generation
                && Some(fact.value) == state.c6_u1_attempt
                && fact.aux == state.c6_p1_endpoint_generation
        }
        9 => {
            fact.lease == state.c6_d1_lease.unwrap_or(0)
                && Some(fact.binding) == state.c6_u1_irq
                && fact.value == 1
                && fact.aux == 0
        }
        10 => {
            fact.lease == state.c6_d1_lease.unwrap_or(0)
                && fact.binding != 0
                && Some(fact.binding) != state.c6_u1_irq
                && fact.value > state.c6_u1_attempt.unwrap_or(0)
                && fact.aux != 0
        }
        11 => {
            fact.lease == state.c6_d1_lease.unwrap_or(0)
                && Some(fact.binding) == state.c6_u2_irq
                && Some(fact.value) == state.c6_u2_attempt
                && Some(fact.aux) == state.c6_u2_endpoint
        }
        12 => {
            let binding = state.binding;
            fact.lease == state.c6_d1_lease.unwrap_or(0)
                && binding.is_some_and(|binding| {
                    fact.binding == binding.generation.0
                        && fact.aux == binding.endpoint.generation.0
                })
                && Some(fact.value) == state.c6_u2_attempt
                && state.publication_service_generation > state.c6_p1_service_generation
        }
        13 => {
            fact.lease == state.c6_d1_lease.unwrap_or(0)
                && fact.binding == state.c6_p1_registry_generation
                && Some(fact.value) == state.c6_u1_attempt
                && fact.aux == 3
        }
        14 => {
            fact.lease == state.c6_d1_lease.unwrap_or(0)
                && fact.binding == state.c6_p2_registry_generation
                && Some(fact.value) == state.c6_d1_supervisor
                && fact.aux == 0
        }
        15 => {
            fact.lease == state.c6_d1_lease.unwrap_or(0)
                && fact.binding == state.c6_p2_service_generation
                && Some(fact.value) == state.c6_u2_attempt
                && fact.aux == state.c6_p2_endpoint_generation
        }
        16 => {
            fact.lease == state.c6_d1_lease.unwrap_or(0)
                && Some(fact.binding) == state.c6_u2_irq
                && Some(fact.value) == state.c6_u2_attempt
                && Some(fact.aux) == state.c6_u2_endpoint
        }
        17 => {
            fact.lease == state.c6_d1_lease.unwrap_or(0)
                && fact.binding == 0
                && Some(fact.value) == state.c6_d1_supervisor
                && fact.aux == 1
        }
        18 => {
            fact.lease == state.c6_d1_lease.unwrap_or(0)
                && fact.binding == 0
                && fact.value == 1
                && fact.aux == 0
        }
        19 => {
            let active = state.devmgr;
            fact.lease > state.c6_d1_lease.unwrap_or(0)
                && fact.binding == 1
                && fact.value != 0
                && fact.aux != 0
                && active.is_some_and(|active| {
                    active.role == RoleId::Devmgr && active.generation == fact.value
                })
        }
        20..=22 => {
            let active = state.devmgr;
            fact.lease == state.c6_d2_lease.unwrap_or(0)
                && fact.binding == 1
                && Some(fact.value) == state.c6_d2_supervisor
                && Some(fact.aux) == state.c6_d2_role
                && active.is_some_and(|active| {
                    active.role == RoleId::Devmgr && active.generation == fact.value
                })
        }
        23 => {
            fact.lease == state.c6_d2_lease.unwrap_or(0)
                && fact.binding == 0
                && fact.value == 3
                && fact.aux == 0
                && resident
                    .controller
                    .c6_startup_profiles_exclude_direct_device_authority()
                && state.resource_domain.is_some_and(|custody| {
                    custody
                        .devmgr_claim_authority(ResourceDomainMembership::InitOutsideDomain)
                        .is_err()
                })
                && state.driver.is_none()
        }
        24 => {
            fact.lease == state.c6_d2_lease.unwrap_or(0)
                && fact.binding == 0
                && fact.value == 0
                && fact.aux == 0
                && state.c6_gate_config.physical_io_not_performed
        }
        25 => {
            let devmgr_failures = resident
                .controller
                .role_failure_count(RoleId::Devmgr)
                .unwrap_or(usize::MAX);
            fact.lease == state.c6_d2_lease.unwrap_or(0)
                && fact.binding == 0
                && fact.value == state.c6_d1_driver_failures
                && fact.aux == devmgr_failures as u64
        }
        26 => {
            fact.lease == state.c6_d2_lease.unwrap_or(0)
                && fact.binding == 0
                && fact.value == u64::from(WYR0_I_SUPERVISION_POLICY.max_attempts)
                && fact.aux == WYR0_I_SUPERVISION_POLICY.backoff_ns
        }
        _ => false,
    };
    if !valid {
        return Err(InitError::WrongManifestProfile);
    }
    let event = match fact.event {
        1 => crate::wyr1c6_gate::GateEvent::D1Begin,
        2 => crate::wyr1c6_gate::GateEvent::D1Lease,
        3 => crate::wyr1c6_gate::GateEvent::U1Start,
        4 => crate::wyr1c6_gate::GateEvent::U1Ready,
        5 => crate::wyr1c6_gate::GateEvent::P1Publish,
        6 => crate::wyr1c6_gate::GateEvent::U1Failure,
        7 => crate::wyr1c6_gate::GateEvent::P1Retire,
        8 => crate::wyr1c6_gate::GateEvent::U1Reap,
        9 => crate::wyr1c6_gate::GateEvent::OldIrqReleased,
        10 => crate::wyr1c6_gate::GateEvent::U2Start,
        11 => crate::wyr1c6_gate::GateEvent::U2Ready,
        12 => crate::wyr1c6_gate::GateEvent::P2Publish,
        13 => crate::wyr1c6_gate::GateEvent::StaleReject,
        14 => crate::wyr1c6_gate::GateEvent::D1Failure,
        15 => crate::wyr1c6_gate::GateEvent::P2Retire,
        16 => crate::wyr1c6_gate::GateEvent::U2Reap,
        17 => crate::wyr1c6_gate::GateEvent::D1GenerationClean,
        18 => crate::wyr1c6_gate::GateEvent::D1GrantAvailable,
        19 => crate::wyr1c6_gate::GateEvent::D2Lease,
        20 => crate::wyr1c6_gate::GateEvent::D2Start,
        21 => crate::wyr1c6_gate::GateEvent::D2Claim,
        22 => crate::wyr1c6_gate::GateEvent::D2Ready,
        23 => crate::wyr1c6_gate::GateEvent::NoAuthority,
        24 => crate::wyr1c6_gate::GateEvent::NoIo,
        25 => crate::wyr1c6_gate::GateEvent::Accounting,
        26 => crate::wyr1c6_gate::GateEvent::Bounded,
        _ => return Err(InitError::WrongManifestProfile),
    };
    let evidence_binding = c6_evidence_binding(
        fact.event,
        fact.binding,
        state.publication_service_generation,
        state.c6_p1_service_generation,
        state.c6_p2_service_generation,
    );
    let log = state
        .c6_evidence
        .as_mut()
        .ok_or(InitError::AbsentState(0x18))?;
    log.record(event, fact.lease, evidence_binding, fact.value, fact.aux)
        .map_err(|_| InitError::WrongManifestProfile)?;
    match fact.event {
        1 => {
            state.c6_d1_lease = Some(fact.lease);
            state.c6_d1_supervisor = Some(fact.value);
        }
        3 => {
            state.c6_u1_irq = Some(fact.binding);
            state.c6_u1_attempt = Some(fact.value);
            state.c6_u1_endpoint = Some(fact.aux);
        }
        5 => {
            state.c6_p1_service_generation = state.publication_service_generation;
            state.c6_p1_registry_generation = fact.binding;
            state.c6_p1_endpoint_generation = fact.aux;
        }
        6 => {
            state.c6_d1_driver_failures = state
                .c6_d1_driver_failures
                .checked_add(1)
                .ok_or(InitError::Accounting)?;
        }
        10 => {
            state.c6_u2_irq = Some(fact.binding);
            state.c6_u2_attempt = Some(fact.value);
            state.c6_u2_endpoint = Some(fact.aux);
        }
        12 => {
            state.c6_p2_service_generation = state.publication_service_generation;
            state.c6_p2_registry_generation = fact.binding;
            state.c6_p2_endpoint_generation = fact.aux;
        }
        19 => {
            state.c6_d2_lease = Some(fact.lease);
            state.c6_d2_supervisor = Some(fact.value);
            state.c6_d2_role = Some(fact.aux);
        }
        17 => state.c6_d1_cleanup_complete = true,
        _ => {}
    }
    if fact.event == 22 {
        emit_c6_terminal_facts(resident)?;
    }
    Ok(())
}

#[cfg(feature = "wyr1c6-selector29")]
const fn c6_evidence_binding(
    event: u8,
    observed_registry_generation: u64,
    current_service_generation: u64,
    p1_service_generation: u64,
    p2_service_generation: u64,
) -> u64 {
    match event {
        5 | 12 => current_service_generation,
        7 | 13 => p1_service_generation,
        14 => p2_service_generation,
        _ => observed_registry_generation,
    }
}

#[cfg(feature = "wyr1c6-selector29")]
fn emit_c6_terminal_facts(resident: &mut ResidentSystemInit) -> Result<(), InitError> {
    let (lease, driver_failures, devmgr_failures, max_attempts, backoff_ns) = {
        let state = resident
            .wyr1c
            .as_ref()
            .ok_or(InitError::AbsentState(0x19))?;
        let devmgr = state.devmgr.ok_or(InitError::AbsentState(0x1a))?;
        if devmgr.role != RoleId::Devmgr
            || state.driver.is_some()
            || state.c6_d2_lease.is_none()
            || state.c6_d2_supervisor != Some(devmgr.generation)
            || state.c6_d2_role != Some(COM2_ROLE_ID.0)
            || !state.c6_gate_config.physical_io_not_performed
            || !resident
                .controller
                .c6_startup_profiles_exclude_direct_device_authority()
            || !state.resource_domain.is_some_and(|custody| {
                custody
                    .devmgr_claim_authority(ResourceDomainMembership::InitOutsideDomain)
                    .is_err()
            })
        {
            return Err(InitError::WrongManifestProfile);
        }
        let lease = state.c6_d2_lease.ok_or(InitError::AbsentState(0x1b))?;
        let driver_failures = state.c6_d1_driver_failures;
        let devmgr_failures = resident
            .controller
            .role_failure_count(RoleId::Devmgr)
            .ok_or(InitError::Accounting)?;
        if driver_failures == 0 || devmgr_failures == 0 {
            return Err(InitError::Accounting);
        }
        (
            lease,
            driver_failures,
            devmgr_failures as u64,
            WYR0_I_SUPERVISION_POLICY.max_attempts,
            WYR0_I_SUPERVISION_POLICY.backoff_ns,
        )
    };
    for (event, value, aux) in [
        (23, 3, 0),
        (24, 0, 0),
        (25, driver_failures, devmgr_failures),
        (26, u64::from(max_attempts), backoff_ns),
    ] {
        accept_c6_fact(
            resident,
            C6Fact {
                event,
                lease,
                binding: 0,
                value,
                aux,
            },
        )?;
    }
    Ok(())
}

#[cfg(feature = "wyr1c6-selector29")]
pub fn finish_c6_evidence(resident: &mut ResidentSystemInit) -> Result<bool, InitError> {
    let state = resident
        .wyr1c
        .as_mut()
        .ok_or(InitError::AbsentState(0x1c))?;
    let log = state
        .c6_evidence
        .as_mut()
        .ok_or(InitError::AbsentState(0x1d))?;
    if !log.ready_for_terminal() {
        return Ok(false);
    }
    log.finish().map_err(|_| InitError::WrongManifestProfile)?;
    Ok(true)
}

fn validate_driver_actor(bootfs: &[u8], request: DriverLaunchRequest) -> Result<&[u8], InitError> {
    // Re-run the complete retained WRRM/product validation at the construction
    // boundary, then join the request identity through WRDM to the exact
    // executable bytes actually supplied to the loader.
    let _ = crate::wyr1b_native::validate_retained_bootfs_c1(bootfs)?;
    let archive = Archive::new(bootfs).map_err(InitError::Bootfs)?;
    let device_manifest = archive
        .lookup(DEVICE_MANIFEST_PATH.as_bytes())
        .map_err(map_lookup)?;
    if device_manifest.is_executable() {
        return Err(InitError::WrongManifestProfile);
    }
    let role = DeviceManifest::parse(device_manifest.data())
        .map_err(|_| InitError::WrongManifestProfile)?
        .match_com2(request.actor_identity)
        .map_err(|_| InitError::WrongManifestProfile)?;
    if request.role_id != COM2_ROLE_ID || role.role_id != request.role_id {
        return Err(InitError::WrongManifestProfile);
    }
    let actor = archive
        .lookup(wyrmroot_device_proto::manifest::UART16550D_PATH)
        .map_err(map_lookup)?;
    if !actor.is_executable()
        || wyrmroot_runtime::sha256::digest(actor.data()) != request.actor_identity.0
    {
        return Err(InitError::ArtifactIdentityMismatch(RoleId::Uart16550d));
    }
    Ok(actor.data())
}

fn driver_correlation_is_fresh(
    supervisor_generation: u64,
    last_attempt: u64,
    last_session: u64,
    last_endpoint: u64,
    last_transaction: u64,
    request: DriverLaunchRequest,
) -> bool {
    request.supervisor_generation == SupervisorGeneration(supervisor_generation)
        && request.attempt_generation.0 > last_attempt
        && request.launch_session.0 > last_session
        && request.endpoint.id.0 > last_endpoint
        && request.endpoint.generation.0 == 1
        && request.transaction_id > last_transaction
}

#[allow(clippy::too_many_arguments)]
fn construct_driver<S, L, W>(
    resident: &mut ResidentSystemInit,
    system: &mut S,
    loader: &mut L,
    waits: &mut W,
    bootfs: &[u8],
    devmgr: ActiveNativeRole,
    request: DriverLaunchRequest,
    child_endpoint: DwHandle,
) -> Result<(), InitError>
where
    S: Wyr1BPlatform,
    L: LoaderPlatform<Error = NativeError>,
    W: SupervisionPlatform<Error = NativeError>,
{
    // The recovery episode lives on the wyr1e console/shell supervisor, so
    // a build without that product has no episode rather than no concept of
    // one. The gate is the product, not a selector.
    #[cfg(feature = "wyr1e-production")]
    let action_deadline = wyr1e::recovery_deadline(resident)?;
    #[cfg(not(feature = "wyr1e-production"))]
    let action_deadline = None;
    if action_deadline.is_some_and(|deadline| system.now().map_or(true, |now| now >= deadline)) {
        system
            .close_handle(child_endpoint)
            .map_err(|_| InitError::Cleanup)?;
        return Err(InitError::Supervision);
    }
    let state = resident
        .wyr1c
        .as_ref()
        .ok_or(InitError::AbsentState(0x1e))?;
    let correlation_valid = driver_correlation_is_fresh(
        devmgr.generation,
        state.last_driver_attempt,
        state.last_driver_session,
        state.last_driver_endpoint,
        state.last_driver_transaction,
        request,
    );
    if !correlation_valid || state.driver.is_some() {
        system
            .close_handle(child_endpoint)
            .map_err(|_| InitError::Cleanup)?;
        return Err(InitError::WrongManifestProfile);
    }
    let actor = match validate_driver_actor(bootfs, request) {
        Ok(actor) => actor,
        Err(error) => {
            system
                .close_handle(child_endpoint)
                .map_err(|_| InitError::Cleanup)?;
            return Err(error);
        }
    };
    // `DW1_WYR1_FINAL_CLOSURE_CONTRACT.md` §5.3 item 2: the driver's attempt
    // TaskGroup is no longer a child of the devmgr generation that asked for
    // it, so tearing that generation down does not take the driver with it.
    // Deliberate driver retirement stays explicit -- `reap_driver` terminates
    // this group by handle -- which is the only path that ever needed to be
    // deliberate.
    //
    // It moves *up one level*, to the resource domain itself, not out to
    // init's bootstrap group. The domain is the fail-closed boundary:
    // `WYR1_C_DEVICE_HANDOFF_CONTRACT.md` §4 makes its teardown terminal
    // recovery for the boot, and a driver holding a DeviceResource and an
    // Interrupt outside it would survive that teardown. Init's own group sits
    // outside the domain, which is exactly why init cannot claim; a driver
    // parented there would inherit that escape. Builds with no resource domain
    // keep init's group, as they always did.
    let driver_parent = resident
        .wyr1c
        .as_ref()
        .and_then(|state| state.resource_domain)
        .map_or(resident.authority.task_group, ResourceDomainCustody::handle);
    let task_group = match system.create_attempt_task_group(driver_parent) {
        Ok(handle) => handle,
        Err(error) => {
            system
                .close_handle(child_endpoint)
                .map_err(|_| InitError::Cleanup)?;
            return Err(InitError::Native(error));
        }
    };
    let loaded = match load_device_driver_process(
        loader,
        LoadAuthority {
            task_group,
            ..resident.authority
        },
        DeviceDriverLoadRequest {
            image: actor,
            display_path: wyrmroot_device_proto::DEVICE_DRIVER_PATH,
            control_endpoint: child_endpoint,
            supervisor_generation: request.supervisor_generation.0,
            role_id: request.role_id.0,
            attempt_generation: request.attempt_generation.0,
            launch_session: request.launch_session.0,
            endpoint_id: request.endpoint.id.0,
            endpoint_generation: request.endpoint.generation.0,
            transaction_id: request.transaction_id,
        },
    ) {
        Ok(loaded) => loaded,
        Err(failure) => {
            let mut cleanup_failed = system.close_handle(task_group).is_err();
            if !failure.control_endpoint_consumed {
                cleanup_failed |= system.close_handle(child_endpoint).is_err();
            }
            return Err(if cleanup_failed {
                InitError::Cleanup
            } else {
                InitError::Loader(failure.error)
            });
        }
    };

    #[cfg(feature = "wyr1e-production")]
    if let Err(error) =
        wyr1e::ensure_recovery_live(resident, system.now().map_err(InitError::Native)?)
    {
        let cleanup_failed =
            cleanup_loaded_before(system, waits, loaded, task_group, true, action_deadline)
                .is_err();
        return Err(if cleanup_failed {
            InitError::Cleanup
        } else {
            error
        });
    }

    {
        let state = resident
            .wyr1c
            .as_mut()
            .ok_or(InitError::AbsentState(0x1f))?;
        state.driver = Some(DriverNativeAttempt {
            loaded,
            task_group,
            request,
        });
        state.last_driver_attempt = request.attempt_generation.0;
        state.last_driver_session = request.launch_session.0;
        state.last_driver_endpoint = request.endpoint.id.0;
        state.last_driver_transaction = request.transaction_id;
    }
    let mut ack = [0u8; LAUNCH_RESPONSE_BYTES];
    encode_constructed(request, &mut ack).map_err(|_| InitError::WrongManifestProfile)?;
    if let Err(error) = system.send_channel(devmgr.loaded.launch_channel, &ack) {
        let attempt = resident
            .wyr1c
            .as_ref()
            .and_then(|state| state.driver)
            .ok_or(InitError::AbsentState(0x20))?;
        let cleanup_failed = cleanup_loaded_before(
            system,
            waits,
            attempt.loaded,
            attempt.task_group,
            true,
            action_deadline,
        )
        .is_err();
        if !cleanup_failed {
            resident
                .wyr1c
                .as_mut()
                .ok_or(InitError::AbsentState(0x21))?
                .driver = None;
        }
        return Err(if cleanup_failed {
            InitError::Cleanup
        } else {
            InitError::Native(error)
        });
    }
    if action_deadline.is_some_and(|deadline| system.now().map_or(true, |now| now >= deadline)) {
        return Err(InitError::Supervision);
    }
    Ok(())
}

#[cfg(feature = "dw1e3-selector31")]
fn start_e3a_probe<S, L, W>(
    resident: &mut ResidentSystemInit,
    system: &mut S,
    loader: &mut L,
    waits: &mut W,
    bootfs: &[u8],
) -> Result<(), InitError>
where
    S: Wyr1BPlatform,
    L: LoaderPlatform<Error = NativeError>,
    W: SupervisionPlatform<Error = NativeError>,
{
    let (
        devmgr,
        registry_control,
        publication_generation,
        driver_attempt,
        challenge_generation,
        already_started,
    ) = {
        let state = resident
            .wyr1c
            .as_ref()
            .ok_or(InitError::AbsentState(0x22))?;
        (
            state.devmgr.ok_or(InitError::AbsentState(0x23))?,
            state
                .registry
                .ok_or(InitError::AbsentState(0x24))?
                .control_channel,
            state.publication_service_generation,
            state
                .driver
                .ok_or(InitError::AbsentState(0x25))?
                .request
                .attempt_generation
                .0,
            state.e3a_next_challenge_generation,
            state.e3a_probe.is_some(),
        )
    };
    if already_started || publication_generation == 0 || !matches!(challenge_generation, 1 | 2) {
        return Err(InitError::WrongActivationOrder);
    }
    let nonce = wyrmroot_runtime::dw1e3_build_nonce().map_err(InitError::Native)?;
    // E3A has no separate payload nonce. E3B supplies both frozen payload
    // nonces, which the runtime validates as distinct from this evidence key.
    let challenge = e3a_challenge(
        wyrmroot_runtime::dw1e3_challenge_nonce(challenge_generation).map_err(InitError::Native)?,
    );
    let expected_hash = e3a_fnv1a64(&challenge);
    let probe_client_id = e3a_probe_client_id(challenge_generation)?;

    // Constructing the process only unblocks devmgr's synchronous staging path;
    // it does not mean the Interrupt is bound or the registry publication is
    // committed. The selector-private ready reply is emitted by devmgr only
    // after both facts hold and its connector broker owns the exact generation.
    let mut devmgr_config = [0u8; wyrmroot_dw1e3_com2_test::DEVMGR_CONFIG_BYTES];
    encode_e3a_devmgr_config(
        DevmgrConfig {
            nonce,
            publication_generation,
        },
        &mut devmgr_config,
    )
    .map_err(|_| InitError::WrongManifestProfile)?;
    system
        .send_channel(devmgr.loaded.launch_channel, &devmgr_config)
        .map_err(InitError::Native)?;

    let now = system.now().map_err(InitError::Native)?;
    let deadline = now
        .checked_add(WYR0_I_SUPERVISION_POLICY.ready_timeout_ns)
        .ok_or(InitError::Accounting)?;
    let observed = waits
        .wait_many(
            &[
                DwWaitItemV1 {
                    handle: devmgr.loaded.launch_channel,
                    signals: DW_SIGNAL_READABLE,
                },
                DwWaitItemV1 {
                    handle: devmgr.loaded.process,
                    signals: DW_SIGNAL_EXITED,
                },
            ],
            DwDeadline(deadline),
        )
        .map_err(InitError::Native)?;
    if observed.index != 0 || observed.observed.0 & DW_SIGNAL_READABLE.0 == 0 {
        return Err(InitError::Supervision);
    }
    let mut devmgr_ready = [0u8; wyrmroot_dw1e3_com2_test::DEVMGR_CONFIG_BYTES];
    let mut ready_handles = [DwReceivedHandleInfoV1::default(); 1];
    let counts = system
        .receive_channel(
            devmgr.loaded.launch_channel,
            &mut devmgr_ready,
            &mut ready_handles,
        )
        .map_err(InitError::Native)?;
    if counts.bytes != devmgr_ready.len() || counts.handles != 0 {
        close_received_native(system, &ready_handles, counts.handles)?;
        return Err(InitError::WrongManifestProfile);
    }
    let ready = parse_devmgr_ready(&devmgr_ready).map_err(|_| InitError::WrongManifestProfile)?;
    if ready
        != (DevmgrReady {
            nonce,
            publication_generation,
        })
    {
        return Err(InitError::WrongManifestProfile);
    }

    let authority = resident.authority;
    let probe = {
        let state = resident
            .wyr1c
            .as_mut()
            .ok_or(InitError::AbsentState(0x26))?;
        launch_registry_client_actor(
            system,
            loader,
            waits,
            authority,
            bootfs,
            registry_control,
            &mut state.topology,
            E3A_PROBE_PATH,
            publication_generation,
            E3A_PROBE_TRANSACTION_ID,
            probe_client_id,
        )?
    };
    let result = (|| {
        // Bind both selector reporters from the controller's retained Process
        // custody. Deepwyrm resolves this handle in system-init's table, so
        // neither the probe nor a guessed primordial identity can claim the
        // controller role.
        wyrmroot_runtime::dw1e3_bind_probe(probe.loaded.process, nonce)
            .map_err(InitError::Native)?;
        let configure = E3AControllerMessage::Configure {
            nonce,
            publication_generation,
            challenge_generation,
            expected_length: E3A_CHALLENGE_BYTES as u64,
            expected_hash,
        };
        let mut bytes = [0u8; E3A_CONTROL_BYTES];
        encode_e3a_controller(configure, &mut bytes)
            .map_err(|_| InitError::WrongManifestProfile)?;
        system
            .send_channel(probe.loaded.launch_channel, &bytes)
            .map_err(InitError::Native)?;

        let now = system.now().map_err(InitError::Native)?;
        let deadline = now
            .checked_add(WYR0_I_SUPERVISION_POLICY.ready_timeout_ns)
            .ok_or(InitError::Accounting)?;
        let observed = waits
            .wait_many(
                &[
                    DwWaitItemV1 {
                        handle: probe.loaded.launch_channel,
                        signals: DW_SIGNAL_READABLE,
                    },
                    DwWaitItemV1 {
                        handle: probe.loaded.process,
                        signals: DW_SIGNAL_EXITED,
                    },
                ],
                DwDeadline(deadline),
            )
            .map_err(InitError::Native)?;
        if observed.index != 0 || observed.observed.0 & DW_SIGNAL_READABLE.0 == 0 {
            return Err(InitError::Supervision);
        }
        let mut handles = [DwReceivedHandleInfoV1::default(); 1];
        let counts = system
            .receive_channel(probe.loaded.launch_channel, &mut bytes, &mut handles)
            .map_err(InitError::Native)?;
        if counts.bytes != bytes.len() || counts.handles != 0 {
            close_received_native(system, &handles, counts.handles)?;
            return Err(InitError::WrongManifestProfile);
        }
        let attached = parse_e3a_controller(&bytes).map_err(|_| InitError::WrongManifestProfile)?;
        let E3AControllerMessage::Attached {
            nonce: received_nonce,
            publication_generation: received_publication,
            stream_generation,
            challenge_generation: received_challenge_generation,
        } = attached
        else {
            return Err(InitError::WrongManifestProfile);
        };
        if received_nonce != nonce
            || received_publication != publication_generation
            || received_challenge_generation != challenge_generation
        {
            return Err(InitError::WrongManifestProfile);
        }

        let binding = ChallengeBinding {
            nonce,
            attempt_generation: driver_attempt,
            publication_generation,
            stream_generation,
            challenge_generation,
            expected_length: E3A_CHALLENGE_BYTES as u64,
            expected_hash,
        };
        let mut binding_bytes = [0u8; TRANSPORT_EMPTY_FACT_BYTES];
        encode_challenge_binding(binding, &mut binding_bytes)
            .map_err(|_| InitError::WrongManifestProfile)?;
        system
            .send_channel(devmgr.loaded.launch_channel, &binding_bytes)
            .map_err(InitError::Native)?;
        let now = system.now().map_err(InitError::Native)?;
        let deadline = now
            .checked_add(WYR0_I_SUPERVISION_POLICY.ready_timeout_ns)
            .ok_or(InitError::Accounting)?;
        let observed = waits
            .wait_many(
                core::slice::from_ref(&DwWaitItemV1 {
                    handle: devmgr.loaded.launch_channel,
                    signals: DW_SIGNAL_READABLE,
                }),
                DwDeadline(deadline),
            )
            .map_err(InitError::Native)?;
        if observed.index != 0 || observed.observed.0 & DW_SIGNAL_READABLE.0 == 0 {
            return Err(InitError::Supervision);
        }
        if receive_devmgr_control(system, devmgr.loaded.launch_channel)?
            != DevmgrControlInput::BindingReady(binding)
        {
            return Err(InitError::WrongManifestProfile);
        }
        // Action 3 is the sole host-transmit readiness point, and only after
        // the current driver has returned its exact BindingReady correlation.
        wyrmroot_runtime::dw1e3_arm_challenge(
            stream_generation,
            challenge_generation,
            E3A_CHALLENGE_BYTES as u64,
            expected_hash,
            nonce,
        )
        .map_err(InitError::Native)?;
        let permit = E3AControllerMessage::ArmPermit {
            nonce,
            publication_generation,
            stream_generation,
            challenge_generation,
            expected_length: E3A_CHALLENGE_BYTES as u64,
            expected_hash,
        };
        encode_e3a_controller(permit, &mut bytes).map_err(|_| InitError::WrongManifestProfile)?;
        system
            .send_channel(probe.loaded.launch_channel, &bytes)
            .map_err(InitError::Native)?;
        Ok((stream_generation, binding))
    })();
    match result {
        Ok((stream_generation, binding)) => {
            let state = resident
                .wyr1c
                .as_mut()
                .ok_or(InitError::AbsentState(0x27))?;
            state.e3a_probe = Some(probe);
            state.e3a_stream_generation = Some(stream_generation);
            state.e3a_binding = Some(binding);
            state.e3a_response_committed = false;
            state.e3a_transport_empty = None;
            state.e3a_begin_retire_sent = false;
            state.e3a_stage1_ready = false;
            state.e3a_peer_closed = false;
            state.e3a_finalize_retire_sent = false;
            state.e3a_u2_probe_reaped_successfully = false;
            Ok(())
        }
        Err(error) => {
            let cleanup_failed =
                cleanup_loaded(system, waits, probe.loaded, probe.task_group, true).is_err();
            Err(if cleanup_failed {
                InitError::Cleanup
            } else {
                error
            })
        }
    }
}

fn reap_driver<S, W>(
    resident: &mut ResidentSystemInit,
    system: &mut S,
    waits: &mut W,
    terminate: bool,
) -> Result<DriverLaunchRequest, InitError>
where
    S: InitPlatform,
    W: SupervisionPlatform<Error = NativeError>,
{
    reap_driver_before(resident, system, waits, terminate, None)
}

fn reap_driver_before<S, W>(
    resident: &mut ResidentSystemInit,
    system: &mut S,
    waits: &mut W,
    terminate: bool,
    deadline_cap: Option<u64>,
) -> Result<DriverLaunchRequest, InitError>
where
    S: InitPlatform,
    W: SupervisionPlatform<Error = NativeError>,
{
    let attempt = resident
        .wyr1c
        .as_ref()
        .and_then(|state| state.driver)
        .ok_or(InitError::AbsentState(0x28))?;
    let request = attempt.request;
    cleanup_loaded_before(
        system,
        waits,
        attempt.loaded,
        attempt.task_group,
        terminate,
        deadline_cap,
    )?;
    if let Some(state) = resident.wyr1c.as_mut() {
        if state.driver != Some(attempt) {
            return Err(InitError::WrongActivationOrder);
        }
        state.driver = None;
        if deadline_cap.is_some_and(|deadline| system.now().map_or(true, |now| now >= deadline)) {
            return Err(InitError::Supervision);
        }
        state.last_reaped_driver = Some(request);
    }
    Ok(request)
}

#[cfg(feature = "dw1e3-selector31")]
fn exact_e3a_response(binding: ChallengeBinding) -> Result<(u64, u64), InitError> {
    let challenge = e3a_challenge(
        wyrmroot_runtime::dw1e3_challenge_nonce(binding.challenge_generation)
            .map_err(InitError::Native)?,
    );
    if binding.expected_length != E3A_CHALLENGE_BYTES as u64
        || binding.expected_hash != e3a_fnv1a64(&challenge)
    {
        return Err(InitError::WrongManifestProfile);
    }
    let response = e3a_response(&challenge);
    Ok((E3A_RESPONSE_BYTES as u64, e3a_fnv1a64(&response)))
}

#[cfg(feature = "dw1e3-selector31")]
fn exact_transport_empty(
    binding: ChallengeBinding,
    fact: TransportEmptyFact,
) -> Result<(), InitError> {
    let (response_length, response_hash) = exact_e3a_response(binding)?;
    if fact.nonce != binding.nonce
        || fact.attempt_generation != binding.attempt_generation
        || fact.publication_generation != binding.publication_generation
        || fact.stream_generation != binding.stream_generation
        || fact.challenge_generation != binding.challenge_generation
        || fact.response_length != response_length
        || fact.response_hash != response_hash
    {
        return Err(InitError::WrongManifestProfile);
    }
    Ok(())
}

#[cfg(feature = "dw1e3-selector31")]
fn maybe_begin_e3a_retire<S: InitPlatform>(
    resident: &mut ResidentSystemInit,
    system: &mut S,
) -> Result<(), InitError> {
    let (
        devmgr,
        binding,
        response_committed,
        transport_empty,
        already_sent,
        u2_probe_reaped_successfully,
    ) = {
        let state = resident
            .wyr1c
            .as_ref()
            .ok_or(InitError::AbsentState(0x29))?;
        (
            state.devmgr.ok_or(InitError::AbsentState(0x2a))?,
            state.e3a_binding.ok_or(InitError::AbsentState(0x2b))?,
            state.e3a_response_committed,
            state.e3a_transport_empty,
            state.e3a_begin_retire_sent,
            state.e3a_u2_probe_reaped_successfully,
        )
    };
    if !response_committed || transport_empty.is_none() {
        return Ok(());
    }
    if binding.challenge_generation == 2 {
        if !u2_probe_reaped_successfully {
            // A TEMT wake can win the resident poll before a simultaneously
            // queued nonzero probe exit.  The exact normal-zero reap is a
            // controller-side causal join, not merely cleanup.
            return Ok(());
        }
        let terminal_claimed = resident
            .wyr1c
            .as_ref()
            .ok_or(InitError::AbsentState(0x2c))?
            .e3a_terminal_claimed;
        if terminal_claimed {
            return Err(InitError::WrongManifestProfile);
        }
        exact_transport_empty(
            binding,
            transport_empty.ok_or(InitError::AbsentState(0x2d))?,
        )?;
        // The probe cannot make this claim: both its committed response and
        // the current driver's post-ack TEMT fact have been rejoined here.
        wyrmroot_runtime::dw1e3_terminal_claim(binding.nonce).map_err(InitError::Native)?;
        resident
            .wyr1c
            .as_mut()
            .ok_or(InitError::AbsentState(0x2e))?
            .e3a_terminal_claimed = true;
        return Ok(());
    }
    if binding.challenge_generation != 1 {
        return Err(InitError::WrongManifestProfile);
    }
    if already_sent {
        return Err(InitError::WrongManifestProfile);
    }
    exact_transport_empty(
        binding,
        transport_empty.ok_or(InitError::AbsentState(0x2f))?,
    )?;
    let mut bytes = [0u8; TRANSPORT_EMPTY_FACT_BYTES];
    encode_begin_retire(binding, &mut bytes).map_err(|_| InitError::WrongManifestProfile)?;
    system
        .send_channel(devmgr.loaded.launch_channel, &bytes)
        .map_err(InitError::Native)?;
    resident
        .wyr1c
        .as_mut()
        .ok_or(InitError::AbsentState(0x30))?
        .e3a_begin_retire_sent = true;
    Ok(())
}

#[cfg(feature = "dw1e3-selector31")]
fn send_e3a_finalize_retire<S: InitPlatform>(
    resident: &mut ResidentSystemInit,
    system: &mut S,
) -> Result<(), InitError> {
    let (devmgr, binding, stage1_ready, peer_closed, already_sent) = {
        let state = resident
            .wyr1c
            .as_ref()
            .ok_or(InitError::AbsentState(0x31))?;
        (
            state.devmgr.ok_or(InitError::AbsentState(0x32))?,
            state.e3a_binding.ok_or(InitError::AbsentState(0x33))?,
            state.e3a_stage1_ready,
            state.e3a_peer_closed,
            state.e3a_finalize_retire_sent,
        )
    };
    if !stage1_ready || !peer_closed {
        return Ok(());
    }
    if already_sent {
        return Err(InitError::WrongManifestProfile);
    }
    let mut bytes = [0u8; TRANSPORT_EMPTY_FACT_BYTES];
    encode_finalize_retire(binding, &mut bytes).map_err(|_| InitError::WrongManifestProfile)?;
    system
        .send_channel(devmgr.loaded.launch_channel, &bytes)
        .map_err(InitError::Native)?;
    resident
        .wyr1c
        .as_mut()
        .ok_or(InitError::AbsentState(0x34))?
        .e3a_finalize_retire_sent = true;
    Ok(())
}

#[cfg(feature = "dw1e3-selector31")]
fn receive_e3a_probe_message<S: InitPlatform>(
    resident: &ResidentSystemInit,
    system: &mut S,
) -> Result<E3AControllerMessage, InitError> {
    let probe = resident
        .wyr1c
        .as_ref()
        .and_then(|state| state.e3a_probe)
        .ok_or(InitError::AbsentState(0x35))?;
    let mut bytes = [0u8; E3A_CONTROL_BYTES];
    let mut handles = [DwReceivedHandleInfoV1::default(); 1];
    let counts = system
        .receive_channel(probe.loaded.launch_channel, &mut bytes, &mut handles)
        .map_err(InitError::Native)?;
    if counts.bytes != bytes.len() || counts.handles != 0 {
        close_received_native(system, &handles, counts.handles)?;
        return Err(InitError::WrongManifestProfile);
    }
    parse_e3a_controller(&bytes).map_err(|_| InitError::WrongManifestProfile)
}

#[cfg(feature = "dw1e3-selector31")]
fn validate_e3a_u1_finalize_exit<W>(
    resident: &ResidentSystemInit,
    waits: &mut W,
) -> Result<(), InitError>
where
    W: SupervisionPlatform<Error = NativeError>,
{
    let state = resident
        .wyr1c
        .as_ref()
        .ok_or(InitError::AbsentState(0x36))?;
    let binding = state.e3a_binding.ok_or(InitError::WrongManifestProfile)?;
    let driver = state.driver.ok_or(InitError::WrongManifestProfile)?;
    if binding.challenge_generation != 1
        || !state.e3a_response_committed
        || !state.e3a_begin_retire_sent
        || !state.e3a_stage1_ready
        || !state.e3a_peer_closed
        || !state.e3a_finalize_retire_sent
        || state.e3a_terminal_claimed
    {
        return Err(InitError::WrongManifestProfile);
    }
    exact_transport_empty(
        binding,
        state
            .e3a_transport_empty
            .ok_or(InitError::WrongManifestProfile)?,
    )?;
    let exit = waits
        .query_task_termination(driver.loaded.process)
        .map_err(InitError::Native)?;
    wyrmroot_runtime::validate_successful_exit(&exit).map_err(|_| InitError::WrongManifestProfile)
}

#[cfg(feature = "dw1e3-selector31")]
fn reap_e3a_probe<S, W>(
    resident: &mut ResidentSystemInit,
    system: &mut S,
    waits: &mut W,
    admit_u2: bool,
) -> Result<(), InitError>
where
    S: InitPlatform,
    W: SupervisionPlatform<Error = NativeError>,
{
    let probe = resident
        .wyr1c
        .as_mut()
        .and_then(|state| state.e3a_probe.take());
    let Some(probe) = probe else {
        return Ok(());
    };
    let deadline = system
        .now()
        .map_err(InitError::Native)?
        .checked_add(WYR0_I_SUPERVISION_POLICY.cleanup_timeout_ns)
        .ok_or(InitError::Accounting)?;
    // Closing only the controller endpoint asks the probe to take its normal
    // parent-peer-close exit. It has already supplied its close proof.
    let mut cleanup_failed = system.close_handle(probe.loaded.launch_channel).is_err();
    let observed_exit = matches!(
        waits.wait_many(
            core::slice::from_ref(&DwWaitItemV1 {
                handle: probe.loaded.process,
                signals: DW_SIGNAL_EXITED,
            }),
            DwDeadline(deadline),
        ),
        Ok(result) if result.index == 0 && result.observed.0 & DW_SIGNAL_EXITED.0 != 0
    ) && matches!(
        waits.query_task_termination(probe.loaded.process),
        Ok(info) if info.state == DW_TASK_STATE_EXITED
    );
    if !observed_exit {
        cleanup_failed |= system.terminate_task_group(probe.task_group).is_err();
        let fallback_deadline = system
            .now()
            .ok()
            .and_then(|now| now.checked_add(WYR0_I_SUPERVISION_POLICY.cleanup_timeout_ns));
        if let Some(fallback_deadline) = fallback_deadline {
            let _ = waits.wait_many(
                core::slice::from_ref(&DwWaitItemV1 {
                    handle: probe.loaded.process,
                    signals: DW_SIGNAL_EXITED,
                }),
                DwDeadline(fallback_deadline),
            );
        } else {
            cleanup_failed = true;
        }
    }
    cleanup_failed |= !matches!(
        waits.query_task_termination(probe.loaded.process),
        Ok(info)
            if info.state == DW_TASK_STATE_EXITED
                && (!admit_u2 || wyrmroot_runtime::validate_successful_exit(&info).is_ok())
    );
    for handle in [probe.loaded.process, probe.task_group] {
        cleanup_failed |= system.close_handle(handle).is_err();
    }
    if let Some(state) = resident.wyr1c.as_mut() {
        let retired_generation = state
            .e3a_binding
            .map(|binding| binding.challenge_generation)
            .unwrap_or(0);
        state.e3a_stream_generation = None;
        state.e3a_binding = None;
        state.e3a_response_committed = false;
        state.e3a_transport_empty = None;
        state.e3a_begin_retire_sent = false;
        state.e3a_stage1_ready = false;
        state.e3a_peer_closed = false;
        state.e3a_finalize_retire_sent = false;
        state.e3a_u2_probe_reaped_successfully = false;
        if cleanup_failed || !admit_u2 {
            // Any unexpected probe loss poisons the selector lifecycle.  A
            // failed cleanup must likewise never expose an intermediate U2
            // admission after a nonzero or incomplete U1 probe exit.
            state.e3a_next_challenge_generation = 0;
        } else if retired_generation == 1 {
            state.e3a_next_challenge_generation = 2;
        }
    }
    if cleanup_failed {
        Err(InitError::Cleanup)
    } else {
        Ok(())
    }
}

/// The fresh U2 probe exits normally after it has committed its response.  It
/// is no longer the active reporter, but its successful exit must be reaped
/// without clearing the U2 binding or a TEMT fact that is still in flight.
#[cfg(feature = "dw1e3-selector31")]
fn reap_e3a_u2_probe_after_response<S, W>(
    resident: &mut ResidentSystemInit,
    system: &mut S,
    waits: &mut W,
) -> Result<(), InitError>
where
    S: InitPlatform,
    W: SupervisionPlatform<Error = NativeError>,
{
    let probe = {
        let state = resident
            .wyr1c
            .as_mut()
            .ok_or(InitError::AbsentState(0x37))?;
        let binding = state.e3a_binding.ok_or(InitError::WrongManifestProfile)?;
        if binding.challenge_generation != 2
            || !state.e3a_response_committed
            || state.e3a_terminal_claimed
        {
            return Err(InitError::WrongManifestProfile);
        }
        state
            .e3a_probe
            .take()
            .ok_or(InitError::WrongManifestProfile)?
    };
    let deadline = system
        .now()
        .map_err(InitError::Native)?
        .checked_add(WYR0_I_SUPERVISION_POLICY.cleanup_timeout_ns)
        .ok_or(InitError::Accounting)?;
    let mut cleanup_failed = system.close_handle(probe.loaded.launch_channel).is_err();
    let observed_exit = matches!(
        waits.wait_many(
            core::slice::from_ref(&DwWaitItemV1 {
                handle: probe.loaded.process,
                signals: DW_SIGNAL_EXITED,
            }),
            DwDeadline(deadline),
        ),
        Ok(result) if result.index == 0 && result.observed.0 & DW_SIGNAL_EXITED.0 != 0
    );
    let terminal_result = if observed_exit {
        match waits.query_task_termination(probe.loaded.process) {
            Ok(exit) => wyrmroot_runtime::validate_successful_exit(&exit)
                .map_err(|_| InitError::WrongManifestProfile),
            Err(error) => Err(InitError::Native(error)),
        }
    } else {
        // No exit by the bounded deadline is a selector failure.  Terminate
        // only in this timeout-cleanup case, then wait/requery so every owned
        // handle is reconciled before returning the original failure.
        cleanup_failed |= system.terminate_task_group(probe.task_group).is_err();
        let fallback_deadline = system
            .now()
            .ok()
            .and_then(|now| now.checked_add(WYR0_I_SUPERVISION_POLICY.cleanup_timeout_ns));
        let fallback_exited = if let Some(fallback_deadline) = fallback_deadline {
            matches!(
                waits.wait_many(
                core::slice::from_ref(&DwWaitItemV1 {
                    handle: probe.loaded.process,
                    signals: DW_SIGNAL_EXITED,
                }),
                DwDeadline(fallback_deadline),
            ),
                Ok(result) if result.index == 0 && result.observed.0 & DW_SIGNAL_EXITED.0 != 0
            ) && matches!(
                waits.query_task_termination(probe.loaded.process),
                Ok(info) if info.state == DW_TASK_STATE_EXITED
            )
        } else {
            false
        };
        if !fallback_exited {
            // We have already closed the controller endpoint, but process and
            // task-group ownership remain live until a later cleanup/reap can
            // prove EXITED. Do not forget them on a successful-but-ineffective
            // terminate request.
            resident
                .wyr1c
                .as_mut()
                .ok_or(InitError::AbsentState(0x38))?
                .e3a_probe = Some(probe);
            return Err(InitError::Cleanup);
        }
        Err(InitError::Supervision)
    };
    for handle in [probe.loaded.process, probe.task_group] {
        cleanup_failed |= system.close_handle(handle).is_err();
    }
    if cleanup_failed {
        return Err(InitError::Cleanup);
    }
    terminal_result?;
    resident
        .wyr1c
        .as_mut()
        .ok_or(InitError::AbsentState(0x39))?
        .e3a_u2_probe_reaped_successfully = true;
    // TEMT may already be present when the exit is observed. Re-run the
    // controller join only after this exact normal-zero reap has committed.
    maybe_begin_e3a_retire(resident, system)
}

#[cfg(feature = "dw1e3-selector31")]
fn e3a_u2_probe_may_exit(resident: &ResidentSystemInit) -> bool {
    resident.wyr1c.as_ref().is_some_and(|state| {
        state
            .e3a_binding
            .is_some_and(|binding| binding.challenge_generation == 2)
            && state.e3a_response_committed
            && !state.e3a_terminal_claimed
    })
}

#[cfg(feature = "dw1e3-selector31")]
fn poison_e3a_lifecycle(resident: &mut ResidentSystemInit) {
    if let Some(state) = resident.wyr1c.as_mut() {
        state.e3a_next_challenge_generation = 0;
        state.e3a_stream_generation = None;
        state.e3a_binding = None;
        state.e3a_response_committed = false;
        state.e3a_transport_empty = None;
        state.e3a_begin_retire_sent = false;
        state.e3a_stage1_ready = false;
        state.e3a_peer_closed = false;
        state.e3a_finalize_retire_sent = false;
        state.e3a_u2_probe_reaped_successfully = false;
    }
}

#[cfg(feature = "dw1e3-selector31")]
fn fail_e3a_u2_probe_exit<S, W>(
    resident: &mut ResidentSystemInit,
    system: &mut S,
    waits: &mut W,
    error: InitError,
) -> Result<(), InitError>
where
    S: InitPlatform,
    W: SupervisionPlatform<Error = NativeError>,
{
    // A timed-out U2 reap can retain the process/task-group for a second
    // bounded cleanup attempt. Consume that owner before poisoning its
    // correlations so a live probe is never orphaned by this failure path.
    let probe_cleanup = reap_e3a_probe(resident, system, waits, false);
    poison_e3a_lifecycle(resident);
    let driver_cleanup = if resident
        .wyr1c
        .as_ref()
        .is_some_and(|state| state.driver.is_some())
    {
        reap_driver(resident, system, waits, true).map(|_| ())
    } else {
        Ok(())
    };
    if probe_cleanup.is_err() || driver_cleanup.is_err() {
        Err(InitError::Cleanup)
    } else {
        Err(error)
    }
}

/// A devmgr or registry recovery cannot inherit an in-flight selector probe.
/// Consume its exact owners first and poison all selector correlations so a
/// delayed report cannot advance Q1/Q2 or make a terminal claim.
#[cfg(feature = "dw1e3-selector31")]
fn fail_closed_e3a_recovery<S, W>(
    resident: &mut ResidentSystemInit,
    system: &mut S,
    waits: &mut W,
) -> Option<bool>
where
    S: InitPlatform,
    W: SupervisionPlatform<Error = NativeError>,
{
    let active = resident.wyr1c.as_ref().is_some_and(|state| {
        state.e3a_probe.is_some()
            || state.e3a_binding.is_some()
            || state.e3a_stream_generation.is_some()
    });
    if !active {
        return None;
    }
    let probe_cleanup = reap_e3a_probe(resident, system, waits, false);
    let driver_cleanup = if resident
        .wyr1c
        .as_ref()
        .is_some_and(|state| state.driver.is_some())
    {
        reap_driver(resident, system, waits, true).map(|_| ())
    } else {
        Ok(())
    };
    poison_e3a_lifecycle(resident);
    // The triggering registry/devmgr role is still owned by its recovery
    // caller. Leave a fatal-cleanup disposition for that caller to consume
    // both actor lifetimes before this resident can return.
    resident.result = RecoveryResult::Fatal;
    Some(probe_cleanup.is_err() || driver_cleanup.is_err())
}

/// Selector-31 recovery is terminal when a Q1/Q2 correlation was active: no
/// replacement may inherit the poisoned state.  Consume both root actors even
/// if only one delivered the triggering failure, then permanently retire their
/// controller reservations without relaunching either role.
#[cfg(feature = "dw1e3-selector31")]
fn finish_e3a_fatal_recovery<S, W>(
    resident: &mut ResidentSystemInit,
    system: &mut S,
    waits: &mut W,
    child_cleanup_failed: bool,
) -> Result<(), InitError>
where
    S: InitPlatform,
    W: SupervisionPlatform<Error = NativeError>,
{
    let (registry, devmgr) = {
        let state = resident
            .wyr1c
            .as_mut()
            .ok_or(InitError::AbsentState(0x3a))?;
        let registry = state.registry.take();
        let devmgr = state.devmgr.take();
        state.binding = None;
        state.waiting_registry_observed = false;
        (registry, devmgr)
    };
    resident.active[0] = None;
    resident.active[1] = None;
    // A child probe/driver failure remains fatal even when both root roles
    // subsequently terminate and reap cleanly. Do not erase the originating
    // cleanup failure while consuming the root actors.
    let mut cleanup_failed = child_cleanup_failed;
    if let Some(devmgr) = devmgr {
        cleanup_failed |=
            cleanup_loaded(system, waits, devmgr.loaded, devmgr.task_group, true).is_err();
        cleanup_failed |= resident
            .controller
            .retire_attempt_after_fatal(RoleId::Devmgr)
            .is_err();
    }
    if let Some(registry) = registry {
        cleanup_failed |= cleanup_loaded(
            system,
            waits,
            registry.active.loaded,
            registry.active.task_group,
            true,
        )
        .is_err();
        cleanup_failed |= system.close_handle(registry.control_channel).is_err();
        cleanup_failed |= resident
            .controller
            .retire_attempt_after_fatal(RoleId::Registryd)
            .is_err();
    }
    resident.controller.fatal();
    resident.result = RecoveryResult::Fatal;
    if cleanup_failed {
        Err(InitError::Cleanup)
    } else {
        Ok(())
    }
}

/// A probe channel close or process exit is never a normal lifecycle edge.
/// Take both owned lifetimes down before returning failure so neither a stale
/// reporter nor a surviving driver can later advance the selector.
#[cfg(feature = "dw1e3-selector31")]
fn fail_e3a_probe_supervision<S, W>(
    resident: &mut ResidentSystemInit,
    system: &mut S,
    waits: &mut W,
    validate_exit: bool,
) -> Result<(), InitError>
where
    S: InitPlatform,
    W: SupervisionPlatform<Error = NativeError>,
{
    let exit_error = if validate_exit {
        let probe = resident
            .wyr1c
            .as_ref()
            .and_then(|state| state.e3a_probe)
            .ok_or(InitError::AbsentState(0x3b))?;
        match waits.query_task_termination(probe.loaded.process) {
            Ok(exit) => wyrmroot_runtime::validate_successful_exit(&exit)
                .map_err(|_| InitError::WrongManifestProfile)
                .err(),
            Err(error) => Some(InitError::Native(error)),
        }
    } else {
        None
    };
    let probe_cleanup = reap_e3a_probe(resident, system, waits, false);
    let driver_cleanup = reap_driver(resident, system, waits, true);
    if probe_cleanup.is_err() || driver_cleanup.is_err() {
        Err(InitError::Cleanup)
    } else {
        Err(exit_error.unwrap_or(InitError::WrongManifestProfile))
    }
}

#[cfg(any(
    feature = "wyr1c6-production",
    feature = "dw1e3-selector31",
    feature = "wyr1d-selector32"
))]
fn acknowledge_driver_reaped<S: InitPlatform>(
    system: &mut S,
    devmgr: ActiveNativeRole,
    request: DriverLaunchRequest,
) -> Result<(), InitError> {
    let mut bytes = [0u8; wyrmroot_device_proto::driver_launch::REAPED_RESPONSE_BYTES];
    encode_reaped(request, &mut bytes).map_err(|_| InitError::WrongManifestProfile)?;
    system
        .send_channel(devmgr.loaded.launch_channel, &bytes)
        .map_err(InitError::Native)
}

fn expect_device_status<S, W>(
    system: &mut S,
    waits: &mut W,
    devmgr: ActiveNativeRole,
    binding: wyrmroot_device_proto::RegistryBinding,
    transaction_id: u64,
    expected_status: StatusCode,
    deadline_cap: Option<u64>,
) -> Result<(), InitError>
where
    S: InitPlatform,
    W: SupervisionPlatform<Error = NativeError>,
{
    let now = system.now().map_err(InitError::Native)?;
    if deadline_cap.is_some_and(|deadline| now >= deadline) {
        return Err(InitError::Supervision);
    }
    let deadline = now
        .checked_add(WYR0_I_SUPERVISION_POLICY.ready_timeout_ns)
        .ok_or(InitError::Accounting)?;
    let deadline = deadline_cap.map_or(deadline, |cap| deadline.min(cap));
    let observed = waits
        .wait_many(
            core::slice::from_ref(&DwWaitItemV1 {
                handle: devmgr.loaded.launch_channel,
                signals: DW_SIGNAL_READABLE,
            }),
            DwDeadline(deadline),
        )
        .map_err(InitError::Native)?;
    if observed.index != 0 || observed.observed.0 & DW_SIGNAL_READABLE.0 == 0 {
        return Err(InitError::Supervision);
    }
    let expected = ControllerMessage::Status {
        supervisor_generation: SupervisorGeneration(devmgr.generation),
        binding: Some(binding),
        transaction_id,
        status: expected_status,
        attempt_generation: None,
    };
    if receive_controller_status(system, devmgr.loaded.launch_channel)? != expected {
        return Err(InitError::WrongManifestProfile);
    }
    if let Some(deadline) = deadline_cap {
        let validated_at = system.now().map_err(InitError::Native)?;
        if validated_at >= deadline {
            return Err(InitError::Supervision);
        }
    }
    Ok(())
}

pub(crate) fn control_tick<S, L, W>(
    resident: &mut ResidentSystemInit,
    system: &mut S,
    loader: &mut L,
    waits: &mut W,
    now_ns: u64,
) -> Result<SystemMode, InitError>
where
    S: Wyr1BPlatform,
    L: LoaderPlatform<Error = NativeError>,
    W: SupervisionPlatform<Error = NativeError>,
{
    if now_ns < resident.last_tick_ns {
        resident.controller.fatal();
        resident.result = RecoveryResult::Fatal;
        return Err(InitError::WrongActivationOrder);
    }
    resident.last_tick_ns = now_ns;
    #[cfg(feature = "wyr1e-production")]
    wyr1e::ensure_recovery_live(resident, now_ns)?;
    let state = resident
        .wyr1c
        .as_ref()
        .ok_or(InitError::AbsentState(0x3c))?;
    let Some(devmgr) = state.devmgr else {
        resident.result = RecoveryResult::Degraded;
        return Ok(resident.controller.mode());
    };
    let mut items = [DwWaitItemV1::default(); 7];
    items[0] = DwWaitItemV1 {
        handle: devmgr.loaded.process,
        signals: DW_SIGNAL_EXITED,
    };
    items[1] = DwWaitItemV1 {
        handle: devmgr.loaded.launch_channel,
        signals: deepwyrm_syscall::DwSignals(DW_SIGNAL_READABLE.0 | DW_SIGNAL_PEER_CLOSED.0),
    };
    let registry_present = state.registry.is_some();
    let mut item_count = if let Some(registry) = state.registry {
        items[2] = DwWaitItemV1 {
            handle: registry.control_channel,
            signals: DW_SIGNAL_PEER_CLOSED,
        };
        items[3] = DwWaitItemV1 {
            handle: registry.active.loaded.process,
            signals: DW_SIGNAL_EXITED,
        };
        4
    } else {
        2
    };
    let driver_present = state.driver.is_some();
    if let Some(driver) = state.driver {
        items[item_count] = DwWaitItemV1 {
            handle: driver.loaded.process,
            signals: DW_SIGNAL_EXITED,
        };
        item_count += 1;
    }
    #[cfg(feature = "dw1e3-selector31")]
    if let Some(probe) = state.e3a_probe {
        items[item_count] = DwWaitItemV1 {
            handle: probe.loaded.launch_channel,
            signals: deepwyrm_syscall::DwSignals(DW_SIGNAL_READABLE.0 | DW_SIGNAL_PEER_CLOSED.0),
        };
        item_count += 1;
        items[item_count] = DwWaitItemV1 {
            handle: probe.loaded.process,
            signals: DW_SIGNAL_EXITED,
        };
        item_count += 1;
    }
    let observed = system.wait_many(&items[..item_count], DwDeadline(now_ns));
    match observed {
        Err(NativeError::Status(status)) if status == DW_STATUS_TIMED_OUT => {}
        Err(error) => return Err(InitError::Native(error)),
        Ok(result) => {
            let event = classify_resident_poll(
                result,
                registry_present,
                driver_present,
                #[cfg(feature = "dw1e3-selector31")]
                state.e3a_probe.is_some(),
            )?;
            let size = system
                .query_memory_object_size(resident.authority.bootfs)
                .map_err(InitError::Native)?;
            let plan = MappingPlan::for_bootfs(size).map_err(|error| {
                ordinary_mapping_error(MappingDiagnosticSite::RegistryReplacement, error, size)
            })?;
            system
                .with_bootfs_bytes(
                    resident.authority.parent_root,
                    resident.authority.bootfs,
                    plan,
                    |system, bootfs| match event {
                        ResidentPollEvent::DevmgrExited | ResidentPollEvent::DevmgrControlLost => {
                            recover_devmgr(resident, system, loader, waits, bootfs)
                        }
                        ResidentPollEvent::DevmgrControlReadable => {
                            let state = resident
                                .wyr1c
                                .as_ref()
                                .ok_or(InitError::AbsentState(0x3d))?;
                            let devmgr = state.devmgr.ok_or(InitError::AbsentState(0x3e))?;
                            match receive_devmgr_control(system, devmgr.loaded.launch_channel) {
                                #[cfg(feature = "wyr1d-selector32")]
                                Ok(DevmgrControlInput::D5Ready(identity)) => {
                                    selector32::driver_ready(
                                        resident, system, loader, waits, bootfs, identity,
                                    )
                                }
                                #[cfg(feature = "wyr1d-selector32")]
                                Ok(DevmgrControlInput::D5TxDrained(identity)) => {
                                    selector32::tx_drained(resident, system, identity)
                                }
                                #[cfg(feature = "dw1e3-selector31")]
                                Ok(DevmgrControlInput::TransportEmpty(fact)) => {
                                    let binding = resident
                                        .wyr1c
                                        .as_ref()
                                        .and_then(|state| state.e3a_binding)
                                        .ok_or(InitError::AbsentState(0x3f))?;
                                    let duplicate = resident
                                        .wyr1c
                                        .as_ref()
                                        .ok_or(InitError::AbsentState(0x40))?
                                        .e3a_transport_empty
                                        .is_some();
                                    if duplicate {
                                        return Err(InitError::WrongManifestProfile);
                                    }
                                    exact_transport_empty(binding, fact)?;
                                    resident
                                        .wyr1c
                                        .as_mut()
                                        .ok_or(InitError::AbsentState(0x41))?
                                        .e3a_transport_empty = Some(fact);
                                    maybe_begin_e3a_retire(resident, system)
                                }
                                #[cfg(feature = "dw1e3-selector31")]
                                Ok(DevmgrControlInput::BindingReady(_binding)) => {
                                    Err(InitError::WrongManifestProfile)
                                }
                                #[cfg(feature = "dw1e3-selector31")]
                                Ok(DevmgrControlInput::RetireStage1Ready(binding)) => {
                                    let state = resident
                                        .wyr1c
                                        .as_mut()
                                        .ok_or(InitError::AbsentState(0x42))?;
                                    if !state.e3a_begin_retire_sent
                                        || state.e3a_stage1_ready
                                        || state.e3a_binding != Some(binding)
                                    {
                                        return Err(InitError::WrongManifestProfile);
                                    }
                                    state.e3a_stage1_ready = true;
                                    // The probe's peer-close report and devmgr's
                                    // stage-1 relay travel over independent
                                    // channels. Rejoin the exact facts here as
                                    // well as in the peer-close branch so either
                                    // valid arrival order can release U1.
                                    send_e3a_finalize_retire(resident, system)
                                }
                                #[cfg(feature = "wyr1c6-selector29")]
                                Ok(DevmgrControlInput::C6Fact(fact)) => {
                                    accept_c6_fact(resident, fact)
                                }
                                Ok(DevmgrControlInput::Status(message)) => {
                                    let duplicate =
                                        state.registry.is_none() && state.waiting_registry_observed;
                                    let expected = ControllerMessage::Status {
                                        supervisor_generation: SupervisorGeneration(
                                            devmgr.generation,
                                        ),
                                        binding: None,
                                        transaction_id: state.last_controller_transaction,
                                        status: StatusCode::OperationalWaitingForRegistry,
                                        attempt_generation: None,
                                    };
                                    if duplicate || message != expected {
                                        return recover_devmgr_after_error(
                                            resident,
                                            system,
                                            loader,
                                            waits,
                                            bootfs,
                                            InitError::WrongManifestProfile,
                                        );
                                    }
                                    if state.registry.is_some() {
                                        recover_registry(
                                            resident,
                                            system,
                                            loader,
                                            waits,
                                            bootfs,
                                            true,
                                            false,
                                            abandoned::reason(
                                                abandoned::trigger::DEVMGR_WAITING,
                                                abandoned::phase::NONE,
                                            ),
                                        )
                                    } else {
                                        resident
                                            .wyr1c
                                            .as_mut()
                                            .ok_or(InitError::AbsentState(0x43))?
                                            .waiting_registry_observed = true;
                                        Ok(())
                                    }
                                }
                                Ok(DevmgrControlInput::DriverLaunch {
                                    request,
                                    child_endpoint,
                                }) => {
                                    if let Err(error) = construct_driver(
                                        resident,
                                        system,
                                        loader,
                                        waits,
                                        bootfs,
                                        devmgr,
                                        request,
                                        child_endpoint,
                                    ) {
                                        recover_devmgr_after_error(
                                            resident, system, loader, waits, bootfs, error,
                                        )
                                    } else {
                                        #[cfg(feature = "wyr1e-production")]
                                        start_wyr1e_or_recover_registry(
                                            resident, system, loader, waits, bootfs,
                                        )?;
                                        #[cfg(feature = "dw1e3-selector31")]
                                        {
                                            start_e3a_probe(resident, system, loader, waits, bootfs)
                                        }
                                        #[cfg(not(feature = "dw1e3-selector31"))]
                                        {
                                            Ok(())
                                        }
                                    }
                                }
                                Ok(DevmgrControlInput::DriverRetired { bytes }) => {
                                    #[cfg(any(
                                        feature = "wyr1c6-production",
                                        feature = "dw1e3-selector31",
                                        feature = "wyr1d-selector32"
                                    ))]
                                    {
                                        let retired = (|| {
                                            let state = resident
                                                .wyr1c
                                                .as_ref()
                                                .ok_or(InitError::AbsentState(0x44))?;
                                            let request = state
                                                .last_reaped_driver
                                                .ok_or(InitError::AbsentState(0x45))?;
                                            parse_driver_retired(&bytes, request)
                                                .map_err(|_| InitError::WrongManifestProfile)?;
                                            #[cfg(feature = "wyr1d-selector32")]
                                            return selector32::observe_driver_retired(
                                                resident, request,
                                            );
                                            #[cfg(not(feature = "wyr1d-selector32"))]
                                            {
                                                let rebound = rebind_publication(
                                                    resident,
                                                    system,
                                                    waits,
                                                    PublicationRebindContext::DriverRetirement,
                                                );
                                                attribute_failure(
                                                    RecoveryOperation::RebindPublication,
                                                    rebound,
                                                )
                                            }
                                        })();
                                        attribute_failure(RecoveryOperation::DriverRetired, retired)
                                    }
                                    #[cfg(not(any(
                                        feature = "wyr1c6-production",
                                        feature = "dw1e3-selector31",
                                        feature = "wyr1d-selector32"
                                    )))]
                                    {
                                        let _ = bytes;
                                        Err(InitError::WrongManifestProfile)
                                    }
                                }
                                Err(error) => recover_devmgr_after_error(
                                    resident, system, loader, waits, bootfs, error,
                                ),
                            }
                        }
                        ResidentPollEvent::RegistryControlLost => recover_registry(
                            resident,
                            system,
                            loader,
                            waits,
                            bootfs,
                            false,
                            false,
                            abandoned::reason(
                                abandoned::trigger::CONTROL_LOST,
                                abandoned::phase::NONE,
                            ),
                        ),
                        ResidentPollEvent::RegistryExited => recover_registry(
                            resident,
                            system,
                            loader,
                            waits,
                            bootfs,
                            false,
                            false,
                            abandoned::reason(abandoned::trigger::EXITED, abandoned::phase::NONE),
                        ),
                        ResidentPollEvent::DriverExited => {
                            #[cfg(feature = "dw1e3-selector31")]
                            if let Err(error) = validate_e3a_u1_finalize_exit(resident, waits) {
                                let driver_cleanup = reap_driver(resident, system, waits, false);
                                let probe_cleanup = reap_e3a_probe(resident, system, waits, false);
                                return Err(if driver_cleanup.is_err() || probe_cleanup.is_err() {
                                    InitError::Cleanup
                                } else {
                                    error
                                });
                            }
                            #[cfg(feature = "wyr1e-production")]
                            let dependent_retirement =
                                wyr1e::retire_dependents(resident, system, waits, false);
                            #[cfg(all(
                                feature = "wyr1e-production",
                                feature = "wyr1e8-selector33"
                            ))]
                            let dependent_retirement = attribute_failure(
                                RecoveryOperation::RetireDependents,
                                dependent_retirement,
                            );
                            #[cfg(feature = "wyr1e-production")]
                            dependent_retirement?;
                            #[cfg(feature = "wyr1e8-selector33")]
                            let _request = {
                                let deadline = wyr1e::recovery_deadline(resident)?;
                                reap_driver_before(resident, system, waits, false, deadline)
                            };
                            #[cfg(not(feature = "wyr1e8-selector33"))]
                            let _request = reap_driver(resident, system, waits, false);
                            let _request =
                                attribute_failure(RecoveryOperation::ReapDriver, _request)?;
                            #[cfg(feature = "wyr1e-production")]
                            {
                                wyr1e::ensure_recovery_live(
                                    resident,
                                    system.now().map_err(InitError::Native)?,
                                )?;
                                let acknowledged = (|| {
                                    let state = resident
                                        .wyr1c
                                        .as_ref()
                                        .ok_or(InitError::AbsentState(0x46))?;
                                    let devmgr =
                                        state.devmgr.ok_or(InitError::AbsentState(0x47))?;
                                    acknowledge_driver_reaped(system, devmgr, _request)
                                })();
                                let acknowledged = attribute_failure(
                                    RecoveryOperation::AcknowledgeReaped,
                                    acknowledged,
                                );
                                acknowledged?;
                                wyr1e::ensure_recovery_live(
                                    resident,
                                    system.now().map_err(InitError::Native)?,
                                )?;
                                Ok(())
                            }
                            #[cfg(not(feature = "wyr1e-production"))]
                            {
                                #[cfg(feature = "dw1e3-selector31")]
                                reap_e3a_probe(resident, system, waits, true)?;
                                #[cfg(any(
                                    feature = "wyr1c6-production",
                                    feature = "dw1e3-selector31",
                                    feature = "wyr1d-selector32"
                                ))]
                                {
                                    let state = resident
                                        .wyr1c
                                        .as_ref()
                                        .ok_or(InitError::AbsentState(0x48))?;
                                    let devmgr =
                                        state.devmgr.ok_or(InitError::AbsentState(0x49))?;
                                    acknowledge_driver_reaped(system, devmgr, _request)?;
                                }
                                Ok(())
                            }
                        }
                        #[cfg(feature = "dw1e3-selector31")]
                        ResidentPollEvent::ProbeControlReadable => {
                            let message = receive_e3a_probe_message(resident, system)?;
                            let binding = resident
                                .wyr1c
                                .as_ref()
                                .and_then(|state| state.e3a_binding)
                                .ok_or(InitError::AbsentState(0x4a))?;
                            match message {
                                E3AControllerMessage::ResponseCommitted {
                                    nonce,
                                    publication_generation,
                                    stream_generation,
                                    challenge_generation,
                                    response_length,
                                    response_hash,
                                } => {
                                    let (expected_length, expected_hash) =
                                        exact_e3a_response(binding)?;
                                    let state = resident
                                        .wyr1c
                                        .as_mut()
                                        .ok_or(InitError::AbsentState(0x4b))?;
                                    if state.e3a_response_committed
                                        || nonce != binding.nonce
                                        || publication_generation != binding.publication_generation
                                        || stream_generation != binding.stream_generation
                                        || challenge_generation != binding.challenge_generation
                                        || response_length != expected_length
                                        || response_hash != expected_hash
                                    {
                                        return Err(InitError::WrongManifestProfile);
                                    }
                                    state.e3a_response_committed = true;
                                    maybe_begin_e3a_retire(resident, system)
                                }
                                E3AControllerMessage::StreamPeerClosed {
                                    nonce,
                                    publication_generation,
                                    stream_generation,
                                    challenge_generation,
                                } => {
                                    let state = resident
                                        .wyr1c
                                        .as_ref()
                                        .ok_or(InitError::AbsentState(0x4c))?;
                                    if !state.e3a_response_committed
                                        || state.e3a_peer_closed
                                        || nonce != binding.nonce
                                        || publication_generation != binding.publication_generation
                                        || stream_generation != binding.stream_generation
                                        || challenge_generation != binding.challenge_generation
                                    {
                                        return Err(InitError::WrongManifestProfile);
                                    }
                                    wyrmroot_runtime::dw1e3_report(
                                        wyrmroot_runtime::Dw1e3ReportEvent::Driver1PeerClosed,
                                        stream_generation,
                                        0,
                                        nonce,
                                    )
                                    .map_err(InitError::Native)?;
                                    resident
                                        .wyr1c
                                        .as_mut()
                                        .ok_or(InitError::AbsentState(0x4d))?
                                        .e3a_peer_closed = true;
                                    send_e3a_finalize_retire(resident, system)
                                }
                                _ => Err(InitError::WrongManifestProfile),
                            }
                        }
                        #[cfg(feature = "dw1e3-selector31")]
                        ResidentPollEvent::ProbeControlLost => {
                            if e3a_u2_probe_may_exit(resident) {
                                match reap_e3a_u2_probe_after_response(resident, system, waits) {
                                    Ok(()) => Ok(()),
                                    Err(error) => {
                                        fail_e3a_u2_probe_exit(resident, system, waits, error)
                                    }
                                }
                            } else {
                                fail_e3a_probe_supervision(resident, system, waits, false)
                            }
                        }
                        #[cfg(feature = "dw1e3-selector31")]
                        ResidentPollEvent::ProbeExited => {
                            if e3a_u2_probe_may_exit(resident) {
                                match reap_e3a_u2_probe_after_response(resident, system, waits) {
                                    Ok(()) => Ok(()),
                                    Err(error) => {
                                        fail_e3a_u2_probe_exit(resident, system, waits, error)
                                    }
                                }
                            } else {
                                fail_e3a_probe_supervision(resident, system, waits, true)
                            }
                        }
                    },
                )
                .map_err(InitError::Native)??;
        }
    }
    #[cfg(feature = "wyr1d-selector32")]
    {
        selector32::poll(resident, system, loader, waits, now_ns)?;
        if selector32::claim_publication_rebind(resident, system.now().map_err(InitError::Native)?)?
        {
            rebind_publication(
                resident,
                system,
                waits,
                PublicationRebindContext::DriverRetirement,
            )?;
        }
    }
    #[cfg(feature = "wyr1e-production")]
    {
        let outcome = wyr1e::poll(resident, system, loader, waits, now_ns)?;
        #[cfg(feature = "wyr1f-closure")]
        let outcome = wyr1f_closure_trigger(resident, outcome);
        // F3A.7g. Handled before the recovery dispatch below, and outside the
        // bootfs mapping it opens: every other non-`Stable` outcome rebuilds
        // something out of the archive, and this one builds nothing. The
        // console is already retired; all that is left is to say so.
        if outcome == wyr1e::PollOutcome::SessionComplete {
            resident.observe_session_complete();
            return Ok(resident.controller.mode());
        }
        if outcome != wyr1e::PollOutcome::Stable {
            if matches!(
                outcome,
                wyr1e::PollOutcome::RecoverDevmgr | wyr1e::PollOutcome::RecoverRegistry(_)
            ) && wyr1e::recovery_deadline(resident)?.is_some()
            {
                return attribute_failure(
                    RecoveryOperation::RecoveryFallback,
                    Err(InitError::Supervision),
                );
            }
            let size = system
                .query_memory_object_size(resident.authority.bootfs)
                .map_err(InitError::Native)?;
            let plan = MappingPlan::for_bootfs(size).map_err(|error| {
                ordinary_mapping_error(MappingDiagnosticSite::RegistryReplacement, error, size)
            })?;
            return system
                .with_bootfs_bytes(
                    resident.authority.parent_root,
                    resident.authority.bootfs,
                    plan,
                    |system, bootfs| {
                        match outcome {
                            // Both are unreachable here: `Stable` does not
                            // enter this block and `SessionComplete` returned
                            // above. Neither is collapsed into the other, so a
                            // future outcome cannot inherit a recovery arm by
                            // accident.
                            wyr1e::PollOutcome::Stable | wyr1e::PollOutcome::SessionComplete => {
                                Ok(())
                            }
                            wyr1e::PollOutcome::LaunchConsole => {
                                let launched = wyr1e::launch_after_publication_observed(
                                    resident, system, loader, waits, bootfs,
                                );
                                attribute_failure(RecoveryOperation::StartConsole, launched)
                            }
                            wyr1e::PollOutcome::RecoverDevmgr => {
                                recover_devmgr(resident, system, loader, waits, bootfs)
                            }
                            wyr1e::PollOutcome::RecoverRegistry(phase) => recover_registry(
                                resident,
                                system,
                                loader,
                                waits,
                                bootfs,
                                false,
                                false,
                                abandoned::reason(abandoned::trigger::WYR1E_POLL, phase),
                            ),
                            #[cfg(feature = "wyr1e8-selector33")]
                            wyr1e::PollOutcome::RecoverRegistryForE8 => recover_registry(
                                resident,
                                system,
                                loader,
                                waits,
                                bootfs,
                                false,
                                true,
                                abandoned::reason(
                                    abandoned::trigger::WYR1E_POLL_E8,
                                    abandoned::phase::NONE,
                                ),
                            ),
                        }?;
                        Ok(resident.controller.mode())
                    },
                )
                .map_err(InitError::Native)?;
        }
    }
    Ok(resident.controller.mode())
}

/// Delivers the one declared final-closure trigger, and closes the episode
/// when the supervisor reaches its own terminal result.
///
/// It substitutes exactly the `RecoverDevmgr` outcome that a real
/// publication-observer failure produces, and only on an otherwise `Stable`
/// poll, so it never overrides a recovery the supervisor already wants. Every
/// transition, retry, deadline and mode change after that is `SystemInit`'s.
#[cfg(feature = "wyr1f-closure")]
fn wyr1f_closure_trigger(
    resident: &mut ResidentSystemInit,
    outcome: wyr1e::PollOutcome,
) -> wyr1e::PollOutcome {
    if resident.controller.mode() == SystemMode::Degraded {
        resident.wyr1f.observe_terminal();
    }
    if outcome != wyr1e::PollOutcome::Stable {
        return outcome;
    }
    let (console_ready, shell_ready) = wyr1e::wyr1f_ready_join(resident);
    resident
        .wyr1f
        .observe_ready_join(console_ready, shell_ready);
    if resident.wyr1f.take_trigger() {
        return wyr1e::PollOutcome::RecoverDevmgr;
    }
    outcome
}

#[allow(clippy::too_many_arguments)]
fn recover_registry<S, L, W>(
    resident: &mut ResidentSystemInit,
    system: &mut S,
    loader: &mut L,
    waits: &mut W,
    bootfs: &[u8],
    status_already_consumed: bool,
    _e8_quiesced: bool,
    reason: u8,
) -> Result<(), InitError>
where
    S: Wyr1BPlatform,
    L: LoaderPlatform<Error = NativeError>,
    W: SupervisionPlatform<Error = NativeError>,
{
    // Only a build whose `poll` reads the registry slot reports the reason,
    // so only that build consumes the trigger. Every caller still names one.
    #[cfg(not(feature = "wyr1e-production"))]
    let _ = reason;
    // The recovery episode lives on the wyr1e console/shell supervisor, so
    // a build without that product has no episode rather than no concept of
    // one. The gate is the product, not a selector.
    #[cfg(feature = "wyr1e-production")]
    let action_deadline = wyr1e::recovery_deadline(resident)?;
    #[cfg(not(feature = "wyr1e-production"))]
    let action_deadline = None;
    #[cfg(feature = "wyr1e8-selector33")]
    if action_deadline.is_some() && !_e8_quiesced {
        return Err(InitError::Supervision);
    }
    #[cfg(feature = "wyr1e-production")]
    if action_deadline.is_some() {
        wyr1e::ensure_recovery_live(resident, system.now().map_err(InitError::Native)?)?;
    }
    #[cfg(feature = "dw1e3-selector31")]
    if let Some(child_cleanup_failed) = fail_closed_e3a_recovery(resident, system, waits) {
        return finish_e3a_fatal_recovery(resident, system, waits, child_cleanup_failed);
    }
    // Four arms for one fact, and two of them threw the cause away: outside
    // the selector this was a bare `bool`, so a dependent retirement that
    // failed said so without saying why. One `Option<InitError>` now, under
    // the product gate that actually has dependents.
    #[cfg(feature = "wyr1e-production")]
    let dependent_cleanup_error = attribute_failure(
        RecoveryOperation::RetireDependents,
        wyr1e::retire_dependents(resident, system, waits, true),
    )
    .err();
    #[cfg(not(feature = "wyr1e-production"))]
    let dependent_cleanup_error: Option<InitError> = None;
    let registry = resident
        .wyr1c
        .as_mut()
        .ok_or(InitError::AbsentState(0x4e))?
        .registry
        .take()
        .ok_or(InitError::AbsentState(0x4f))?;
    resident.active[0] = None;
    resident
        .wyr1c
        .as_mut()
        .ok_or(InitError::AbsentState(0x50))?
        .binding = None;
    let exhausted = if action_deadline.is_some() && dependent_cleanup_error.is_none() {
        // The authenticated, exactly quiesced action admits a fresh finite
        // episode only after dependent retirement succeeds. Ordinary failures
        // keep the boot-anchored episode, even after a long healthy lifetime.
        retire_registry_for_recovery_before(
            system,
            waits,
            &mut resident.controller,
            registry,
            action_deadline,
        )
    } else {
        poison_registry_generation_before(
            system,
            waits,
            &mut resident.controller,
            registry,
            dependent_cleanup_error.is_some(),
            action_deadline,
        )
    };
    let exhausted = attribute_failure(RecoveryOperation::RetireRegistry, exhausted);
    if let Some(error) = dependent_cleanup_error {
        return if exhausted.is_err() {
            attribute_failure(RecoveryOperation::RetireRegistry, Err(InitError::Cleanup))
        } else {
            Err(error)
        };
    }
    let exhausted = exhausted?;
    let step = registry_recovery_step(exhausted, status_already_consumed);
    match step {
        RegistryRecoveryStep::Degraded => {
            resident.result = RecoveryResult::Degraded;
            if action_deadline.is_some() {
                return attribute_failure(
                    RecoveryOperation::RetireRegistry,
                    Err(InitError::Cleanup),
                );
            }
            // F3A.6f. `state.registry` and `state.binding` were emptied above
            // and nothing was installed, so a build whose `poll` reads that
            // slot cannot continue; see `InitError::RegistryAbandoned`.
            #[cfg(feature = "wyr1e-production")]
            return attribute_failure(
                RecoveryOperation::RetireRegistry,
                Err(InitError::RegistryAbandoned(reason)),
            );
            #[cfg(not(feature = "wyr1e-production"))]
            return Ok(());
        }
        RegistryRecoveryStep::Restart | RegistryRecoveryStep::AwaitStatus => {}
    }
    #[cfg(feature = "wyr1e-production")]
    if action_deadline.is_some() {
        wyr1e::ensure_recovery_live(resident, system.now().map_err(InitError::Native)?)?;
    }
    let replacement = launch_registry_until_ready_before(
        system,
        loader,
        waits,
        &mut resident.controller,
        resident.authority,
        bootfs,
        action_deadline,
    );
    let replacement = attribute_failure(RecoveryOperation::LaunchRegistry, replacement)?;
    let Some(replacement) = replacement else {
        resident.result = RecoveryResult::Degraded;
        if action_deadline.is_some() {
            return attribute_failure(
                RecoveryOperation::LaunchRegistry,
                Err(InitError::Supervision),
            );
        }
        // F3A.6f, the second of the two exits. Same reasoning as the
        // `Degraded` step above: emptied, nothing installed, terminal where a
        // `poll` depends on it.
        #[cfg(feature = "wyr1e-production")]
        return attribute_failure(
            RecoveryOperation::LaunchRegistry,
            Err(InitError::RegistryAbandoned(reason)),
        );
        #[cfg(not(feature = "wyr1e-production"))]
        return Ok(());
    };
    #[cfg(feature = "wyr1e-production")]
    if action_deadline.is_some()
        && let Err(error) =
            wyr1e::ensure_recovery_live(resident, system.now().map_err(InitError::Native)?)
    {
        let cleanup = poison_registry_generation_before(
            system,
            waits,
            &mut resident.controller,
            replacement,
            false,
            action_deadline,
        );
        return if cleanup.is_err() {
            let failed: Result<(), InitError> = Err(InitError::Cleanup);
            // Which leg failed is class C of the R7A inventory, so the tag
            // stays selector-gated while the deadline check above does not.
            attribute_failure(RecoveryOperation::LaunchRegistry, failed)
        } else {
            Err(error)
        };
    }
    #[cfg(feature = "wyr1e-production")]
    {
        let reserved = wyr1e::reserve_registry_replacement(resident, replacement.active.generation);
        let reserved = attribute_failure(RecoveryOperation::CommitRegistry, reserved);
        reserved?;
    }
    let replacement = restart_topology_or_poison_before(
        system,
        waits,
        &mut resident.controller,
        &mut resident
            .wyr1c
            .as_mut()
            .ok_or(InitError::AbsentState(0x51))?
            .topology,
        replacement,
        action_deadline,
    );
    let replacement = attribute_failure(RecoveryOperation::CommitRegistry, replacement);
    let replacement = replacement?;
    #[cfg(feature = "wyr1e-production")]
    {
        let committed = wyr1e::commit_registry_replacement(resident, replacement.active.generation);
        let committed = attribute_failure(RecoveryOperation::CommitRegistry, committed);
        committed?;
    }
    resident
        .wyr1c
        .as_mut()
        .ok_or(InitError::AbsentState(0x52))?
        .registry = Some(replacement);
    resident.active[0] = Some(replacement.active);
    if step == RegistryRecoveryStep::AwaitStatus {
        let state = resident
            .wyr1c
            .as_ref()
            .ok_or(InitError::AbsentState(0x53))?;
        let devmgr = state.devmgr.ok_or(InitError::AbsentState(0x54))?;
        let waiting = await_waiting_for_registry(
            system,
            waits,
            devmgr,
            devmgr.generation,
            state.last_controller_transaction,
            action_deadline,
        );
        let waiting = attribute_failure(RecoveryOperation::RebindPublication, waiting);
        if let Err(error) = waiting {
            return recover_devmgr_after_error(resident, system, loader, waits, bootfs, error);
        }
    }
    resident
        .wyr1c
        .as_mut()
        .ok_or(InitError::AbsentState(0x55))?
        .waiting_registry_observed = true;
    let rebound = rebind_publication(
        resident,
        system,
        waits,
        PublicationRebindContext::RegistryRecovery,
    );
    let rebound = attribute_failure(RecoveryOperation::RebindPublication, rebound);
    if let Err(error) = rebound {
        return recover_devmgr_after_error(resident, system, loader, waits, bootfs, error);
    }
    #[cfg(feature = "wyr1e-production")]
    if resident
        .wyr1c
        .as_ref()
        .is_some_and(|state| state.driver.is_some())
    {
        let started = start_wyr1e_or_recover_registry(resident, system, loader, waits, bootfs);
        let started = attribute_failure(RecoveryOperation::StartConsole, started);
        started?;
    }
    Ok(())
}

#[cfg(all(test, feature = "wyr1e-production"))]
pub(crate) const E8_REGISTRY_FIXTURE_DEVMGR_CONTROL: DwHandle = DwHandle(0xE8B5_0021);
#[cfg(all(test, feature = "wyr1e-production"))]
pub(crate) const E8_REGISTRY_FIXTURE_DRIVER_PROCESS: DwHandle = DwHandle(0xE8B5_0030);

#[cfg(all(test, feature = "wyr1e8-selector33"))]
pub(crate) struct E8RegistryRecoveryFixtureResult {
    pub(crate) shell: ShellControllerState,
    pub(crate) jobs: JobDispatcher,
    pub(crate) topology: RegistryTopology,
    pub(crate) registry_generation: u64,
    pub(crate) publication_generation: u64,
}

#[cfg(all(test, feature = "wyr1e-production"))]
fn install_e8_registry_fixture_role(
    controller: &mut SystemInit,
    role: RoleId,
    generation: u64,
    transaction_id: u64,
    executable_identity: [u8; 32],
    startup_profile: StartupProfile,
    loaded: LoadedProcess,
    task_group: DwHandle,
    started_at: u64,
) -> Result<ActiveNativeRole, InitError> {
    let reservation = controller.reserve_attempt(role, generation, transaction_id)?;
    controller.install_attempt(AttemptResources {
        role,
        generation,
        transaction_id,
        executable_identity,
        startup_profile,
        task_group,
        process: loaded.process,
        launch_channel: loaded.launch_channel,
        mappings: 0,
        reservation,
    })?;
    controller.child_started(role, generation, transaction_id, started_at)?;
    controller.ready(role, generation, transaction_id, started_at + 1)?;
    Ok(ActiveNativeRole {
        role,
        generation,
        transaction_id,
        loaded,
        task_group,
    })
}

/// The resident a recovery fixture starts from: an operational controller with
/// a live registry, devmgr and driver, and one registry binding.
///
/// Reset card R7E. This was the opening half of the E8 orchestrator bridge,
/// and that made the E8 mega-fixture the only host test in the tree that
/// reached `recover_registry`, `recover_devmgr` or `recover_devmgr_after_error`
/// at all -- measured by probe, not assumed. The resident is ordinary; only
/// the `e6` state its caller supplies decides whether an episode is open, so
/// the product path can be driven without a shell, a trigger or a barrier.
#[cfg(all(test, feature = "wyr1e-production"))]
fn recovery_fixture_resident(
    registry_identity: [u8; 32],
    registry_generation: u64,
    e6: wyr1e::State,
    topology: RegistryTopology,
    driver_request: Option<DriverLaunchRequest>,
) -> Result<
    (
        ResidentSystemInit,
        ActiveNativeRole,
        Option<DriverNativeAttempt>,
    ),
    InitError,
> {
    const REGISTRY_TRANSACTION: u64 = 0xE8B5_0001;
    const LAST_CONTROLLER_TRANSACTION: u64 = 9;
    const NEXT_CONTROLLER_TRANSACTION: u64 = 10;
    let devmgr_identity = [0xD5; 32];
    let mut controller = SystemInit {
        mode: SystemMode::Bootstrap,
        roles: [
            RoleController::new(RoleId::Registryd, registry_identity)?,
            RoleController::new(RoleId::Devmgr, devmgr_identity)?,
        ],
        degraded_transitions: 0,
        activated: [false; EARLY_ROLE_COUNT],
        accounting: AttemptLedger::new(),
        gate: None,
        evidence: None,
        registry_startup_profile: StartupProfile::BootstrapRegistry,
        devmgr_startup_profile: StartupProfile::DeviceCoordinator,
    };
    controller.become_operational()?;
    controller.begin_registry(1, registry_generation, REGISTRY_TRANSACTION)?;
    let registry_active = install_e8_registry_fixture_role(
        &mut controller,
        RoleId::Registryd,
        registry_generation,
        REGISTRY_TRANSACTION,
        registry_identity,
        StartupProfile::BootstrapRegistry,
        LoadedProcess {
            process: DwHandle(0xE8B5_0011),
            launch_channel: DwHandle(0xE8B5_0012),
        },
        DwHandle(0xE8B5_0013),
        2,
    )?;
    let devmgr_transaction = REGISTRY_TRANSACTION + 1;
    let devmgr = install_e8_registry_fixture_role(
        &mut controller,
        RoleId::Devmgr,
        registry_generation,
        devmgr_transaction,
        devmgr_identity,
        StartupProfile::DeviceCoordinator,
        LoadedProcess {
            process: DwHandle(0xE8B5_0020),
            launch_channel: E8_REGISTRY_FIXTURE_DEVMGR_CONTROL,
        },
        DwHandle(0xE8B5_0022),
        4,
    )?;
    let registry = registry_native_attempt_for_fixture(registry_active, DwHandle(0xE8B5_0010), 3);
    let driver = driver_request.map(|request| DriverNativeAttempt {
        loaded: LoadedProcess {
            process: E8_REGISTRY_FIXTURE_DRIVER_PROCESS,
            launch_channel: DwHandle(0xE8B5_0031),
        },
        task_group: DwHandle(0xE8B5_0032),
        request,
    });
    let initial_binding = wyrmroot_device_proto::RegistryBinding {
        generation: RegistryGeneration(registry_generation),
        endpoint: RegistryEndpoint {
            id: RegistryEndpointId(1),
            generation: RegistryEndpointGeneration(1),
        },
    };
    let resident = ResidentSystemInit {
        controller,
        authority: LoadAuthority {
            parent_root: DwHandle(0xE8B5_0040),
            bootfs: DwHandle(0xE8B5_0041),
            task_group: DwHandle(0xE8B5_0042),
        },
        result: RecoveryResult::Recovered,
        active: [Some(registry_active), Some(devmgr)],
        evidence_finalized: false,
        session_complete: false,
        last_tick_ns: 0,
        wyr1b: None,
        wyr1b_evidence: None,
        #[cfg(feature = "wyr1f-closure")]
        wyr1f: crate::wyr1f_closure::ClosureEpisode::new(None),
        wyr1c: Some(ResidentState {
            e6: Some(e6),
            resource_domain: Some(ResourceDomainCustody::new(DwHandle(0xE8B5_0043))),
            registry: Some(registry),
            topology,
            devmgr: Some(devmgr),
            binding: Some(initial_binding),
            publication_service_generation: driver_request
                .map_or(1, |request| request.attempt_generation.0),
            waiting_registry_observed: false,
            publication_allocator: PublicationAllocator::new(),
            last_controller_transaction: LAST_CONTROLLER_TRANSACTION,
            next_controller_transaction: NEXT_CONTROLLER_TRANSACTION,
            driver,
            last_reaped_driver: None,
            last_driver_attempt: driver_request.map_or(0, |request| request.attempt_generation.0),
            last_driver_session: driver_request.map_or(0, |request| request.launch_session.0),
            last_driver_endpoint: driver_request.map_or(0, |request| request.endpoint.id.0),
            last_driver_transaction: driver_request.map_or(0, |request| request.transaction_id),
        }),
    };

    Ok((resident, devmgr, driver))
}

/// Drives the product's ordinary registry recovery with no episode open.
///
/// Reset card R7E. A probe over the whole host suite found that
/// `recover_registry`, `recover_devmgr` and `recover_devmgr_after_error` were
/// reached by exactly one test -- the E8 producer fixture -- and only through a
/// ShellJobs launch carrying a magic path and nonce. The *product's* recovery,
/// the one R7B-1 made ordinary by giving the episode a budget instead of a
/// selector, had no coverage at all.
///
/// This is that path: no trigger, no held WAIT, no shell. `recovery_deadline`
/// answers `None`, so the episode arithmetic the selector opens is simply not
/// entered, and what runs is registry retirement, relaunch, topology restart
/// and publication rebinding.
#[cfg(all(test, feature = "wyr1e-production"))]
pub(crate) fn exercise_ordinary_registry_recovery<S, L, W>(
    system: &mut S,
    loader: &mut L,
    waits: &mut W,
    bootfs: &[u8],
    registry_identity: [u8; 32],
    registry_generation: u64,
) -> Result<(RecoveryResult, u64, Option<RestartState>), InitError>
where
    S: Wyr1BPlatform,
    L: LoaderPlatform<Error = NativeError>,
    W: SupervisionPlatform<Error = NativeError>,
{
    let (mut resident, _devmgr, _driver) = recovery_fixture_resident(
        registry_identity,
        registry_generation,
        wyr1e::State::new(registry_generation)?,
        RegistryTopology::new(registry_generation).map_err(InitError::Wyr1BModel)?,
        None,
    )?;
    recover_registry(
        &mut resident,
        system,
        loader,
        waits,
        bootfs,
        false,
        false,
        abandoned::reason(abandoned::trigger::NONE, abandoned::phase::NONE),
    )?;
    let role = resident.controller.role_state(RoleId::Registryd);
    let state = resident
        .wyr1c
        .as_ref()
        .ok_or(InitError::AbsentState(0x56))?;
    Ok((resident.result, state.topology.generation(), role))
}

/// The driver request the closure fixture's retained driver was launched from.
#[cfg(all(test, feature = "wyr1f-closure"))]
pub(crate) fn wyr1f_fixture_driver_request() -> DriverLaunchRequest {
    DriverLaunchRequest {
        supervisor_generation: SupervisorGeneration(1),
        role_id: wyrmroot_device_proto::COM2_ROLE_ID,
        attempt_generation: wyrmroot_device_proto::coordinator::AttemptGeneration(1),
        launch_session: wyrmroot_device_proto::coordinator::LaunchSessionGeneration(2),
        endpoint: wyrmroot_device_proto::ControlEndpoint {
            id: wyrmroot_device_proto::coordinator::EndpointId(3),
            generation: wyrmroot_device_proto::coordinator::EndpointGeneration(1),
        },
        transaction_id: 9,
        driver_path: wyrmroot_device_proto::DEVICE_DRIVER_PATH,
        actor_identity: wyrmroot_device_proto::manifest::ContentIdentity([0x5a; 32]),
        child_is_channel: true,
        child_rights: wyrmroot_device_proto::DirectControlRights::ExactReduced,
    }
}

/// What one declared closure episode leaves behind.
#[cfg(all(test, feature = "wyr1f-closure"))]
#[derive(Debug)]
pub(crate) struct Wyr1fDegradedOutcome {
    pub(crate) result: RecoveryResult,
    pub(crate) mode: SystemMode,
    pub(crate) degraded_transitions: u8,
    pub(crate) console: Option<InstalledPeer>,
    pub(crate) driver_retained: bool,
    pub(crate) devmgr_state: Option<RestartState>,
    pub(crate) permanent_failure_records: usize,
    pub(crate) refuses_activation: bool,
}

/// Drives one declared closure episode through the production recovery path.
///
/// Nothing here is synthetic except the resident the episode starts from: the
/// trigger is taken through `wyr1f_closure_trigger`, and the consequence is
/// `recover_devmgr` and `launch_devmgr_replacement` exactly as the product
/// runs them. `DW1_WYR1_FINAL_CLOSURE_CONTRACT.md` §5.4 and §11 item 4.
#[cfg(all(test, feature = "wyr1f-closure"))]
#[allow(clippy::too_many_arguments)]
pub(crate) fn exercise_wyr1f_degraded_episode<S, L, W>(
    system: &mut S,
    loader: &mut L,
    waits: &mut W,
    bootfs: &[u8],
    registry_identity: [u8; 32],
    registry_generation: u64,
    console: InstalledPeer,
    driver_request: DriverLaunchRequest,
    deliveries: u32,
) -> Result<Wyr1fDegradedOutcome, InitError>
where
    S: Wyr1BPlatform,
    L: LoaderPlatform<Error = NativeError>,
    W: SupervisionPlatform<Error = NativeError>,
{
    use crate::gate::{GateConfig, GateContract, GateScenario};
    let e6 = wyr1e::State::wyr1f_degraded_fixture(registry_generation, console)?;
    let (mut resident, _devmgr, _driver) = recovery_fixture_resident(
        registry_identity,
        registry_generation,
        e6,
        RegistryTopology::new(registry_generation).map_err(InitError::Wyr1BModel)?,
        Some(driver_request),
    )?;
    let gate = GateConfig {
        contract: GateContract::Dw1Wyr1InteractiveClosure,
        scenario: GateScenario::DegradedRecovery,
        nonce: 0x00ff,
    };
    resident.controller.install_wyr1f_gate_for_fixture(gate)?;
    resident.wyr1f = crate::wyr1f_closure::ClosureEpisode::new(Some(gate));

    // Deliver the trigger `deliveries` times. A second episode, a re-armed
    // one, or a reset retry budget would all show up in the outcome.
    let mut fired = 0_u32;
    for _ in 0..deliveries {
        if wyr1f_closure_trigger(&mut resident, wyr1e::PollOutcome::Stable)
            == wyr1e::PollOutcome::RecoverDevmgr
        {
            fired += 1;
            recover_devmgr(&mut resident, system, loader, waits, bootfs)?;
        }
    }
    assert_eq!(fired, 1, "exactly one episode per boot");
    // One more poll, as the idle product makes it, to close the episode.
    let idle = wyr1f_closure_trigger(&mut resident, wyr1e::PollOutcome::Stable);
    assert_eq!(
        idle,
        wyr1e::PollOutcome::Stable,
        "an idle poll re-triggered"
    );

    let permanent_failure_records = (0..)
        .map_while(|index| resident.controller.evidence_line(index))
        .filter(|line| &line[39..41] == b"04")
        .count();
    let state = resident
        .wyr1c
        .as_ref()
        .ok_or(InitError::AbsentState(0x57))?;
    Ok(Wyr1fDegradedOutcome {
        result: resident.result,
        mode: resident.controller.mode(),
        degraded_transitions: resident.controller.degraded_transitions(),
        console: state.e6.as_ref().and_then(wyr1e::State::wyr1f_console),
        driver_retained: state.driver.is_some(),
        devmgr_state: resident.controller.role_state(RoleId::Devmgr),
        permanent_failure_records,
        refuses_activation: resident.wyr1f.refuses_activation(),
    })
}

/// Test-only bridge from the reached S3 held-WAIT state into the production
/// registry-recovery orchestrator. The caller supplies real dispatcher-owned
/// shell/job state; this function performs the actual dependent retirement,
/// registry process retirement/relaunch, topology restart, devmgr WAIT/rebind,
/// and current-driver publication observation before returning the surviving
/// owners for the S4 evidence continuation.
#[cfg(all(test, feature = "wyr1e8-selector33"))]
#[allow(clippy::too_many_arguments)]
pub(crate) fn exercise_e8_registry_recovery_orchestrator<S, L, W, E>(
    system: &mut S,
    loader: &mut L,
    waits: &mut W,
    bootfs: &[u8],
    registry_identity: [u8; 32],
    registry_generation: u64,
    shell: ShellControllerState,
    jobs: JobDispatcher,
    console: InstalledPeer,
    topology: RegistryTopology,
    driver_request: DriverLaunchRequest,
    enqueue_publication: E,
) -> Result<E8RegistryRecoveryFixtureResult, InitError>
where
    S: Wyr1BPlatform,
    L: LoaderPlatform<Error = NativeError>,
    W: SupervisionPlatform<Error = NativeError>,
    E: FnOnce(&mut S, DwHandle, &[u8]) -> Result<(), NativeError>,
{
    let e6 = wyr1e::State::from_e8_registry_fixture(shell, jobs, console);
    let (mut resident, devmgr, driver) = recovery_fixture_resident(
        registry_identity,
        registry_generation,
        e6,
        topology,
        Some(driver_request),
    )?;
    recover_registry(
        &mut resident,
        system,
        loader,
        waits,
        bootfs,
        false,
        true,
        abandoned::reason(abandoned::trigger::NONE, abandoned::phase::NONE),
    )?;

    let (client, grant, publication_generation) = resident
        .wyr1c
        .as_ref()
        .and_then(|state| state.e6.as_ref())
        .and_then(wyr1e::State::e8_fixture_publication_observer)
        .ok_or(InitError::AbsentState(0x58))?;
    let mut publication = [0u8; 72];
    let publication_len = wyrmroot_registry_proto::encode_generation_changed(
        RegistryHeader {
            message_type: RegistryMessageType::GenerationChanged,
            registry_generation: grant.registry_generation,
            endpoint_id: grant.endpoint_id,
            endpoint_generation: grant.endpoint_generation,
            transaction_id: 1,
        },
        publication_generation,
        &mut publication,
    )
    .map_err(InitError::RegistryProtocol)?;
    enqueue_publication(system, client, &publication[..publication_len])
        .map_err(InitError::Native)?;
    let now = system.now().map_err(InitError::Native)?;
    let publication_outcome = wyr1e::poll(&mut resident, system, loader, waits, now)
        .unwrap_or_else(|error| panic!("production publication observer failed: {error:?}"));
    assert_eq!(
        publication_outcome,
        wyr1e::PollOutcome::LaunchConsole,
        "production publication outcome"
    );

    let mut state = resident.wyr1c.take().ok_or(InitError::AbsentState(0x59))?;
    let replacement_generation = state.topology.generation();
    assert!(
        replacement_generation > registry_generation,
        "replacement generation"
    );
    assert_eq!(
        state.publication_service_generation, publication_generation,
        "publication generation"
    );
    assert!(state.registry.is_some(), "replacement registry owner");
    assert_eq!(state.devmgr, Some(devmgr), "retained devmgr owner");
    assert_eq!(state.driver, driver, "retained driver owner");
    let e6 = state.e6.take().ok_or(InitError::AbsentState(0x5a))?;
    assert!(
        e6.e8_fixture_publication_observer().is_none(),
        "publication observation consumed"
    );
    let (shell, jobs, console) = e6.into_e8_registry_fixture_parts();
    assert!(console.is_none(), "old console retired");
    Ok(E8RegistryRecoveryFixtureResult {
        shell,
        jobs,
        topology: state.topology,
        registry_generation: replacement_generation,
        publication_generation,
    })
}

#[cfg(feature = "wyr1e-production")]
fn start_wyr1e_or_recover_registry<S, L, W>(
    resident: &mut ResidentSystemInit,
    system: &mut S,
    loader: &mut L,
    waits: &mut W,
    bootfs: &[u8],
) -> Result<(), InitError>
where
    S: Wyr1BPlatform,
    L: LoaderPlatform<Error = NativeError>,
    W: SupervisionPlatform<Error = NativeError>,
{
    let result = wyr1e::start_after_driver_constructed(resident, system);
    #[cfg(feature = "wyr1e8-selector33")]
    if result.is_err() && wyr1e::recovery_deadline(resident)?.is_some() {
        return result;
    }
    match result {
        Ok(()) => Ok(()),
        Err(_) if wyr1e::registry_recovery_required(resident) => recover_registry(
            resident,
            system,
            loader,
            waits,
            bootfs,
            false,
            false,
            abandoned::reason(
                abandoned::trigger::WYR1E_START_FALLBACK,
                abandoned::phase::NONE,
            ),
        ),
        Err(error) => Err(error),
    }
}

fn recover_devmgr_after_error<S, L, W>(
    resident: &mut ResidentSystemInit,
    system: &mut S,
    loader: &mut L,
    waits: &mut W,
    bootfs: &[u8],
    error: InitError,
) -> Result<(), InitError>
where
    S: Wyr1BPlatform,
    L: LoaderPlatform<Error = NativeError>,
    W: SupervisionPlatform<Error = NativeError>,
{
    // `DIAGNOSTIC_CAUSE_CARRIAGE_CONTRACT.md` 3.5: the parameter was taken and
    // then discarded outside the selector, which told every reader this
    // function carried a cause it did not. It is read in every build now.
    #[cfg(feature = "wyr1e-production")]
    let episode_open = wyr1e::recovery_deadline(resident)?.is_some();
    #[cfg(not(feature = "wyr1e-production"))]
    let episode_open = false;
    if episode_open {
        return Err(error);
    }
    recover_devmgr(resident, system, loader, waits, bootfs)
}

#[cfg(feature = "wyr1c6-selector29")]
fn selector29_restarting_d1(
    devmgr_generation: u64,
    active_driver: Option<DriverLaunchRequest>,
    last_reaped_driver: Option<DriverLaunchRequest>,
) -> bool {
    if devmgr_generation != wyrmroot_device_proto::SELECTOR29_FAILURE_SUPERVISOR_GENERATION {
        return false;
    }
    active_driver.or(last_reaped_driver).is_some_and(|request| {
        request.supervisor_generation.0
            == wyrmroot_device_proto::SELECTOR29_FAILURE_SUPERVISOR_GENERATION
            && request.attempt_generation.0
                > wyrmroot_device_proto::SELECTOR29_FAILURE_ATTEMPT_GENERATION
    })
}

#[cfg(feature = "wyr1c6-selector29")]
const fn selector29_terminal_fact_for_event(
    next: crate::wyr1c6_gate::GateEvent,
) -> Result<Option<u8>, InitError> {
    match next {
        crate::wyr1c6_gate::GateEvent::StaleReject => Ok(Some(13)),
        crate::wyr1c6_gate::GateEvent::D1Failure => Ok(Some(14)),
        crate::wyr1c6_gate::GateEvent::P2Retire => Ok(None),
        _ => Err(InitError::WrongManifestProfile),
    }
}

#[cfg(feature = "wyr1c6-selector29")]
fn selector29_next_d1_terminal_fact(
    resident: &ResidentSystemInit,
) -> Result<Option<u8>, InitError> {
    let next = resident
        .wyr1c
        .as_ref()
        .and_then(|state| state.c6_evidence.as_ref())
        .and_then(crate::wyr1c6_gate::EvidenceLog::next_expected_event)
        .ok_or(InitError::AbsentState(0x5b))?;
    selector29_terminal_fact_for_event(next)
}

#[cfg(feature = "wyr1c6-selector29")]
fn drain_selector29_d1_terminal_facts<S: InitPlatform>(
    resident: &mut ResidentSystemInit,
    system: &mut S,
    devmgr: ActiveNativeRole,
) -> Result<(), InitError> {
    while let Some(expected) = selector29_next_d1_terminal_fact(resident)? {
        match receive_devmgr_control(system, devmgr.loaded.launch_channel)? {
            DevmgrControlInput::C6Fact(fact) if fact.event == expected => {
                accept_c6_fact(resident, fact)?;
            }
            _ => return Err(InitError::WrongManifestProfile),
        }
    }
    Ok(())
}

fn recover_devmgr<S, L, W>(
    resident: &mut ResidentSystemInit,
    system: &mut S,
    loader: &mut L,
    waits: &mut W,
    bootfs: &[u8],
) -> Result<(), InitError>
where
    S: Wyr1BPlatform,
    L: LoaderPlatform<Error = NativeError>,
    W: SupervisionPlatform<Error = NativeError>,
{
    #[cfg(feature = "wyr1e8-selector33")]
    if wyr1e::recovery_deadline(resident)?.is_some() {
        return Err(InitError::Supervision);
    }
    #[cfg(feature = "dw1e3-selector31")]
    if let Some(child_cleanup_failed) = fail_closed_e3a_recovery(resident, system, waits) {
        return finish_e3a_fatal_recovery(resident, system, waits, child_cleanup_failed);
    }
    // `DW1_WYR1_FINAL_CLOSURE_CONTRACT.md` §5.3.1 item 4. A coordinator change
    // does not by itself invalidate the device topology beneath it, so the
    // console stack is retained *through* the recovery episode and torn down
    // only once a replacement generation is actually READY and about to build
    // a driver of its own -- see `retire_retained_device_topology`. An episode
    // that exhausts instead therefore reaches DEGRADED with the console and
    // the live shell generation still serving, which is what [B] §5.4 promises
    // and what §5.4's dependency-preservation rule requires.
    //
    // With no console product installed there is no consumer, the retention is
    // false, and everything below runs exactly as it always has.
    #[cfg(feature = "wyr1e-production")]
    let retained_device_topology = wyr1e::console_depends_on_driver(resident);
    #[cfg(not(feature = "wyr1e-production"))]
    let retained_device_topology = false;
    #[cfg(feature = "wyr1e-production")]
    if !retained_device_topology
        && wyr1e::retire_dependents(resident, system, waits, false).is_err()
    {
        resident.result = RecoveryResult::Degraded;
        return Err(InitError::Cleanup);
    }
    #[cfg(feature = "wyr1c6-selector29")]
    let restarting_d1 = {
        let state = resident
            .wyr1c
            .as_ref()
            .ok_or(InitError::AbsentState(0x5c))?;
        selector29_restarting_d1(
            state
                .devmgr
                .map(|devmgr| devmgr.generation)
                .unwrap_or_default(),
            state.driver.map(|driver| driver.request),
            state.last_reaped_driver,
        )
    };
    #[cfg(feature = "wyr1c6-selector29")]
    if restarting_d1 {
        let devmgr = resident
            .wyr1c
            .as_ref()
            .and_then(|state| state.devmgr)
            .ok_or(InitError::AbsentState(0x5d))?;
        // D1 sends the final stale-rejection and failure facts immediately
        // before exiting. A process-exit wait may win over the readable launch
        // channel, so drain those already-buffered facts before synthesizing
        // P2 retirement and U2 reap evidence.
        drain_selector29_d1_terminal_facts(resident, system, devmgr)?;
    }
    if !retained_device_topology
        && resident
            .wyr1c
            .as_ref()
            .is_some_and(|state| state.driver.is_some())
        && reap_driver(resident, system, waits, true).is_err()
    {
        resident.result = RecoveryResult::Degraded;
        return Err(InitError::Cleanup);
    }
    #[cfg(feature = "wyr1c6-selector29")]
    if restarting_d1 {
        let (lease, p2_binding, p2_attempt, p2_endpoint, irq, u2_attempt, u2_endpoint) = {
            let state = resident
                .wyr1c
                .as_ref()
                .ok_or(InitError::AbsentState(0x5e))?;
            (
                state.c6_d1_lease.ok_or(InitError::AbsentState(0x5f))?,
                if state.c6_p2_service_generation == 0 {
                    return Err(InitError::WrongActivationOrder);
                } else {
                    state.c6_p2_service_generation
                },
                state.c6_u2_attempt.ok_or(InitError::AbsentState(0x60))?,
                if state.c6_p2_endpoint_generation == 0 {
                    return Err(InitError::WrongActivationOrder);
                } else {
                    state.c6_p2_endpoint_generation
                },
                state.c6_u2_irq.ok_or(InitError::AbsentState(0x61))?,
                state.c6_u2_attempt.ok_or(InitError::AbsentState(0x62))?,
                state.c6_u2_endpoint.ok_or(InitError::AbsentState(0x63))?,
            )
        };
        accept_c6_fact(
            resident,
            C6Fact {
                event: 15,
                lease,
                binding: p2_binding,
                value: p2_attempt,
                aux: p2_endpoint,
            },
        )?;
        accept_c6_fact(
            resident,
            C6Fact {
                event: 16,
                lease,
                binding: irq,
                value: u2_attempt,
                aux: u2_endpoint,
            },
        )?;
    }
    let active = resident
        .wyr1c
        .as_mut()
        .ok_or(InitError::AbsentState(0x64))?
        .devmgr
        .take()
        .ok_or(InitError::AbsentState(0x65))?;
    resident.active[1] = None;
    {
        let state = resident
            .wyr1c
            .as_mut()
            .ok_or(InitError::AbsentState(0x66))?;
        state.binding = None;
        state.waiting_registry_observed = false;
    }
    let now = system.now().map_err(InitError::Native)?;
    let transition = resident.controller.fail(
        RoleId::Devmgr,
        active.generation,
        active.transaction_id,
        now,
        AttemptFailure::WaitFailed,
    );
    let cleanup_failed =
        cleanup_loaded(system, waits, active.loaded, active.task_group, true).is_err();
    if let Err(error) = transition {
        let disposition = if cleanup_failed {
            CleanupDisposition::Failed
        } else {
            CleanupDisposition::Complete
        };
        resident.controller.retire_active_fail_closed(
            RoleId::Devmgr,
            active.generation,
            active.transaction_id,
            now,
            AttemptFailure::WaitFailed,
            disposition,
        )?;
        resident.result = RecoveryResult::Degraded;
        return if cleanup_failed {
            Err(InitError::Cleanup)
        } else {
            Err(error)
        };
    }
    let retired_at = now.checked_add(1).ok_or(InitError::Accounting)?;
    if cleanup_failed {
        resident.controller.cleanup_failed(
            RoleId::Devmgr,
            active.generation,
            active.transaction_id,
            retired_at,
        )?;
        resident.result = RecoveryResult::Degraded;
        return Ok(());
    }
    resident.controller.cleanup_complete(
        RoleId::Devmgr,
        active.generation,
        active.transaction_id,
        retired_at,
    )?;
    #[cfg(feature = "wyr1c6-selector29")]
    if restarting_d1 {
        let lease = resident
            .wyr1c
            .as_ref()
            .and_then(|state| state.c6_d1_lease)
            .ok_or(InitError::AbsentState(0x67))?;
        accept_c6_fact(
            resident,
            C6Fact {
                event: 17,
                lease,
                binding: 0,
                value: active.generation,
                aux: 1,
            },
        )?;
    }
    if advance_or_degrade(
        system,
        &mut resident.controller,
        RoleId::Devmgr,
        active.transaction_id,
    )? {
        resident.result = RecoveryResult::Degraded;
        return Ok(());
    }
    launch_devmgr_replacement(resident, system, loader, waits, bootfs)
}

/// Tears down a device topology that `recover_devmgr` retained through the
/// episode, once a replacement coordinator generation is actually READY.
///
/// This is the second half of §5.3.1 item 4. Deferring the teardown to here,
/// rather than skipping it, keeps ordinary devmgr recovery's end state exactly
/// what it was -- fresh driver, fresh console, fresh foreground shell -- while
/// an episode that never produces a replacement generation leaves the console
/// stack untouched. It runs before the new generation is installed, so the
/// replacement's first driver-launch request cannot race a live old driver.
#[cfg(feature = "wyr1e-production")]
fn retire_retained_device_topology<S, W>(
    resident: &mut ResidentSystemInit,
    system: &mut S,
    waits: &mut W,
) -> Result<(), InitError>
where
    S: Wyr1BPlatform,
    W: SupervisionPlatform<Error = NativeError>,
{
    if !wyr1e::console_depends_on_driver(resident) {
        return Ok(());
    }
    let retired = wyr1e::retire_dependents(resident, system, waits, false)
        .and_then(|()| reap_driver(resident, system, waits, true).map(|_| ()));
    if retired.is_err() {
        resident.result = RecoveryResult::Degraded;
        return Err(InitError::Cleanup);
    }
    Ok(())
}

fn launch_devmgr_replacement<S, L, W>(
    resident: &mut ResidentSystemInit,
    system: &mut S,
    loader: &mut L,
    waits: &mut W,
    bootfs: &[u8],
) -> Result<(), InitError>
where
    S: Wyr1BPlatform,
    L: LoaderPlatform<Error = NativeError>,
    W: SupervisionPlatform<Error = NativeError>,
{
    let manifest_entry = Archive::new(bootfs)
        .map_err(InitError::Bootfs)?
        .lookup(DEVICE_MANIFEST_PATH.as_bytes())
        .map_err(map_lookup)?;
    loop {
        let attempt_transaction = match resident
            .controller
            .role_state(RoleId::Devmgr)
            .ok_or(InitError::AbsentState(0x68))?
        {
            RestartState::Starting { transaction_id, .. } => transaction_id,
            _ => return Err(InitError::WrongActivationOrder),
        };
        let registry = resident.wyr1c.as_ref().and_then(|state| state.registry);
        let resource_domain = resident
            .wyr1c
            .as_ref()
            .and_then(|state| state.resource_domain);
        let Some(registry) = registry else {
            resident.result = RecoveryResult::Degraded;
            return Ok(());
        };
        // The declared episode refuses each replacement activation, before any
        // topology grant or publication is issued, so nothing is reserved that
        // the refusal would then have to unwind. The refusal is an ordinary
        // attempt failure and takes the ordinary arm below: the episode never
        // counts an attempt, moves a deadline or sets a mode itself.
        #[cfg(feature = "wyr1f-closure")]
        let refused = resident.wyr1f.refuses_activation();
        #[cfg(not(feature = "wyr1f-closure"))]
        let refused = false;
        let attempt = if refused {
            Err(InitError::Supervision)
        } else {
            let state = resident
                .wyr1c
                .as_mut()
                .ok_or(InitError::AbsentState(0x69))?;
            launch_devmgr(
                system,
                loader,
                waits,
                &mut resident.controller,
                resident.authority,
                resource_domain,
                bootfs,
                registry,
                &mut state.topology,
                &mut state.publication_allocator,
                manifest_entry.data(),
            )
        };
        match attempt {
            Ok(attempt) => {
                #[cfg(feature = "wyr1e-production")]
                retire_retained_device_topology(resident, system, waits)?;
                let state = resident
                    .wyr1c
                    .as_mut()
                    .ok_or(InitError::AbsentState(0x6a))?;
                state.devmgr = Some(attempt.active);
                state.binding = Some(attempt.binding);
                state.publication_service_generation = attempt.publication_service_generation;
                state.last_controller_transaction = attempt.last_controller_transaction;
                state.next_controller_transaction = attempt.next_controller_transaction;
                state.waiting_registry_observed = false;
                resident.active[1] = Some(attempt.active);
                return Ok(());
            }
            Err(error) => {
                let (generation, transaction_id) = match resident
                    .controller
                    .role_state(RoleId::Devmgr)
                    .ok_or(InitError::AbsentState(0x6b))?
                {
                    RestartState::Starting {
                        generation,
                        transaction_id,
                        ..
                    } => (generation, transaction_id),
                    RestartState::Backoff { .. } => {
                        if advance_or_degrade(
                            system,
                            &mut resident.controller,
                            RoleId::Devmgr,
                            attempt_transaction,
                        )? {
                            resident.result = RecoveryResult::Degraded;
                            return Ok(());
                        }
                        continue;
                    }
                    RestartState::PermanentFailure { .. } => {
                        resident.result = RecoveryResult::Degraded;
                        return Ok(());
                    }
                    _ => return Err(error),
                };
                let failed_at = system.now().map_err(InitError::Native)?;
                resident.controller.fail(
                    RoleId::Devmgr,
                    generation,
                    transaction_id,
                    failed_at,
                    AttemptFailure::CreationFailed,
                )?;
                resident.controller.cleanup_complete(
                    RoleId::Devmgr,
                    generation,
                    transaction_id,
                    failed_at.checked_add(1).ok_or(InitError::Accounting)?,
                )?;
                if advance_or_degrade(
                    system,
                    &mut resident.controller,
                    RoleId::Devmgr,
                    transaction_id,
                )? {
                    resident.result = RecoveryResult::Degraded;
                    return Ok(());
                }
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PublicationRebindContext {
    RegistryRecovery,
    #[cfg(any(
        test,
        feature = "wyr1c6-production",
        feature = "dw1e3-selector31",
        feature = "wyr1d-selector32"
    ))]
    DriverRetirement,
}

impl PublicationRebindContext {
    fn expected_status(
        self,
        resource_domain: Option<ResourceDomainCustody>,
        _driver: Option<DriverNativeAttempt>,
        _reaped: Option<DriverLaunchRequest>,
        _supervisor: SupervisorGeneration,
    ) -> Result<StatusCode, InitError> {
        match self {
            Self::RegistryRecovery if resource_domain.is_some() => {
                Ok(StatusCode::OperationalResourceOwned)
            }
            Self::RegistryRecovery => Ok(StatusCode::OperationalWaitingForDeviceBundle),
            #[cfg(any(
                test,
                feature = "wyr1c6-production",
                feature = "dw1e3-selector31",
                feature = "wyr1d-selector32"
            ))]
            Self::DriverRetirement => {
                let reaped = _reaped.ok_or(InitError::AbsentState(0x6c))?;
                if _driver.is_some() || reaped.supervisor_generation != _supervisor {
                    return Err(InitError::WrongActivationOrder);
                }
                Ok(StatusCode::OperationalWaitingForDeviceBundle)
            }
        }
    }
}

fn rebind_publication<S, W>(
    resident: &mut ResidentSystemInit,
    system: &mut S,
    waits: &mut W,
    context: PublicationRebindContext,
) -> Result<(), InitError>
where
    S: Wyr1BPlatform,
    W: SupervisionPlatform<Error = NativeError>,
{
    // The recovery episode lives on the wyr1e console/shell supervisor, so
    // a build without that product has no episode rather than no concept of
    // one. The gate is the product, not a selector.
    #[cfg(feature = "wyr1e-production")]
    let deadline_cap = wyr1e::recovery_deadline(resident)?;
    #[cfg(not(feature = "wyr1e-production"))]
    let deadline_cap = None;
    let state = resident
        .wyr1c
        .as_mut()
        .ok_or(InitError::AbsentState(0x6d))?;
    let registry = state.registry.ok_or(InitError::AbsentState(0x6e))?;
    let devmgr = state.devmgr.ok_or(InitError::AbsentState(0x6f))?;
    let expected_status = context.expected_status(
        state.resource_domain,
        state.driver,
        state.last_reaped_driver,
        SupervisorGeneration(devmgr.generation),
    )?;
    let rebound = perform_rebind(
        system,
        waits,
        &mut state.topology,
        &mut state.publication_allocator,
        registry.control_channel,
        devmgr,
        state.next_controller_transaction,
        expected_status,
        deadline_cap,
    );
    let (binding, publication_service_generation, transaction_id) = match rebound {
        Ok(rebound) => rebound,
        Err(error) => {
            #[cfg(feature = "wyr1e8-selector33")]
            if deadline_cap.is_some() {
                state
                    .e6
                    .as_mut()
                    .ok_or(InitError::AbsentState(0x70))?
                    .shell
                    .poison(registry.active.generation);
            }
            return Err(error);
        }
    };
    state.binding = Some(binding);
    state.publication_service_generation = publication_service_generation;
    state.waiting_registry_observed = false;
    state.last_controller_transaction = transaction_id;
    state.next_controller_transaction =
        transaction_id.checked_add(1).ok_or(InitError::Accounting)?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn perform_rebind<S, W>(
    system: &mut S,
    waits: &mut W,
    topology: &mut RegistryTopology,
    publication_allocator: &mut PublicationAllocator,
    registry_control: DwHandle,
    devmgr: ActiveNativeRole,
    transaction_id: u64,
    expected_status: StatusCode,
    deadline_cap: Option<u64>,
) -> Result<(wyrmroot_device_proto::RegistryBinding, u64, u64), InitError>
where
    S: Wyr1BPlatform,
    W: SupervisionPlatform<Error = NativeError>,
{
    if let Some(deadline) = deadline_cap {
        let now = system.now().map_err(InitError::Native)?;
        if now >= deadline {
            return Err(InitError::Supervision);
        }
    }
    let grant = topology
        .issue(devmgr.generation, EndpointKind::Publication)
        .map_err(InitError::Wyr1BModel)?;
    let publication = publication_allocator.issue()?;
    let binding = wyrmroot_device_proto::RegistryBinding {
        generation: RegistryGeneration(grant.registry_generation),
        endpoint: RegistryEndpoint {
            id: RegistryEndpointId(grant.endpoint_id),
            generation: RegistryEndpointGeneration(grant.endpoint_generation),
        },
    };
    let (registry_endpoint, devmgr_endpoint) = create_controller_channel_pair(system)?;
    if let Some(deadline) = deadline_cap {
        let now = system.now().map_err(InitError::Native)?;
        if now >= deadline {
            let failed = system.close_handle(registry_endpoint).is_err()
                | system.close_handle(devmgr_endpoint).is_err();
            return Err(if failed {
                InitError::Cleanup
            } else {
                InitError::Supervision
            });
        }
    }
    if let Err(error) = install_publication(
        system,
        registry_control,
        grant,
        publication,
        registry_endpoint,
    ) {
        let cleanup_failed = system.close_handle(devmgr_endpoint).is_err()
            | system.close_handle(registry_endpoint).is_err();
        return Err(if cleanup_failed {
            InitError::Cleanup
        } else {
            error
        });
    }
    if let Some(deadline) = deadline_cap {
        let now = system.now().map_err(InitError::Native)?;
        if now >= deadline {
            return Err(if system.close_handle(devmgr_endpoint).is_err() {
                InitError::Cleanup
            } else {
                InitError::Supervision
            });
        }
    }
    let request = ControllerMessage::RebindPublication {
        supervisor_generation: SupervisorGeneration(devmgr.generation),
        binding,
        transaction_id,
    };
    let bytes = match encode_publication_request(request, publication.service_generation) {
        Ok(bytes) => bytes,
        Err(()) => {
            return Err(if system.close_handle(devmgr_endpoint).is_err() {
                InitError::Cleanup
            } else {
                InitError::WrongManifestProfile
            });
        }
    };
    let transfer = DwHandleTransferV1 {
        handle: devmgr_endpoint,
        requested_rights: wyrmroot_loader::launch::CHILD_CHANNEL_RIGHTS,
        operation: DW_HANDLE_TRANSFER_MOVE,
        reserved0: 0,
        reserved: [0; 2],
    };
    if let Err(error) = system
        .send_channel_with_handles(
            devmgr.loaded.launch_channel,
            &bytes,
            core::slice::from_ref(&transfer),
        )
        .map_err(InitError::Native)
    {
        let cleanup_failed = system.close_handle(devmgr_endpoint).is_err();
        return Err(if cleanup_failed {
            InitError::Cleanup
        } else {
            error
        });
    }
    if deadline_cap.is_some_and(|deadline| system.now().map_or(true, |now| now >= deadline)) {
        return Err(InitError::Supervision);
    }
    expect_device_status(
        system,
        waits,
        devmgr,
        binding,
        transaction_id,
        expected_status,
        deadline_cap,
    )?;
    Ok((binding, publication.service_generation, transaction_id))
}

#[cfg(test)]
mod tests {
    use super::*;
    use deepwyrm_syscall::{DW_SIGNAL_EXITED, DW_SIGNAL_PEER_CLOSED, DW_SIGNAL_READABLE, DwStatus};
    use wyrmroot_device_proto::manifest::{
        HEADER_BYTES as WRDM_HEADER_BYTES, MAGIC as WRDM_MAGIC, MAJOR as WRDM_MAJOR,
        MINOR as WRDM_MINOR, PROFILE_Q35, PROFILE_Q35_VERSION, RECORD_BYTES as WRDM_RECORD_BYTES,
        UART16550D_PATH,
    };

    const FAILURE: NativeError = NativeError::Status(DwStatus(-1));

    #[cfg(feature = "dw1e3-selector31")]
    #[test]
    fn selector31_probe_generations_use_distinct_sticky_registry_client_ids() {
        let u1 = e3a_probe_client_id(1).unwrap();
        let u2 = e3a_probe_client_id(2).unwrap();
        assert_ne!(u1, u2);
        assert_eq!(e3a_probe_client_id(0), Err(InitError::WrongActivationOrder));
        assert_eq!(e3a_probe_client_id(3), Err(InitError::WrongActivationOrder));
    }

    struct RebindPlatform {
        inbound: [u8; wyrmroot_device_proto::controller::STATUS_BYTES],
        inbound_len: usize,
        send_count: usize,
        fail_send_at: usize,
        closed: [DwHandle; 4],
        close_count: usize,
        registry_service_generation: Option<u64>,
        controller_service_generation: Option<u64>,
        controller_request: Option<ControllerMessage>,
        now: u64,
        receive_at: Option<u64>,
    }

    impl RebindPlatform {
        fn with_status(message: ControllerMessage) -> Self {
            let mut inbound = [0; wyrmroot_device_proto::controller::STATUS_BYTES];
            encode_controller(message, &mut inbound).unwrap();
            Self::with_reply(inbound)
        }

        fn with_reply(inbound: [u8; wyrmroot_device_proto::controller::STATUS_BYTES]) -> Self {
            Self {
                inbound,
                inbound_len: wyrmroot_device_proto::controller::STATUS_BYTES,
                send_count: 0,
                fail_send_at: usize::MAX,
                closed: [DwHandle(0); 4],
                close_count: 0,
                registry_service_generation: None,
                controller_service_generation: None,
                controller_request: None,
                now: 100,
                receive_at: None,
            }
        }
    }

    impl InitPlatform for RebindPlatform {
        fn query_capability_info(
            &mut self,
            _handle: DwHandle,
        ) -> Result<CapabilityInfo<DwObjectType, DwRights>, NativeError> {
            Err(FAILURE)
        }

        fn receive_channel(
            &mut self,
            _channel: DwHandle,
            bytes: &mut [u8],
            _handles: &mut [DwReceivedHandleInfoV1],
        ) -> Result<ReceiveCounts, NativeError> {
            if self.inbound_len == 0 {
                return Err(FAILURE);
            }
            bytes[..self.inbound_len].copy_from_slice(&self.inbound[..self.inbound_len]);
            let counts = ReceiveCounts {
                bytes: self.inbound_len,
                handles: 0,
            };
            self.inbound_len = 0;
            if let Some(now) = self.receive_at {
                self.now = now;
            }
            Ok(counts)
        }

        fn query_memory_object_size(&mut self, _handle: DwHandle) -> Result<u64, NativeError> {
            Err(FAILURE)
        }

        fn with_bootfs_bytes<R>(
            &mut self,
            _root: DwHandle,
            _bootfs: DwHandle,
            _plan: MappingPlan,
            _use_bytes: impl for<'a> FnOnce(&mut Self, &'a [u8]) -> R,
        ) -> Result<R, NativeError> {
            Err(FAILURE)
        }

        fn send_channel(&mut self, _channel: DwHandle, _bytes: &[u8]) -> Result<(), NativeError> {
            Err(FAILURE)
        }

        fn close_handle(&mut self, handle: DwHandle) -> Result<(), NativeError> {
            self.closed[self.close_count] = handle;
            self.close_count += 1;
            Ok(())
        }

        fn create_attempt_task_group(
            &mut self,
            _parent: DwHandle,
        ) -> Result<DwHandle, NativeError> {
            Err(FAILURE)
        }

        fn terminate_task_group(&mut self, _task_group: DwHandle) -> Result<(), NativeError> {
            Err(FAILURE)
        }

        fn now(&mut self) -> Result<u64, NativeError> {
            Ok(self.now)
        }

        fn wait_until(&mut self, _deadline_ns: u64) -> Result<(), NativeError> {
            Err(FAILURE)
        }
    }

    impl Wyr1BPlatform for RebindPlatform {
        fn channel_create(
            &mut self,
            _rights: DwRights,
        ) -> Result<(DwHandle, DwHandle), NativeError> {
            Ok((DwHandle(50), DwHandle(51)))
        }

        fn send_channel_with_handles(
            &mut self,
            channel: DwHandle,
            bytes: &[u8],
            transfers: &[DwHandleTransferV1],
        ) -> Result<(), NativeError> {
            self.send_count += 1;
            assert_eq!(transfers.len(), 1);
            assert_eq!(transfers[0].operation, DW_HANDLE_TRANSFER_MOVE);
            assert_eq!(transfers[0].requested_rights, CHILD_CHANNEL_RIGHTS);
            assert_eq!(transfers[0].reserved0, 0);
            assert_eq!(transfers[0].reserved, [0; 2]);
            if self.send_count == 1 {
                assert_eq!(channel, DwHandle(40));
                assert_eq!(transfers[0].handle, DwHandle(50));
                let parsed = wyrmroot_registry_proto::parse(bytes, 1).unwrap();
                let wyrmroot_registry_proto::Message::InstallPublication(publication) =
                    parsed.message
                else {
                    panic!("registry must receive publication installation");
                };
                self.registry_service_generation = Some(publication.service_generation);
            } else {
                assert_eq!(self.send_count, 2);
                assert_eq!(channel, devmgr().loaded.launch_channel);
                assert_eq!(transfers[0].handle, DwHandle(51));
                #[cfg(any(feature = "wyr1d-selector32", feature = "wyr1e-production"))]
                {
                    let parsed = wyrmroot_device_proto::controller_v1_1::parse(bytes).unwrap();
                    self.controller_request = Some(parsed.controller);
                    self.controller_service_generation = Some(parsed.service_generation);
                    assert_eq!(
                        self.controller_service_generation,
                        self.registry_service_generation
                    );
                }
                #[cfg(not(any(feature = "wyr1d-selector32", feature = "wyr1e-production")))]
                {
                    self.controller_request = Some(parse_controller(bytes).unwrap());
                }
            }
            if self.send_count == self.fail_send_at {
                Err(FAILURE)
            } else {
                Ok(())
            }
        }

        fn wait_many(
            &mut self,
            _items: &[DwWaitItemV1],
            _deadline: DwDeadline,
        ) -> Result<DwWaitResultV1, NativeError> {
            Err(FAILURE)
        }

        fn materialize_read_only_memory(
            &mut self,
            _root: DwHandle,
            _bytes: &[u8],
            _rights: DwRights,
        ) -> Result<DwHandle, NativeError> {
            Err(FAILURE)
        }
    }

    struct StatusWaits {
        fail: bool,
    }

    impl SupervisionPlatform for StatusWaits {
        type Error = NativeError;

        fn wait_many(
            &mut self,
            _items: &[DwWaitItemV1],
            _deadline: DwDeadline,
        ) -> Result<DwWaitResultV1, Self::Error> {
            if self.fail {
                Err(FAILURE)
            } else {
                Ok(DwWaitResultV1 {
                    index: 0,
                    observed: DW_SIGNAL_READABLE,
                    ..DwWaitResultV1::default()
                })
            }
        }

        fn receive_channel(
            &mut self,
            _channel: DwHandle,
            _bytes: &mut [u8],
            _handles: &mut [DwReceivedHandleInfoV1],
        ) -> Result<ReceiveCounts, Self::Error> {
            Err(FAILURE)
        }

        fn query_task_termination(
            &mut self,
            _process: DwHandle,
        ) -> Result<DwTaskTerminationInfoV1, Self::Error> {
            Err(FAILURE)
        }
    }

    const fn devmgr() -> ActiveNativeRole {
        ActiveNativeRole {
            role: RoleId::Devmgr,
            generation: 7,
            transaction_id: 8,
            loaded: LoadedProcess {
                process: DwHandle(20),
                launch_channel: DwHandle(30),
            },
            task_group: DwHandle(10),
        }
    }

    fn binding() -> wyrmroot_device_proto::RegistryBinding {
        wyrmroot_device_proto::RegistryBinding {
            generation: RegistryGeneration(2),
            endpoint: RegistryEndpoint {
                id: RegistryEndpointId(1),
                generation: RegistryEndpointGeneration(1),
            },
        }
    }

    fn rebound_binding() -> wyrmroot_device_proto::RegistryBinding {
        wyrmroot_device_proto::RegistryBinding {
            generation: RegistryGeneration(2),
            endpoint: RegistryEndpoint {
                id: RegistryEndpointId(2),
                generation: RegistryEndpointGeneration(1),
            },
        }
    }

    fn waiting_device_status() -> ControllerMessage {
        ControllerMessage::Status {
            supervisor_generation: SupervisorGeneration(7),
            binding: Some(binding()),
            transaction_id: 9,
            status: StatusCode::OperationalWaitingForDeviceBundle,
            attempt_generation: None,
        }
    }

    fn real_rebind_producer(retired: bool) -> wyrmroot_devmgr::ResidentController {
        use wyrmroot_device_proto::coordinator::BundleGeneration;
        let mut producer = wyrmroot_devmgr::ResidentController::new(
            wyrmroot_devmgr::prepare_operational(&wrdm([0x5a; 32]), 7).unwrap(),
            8,
        )
        .unwrap();
        let mut initial = binding();
        if !retired {
            initial.generation = RegistryGeneration(1);
        }
        producer
            .accept(
                ControllerMessage::InstallPublication {
                    supervisor_generation: SupervisorGeneration(7),
                    binding: initial,
                    transaction_id: 8,
                },
                0,
            )
            .unwrap();
        producer
            .admit_device_resource(deepwyrm_syscall::DwDeviceResourceInfoV1 {
                size: deepwyrm_syscall::DW_DEVICE_RESOURCE_INFO_V1_SIZE,
                version: deepwyrm_syscall::DW_DEVICE_RESOURCE_INFO_V1_VERSION,
                kind: deepwyrm_syscall::DW_DEVICE_RESOURCE_KIND_X86_PIO_WITH_PLATFORM_INTERRUPT,
                flags: 0,
                resource_id: 1,
                lease_generation: 19,
                pio_base: 0x2f8,
                pio_length: 8,
                interrupt_source: 3,
                reserved: 0,
            })
            .unwrap();
        let driver = producer
            .issue_driver_launch_with_bundle(
                true,
                wyrmroot_device_proto::DirectControlRights::ExactReduced,
            )
            .unwrap();
        producer.driver_constructed().unwrap();
        producer.resource_bundle_message().unwrap();
        producer.bundle_transferred().unwrap();
        producer
            .accept_driver_ready(wyrmroot_device_proto::ControlMessage::Ready {
                role_id: driver.role_id,
                bundle_generation: BundleGeneration(19),
                attempt_generation: driver.attempt_generation,
                endpoint: driver.endpoint,
                transaction_id: driver.transaction_id,
            })
            .unwrap();
        producer.publication_committed().unwrap();
        if retired {
            producer.retire_message().unwrap();
            producer.accept_intentional_driver_terminal(driver).unwrap();
            producer.publication_retired().unwrap();
            producer.reap_driver().unwrap();
        } else {
            producer.publication_peer_closed().unwrap();
        }
        producer
            .accept(
                ControllerMessage::RebindPublication {
                    supervisor_generation: SupervisorGeneration(7),
                    binding: rebound_binding(),
                    transaction_id: 9,
                },
                1,
            )
            .unwrap();
        assert_eq!(producer.driver_ready(), !retired);
        assert_eq!(
            producer.active_driver_request(),
            if retired { None } else { Some(driver) }
        );
        producer
    }

    #[test]
    fn real_rebind_acknowledgements_are_lifecycle_exact_and_reject_swapped_or_stale_replies() {
        for retired in [false, true] {
            let producer = real_rebind_producer(retired);
            let reply = producer.publication_acknowledgement().unwrap();
            let context = if retired {
                PublicationRebindContext::DriverRetirement
            } else {
                PublicationRebindContext::RegistryRecovery
            };
            let expected_status = context
                .expected_status(
                    Some(ResourceDomainCustody::new(DwHandle(60))),
                    None,
                    retired.then(driver_request),
                    SupervisorGeneration(7),
                )
                .unwrap();
            assert_eq!(
                parse_controller(&reply).unwrap(),
                ControllerMessage::Status {
                    supervisor_generation: SupervisorGeneration(7),
                    binding: Some(rebound_binding()),
                    transaction_id: 9,
                    status: expected_status,
                    attempt_generation: None,
                }
            );
            let swapped = if retired {
                StatusCode::OperationalResourceOwned
            } else {
                StatusCode::OperationalWaitingForDeviceBundle
            };
            for mutation in [
                None,
                Some((72, swapped as u64)),
                Some((24, 8)),
                Some((32, 3)),
                Some((40, 3)),
                Some((48, 2)),
                Some((56, 10)),
                Some((80, 1)),
            ] {
                let mut bytes = reply;
                if let Some((offset, value)) = mutation {
                    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
                }
                let mut platform = RebindPlatform::with_reply(bytes);
                let mut topology = RegistryTopology::new(2).unwrap();
                topology.issue(7, EndpointKind::Publication).unwrap();
                let result = perform_rebind(
                    &mut platform,
                    &mut StatusWaits { fail: false },
                    &mut topology,
                    &mut PublicationAllocator::new(),
                    DwHandle(40),
                    devmgr(),
                    9,
                    expected_status,
                    Some(1_000_000_000),
                );
                if mutation.is_none() {
                    assert!(result.is_ok(), "retired={retired}: {result:?}");
                } else {
                    assert_eq!(
                        result,
                        Err(InitError::WrongManifestProfile),
                        "retired={retired}, mutation={mutation:?}"
                    );
                }
                assert_eq!(platform.inbound_len, 0);
                assert_eq!(platform.send_count, 2);
                assert_eq!(platform.close_count, 0);
                assert_eq!(
                    platform.controller_request,
                    Some(ControllerMessage::RebindPublication {
                        supervisor_generation: SupervisorGeneration(7),
                        binding: rebound_binding(),
                        transaction_id: 9,
                    })
                );
            }
            let mut platform = RebindPlatform::with_reply(reply);
            platform.receive_at = Some(101);
            let mut topology = RegistryTopology::new(2).unwrap();
            topology.issue(7, EndpointKind::Publication).unwrap();
            assert_eq!(
                perform_rebind(
                    &mut platform,
                    &mut StatusWaits { fail: false },
                    &mut topology,
                    &mut PublicationAllocator::new(),
                    DwHandle(40),
                    devmgr(),
                    9,
                    expected_status,
                    Some(101),
                ),
                Err(InitError::Supervision)
            );
            assert_eq!(platform.inbound_len, 0);
        }
    }

    #[test]
    fn rebind_postconditions_require_the_reached_resource_and_reaped_owner_context() {
        let custody = Some(ResourceDomainCustody::new(DwHandle(60)));
        let request = driver_request();
        let driver = Some(DriverNativeAttempt {
            loaded: devmgr().loaded,
            task_group: DwHandle(61),
            request,
        });
        let supervisor = SupervisorGeneration(7);
        assert_eq!(
            PublicationRebindContext::RegistryRecovery
                .expected_status(None, None, None, supervisor),
            Ok(StatusCode::OperationalWaitingForDeviceBundle)
        );
        assert_eq!(
            PublicationRebindContext::RegistryRecovery
                .expected_status(custody, driver, None, supervisor),
            Ok(StatusCode::OperationalResourceOwned)
        );
        assert_eq!(
            PublicationRebindContext::DriverRetirement.expected_status(
                custody,
                None,
                Some(request),
                supervisor
            ),
            Ok(StatusCode::OperationalWaitingForDeviceBundle)
        );
        assert_eq!(
            PublicationRebindContext::DriverRetirement.expected_status(
                custody,
                driver,
                Some(request),
                supervisor
            ),
            // Still an ordering violation, not an absent slot: this reaches
            // the explicit guard rather than a state `Option`.
            Err(InitError::WrongActivationOrder)
        );
        assert_eq!(
            PublicationRebindContext::DriverRetirement
                .expected_status(custody, None, None, supervisor),
            Err(InitError::AbsentState(0x6c))
        );
        assert_eq!(
            PublicationRebindContext::DriverRetirement.expected_status(
                custody,
                None,
                Some(request),
                SupervisorGeneration(8)
            ),
            // A stale supervisor generation is an ordering violation, and the
            // guard that says so runs before any slot is read.
            Err(InitError::WrongActivationOrder)
        );
    }

    #[test]
    fn successful_rebind_preserves_devmgr_generation_and_commits_correlation() {
        let status = ControllerMessage::Status {
            supervisor_generation: SupervisorGeneration(7),
            binding: Some(rebound_binding()),
            transaction_id: 9,
            status: StatusCode::OperationalWaitingForDeviceBundle,
            attempt_generation: None,
        };
        let mut platform = RebindPlatform::with_status(status);
        let mut waits = StatusWaits { fail: false };
        let mut topology = RegistryTopology::new(2).unwrap();
        let initial_grant = topology.issue(7, EndpointKind::Publication).unwrap();
        assert_eq!(initial_grant.endpoint_id, 1);
        let mut publications = PublicationAllocator::new();
        let initial_publication = publications.issue().unwrap();
        let result = perform_rebind(
            &mut platform,
            &mut waits,
            &mut topology,
            &mut publications,
            DwHandle(40),
            devmgr(),
            9,
            StatusCode::OperationalWaitingForDeviceBundle,
            None,
        )
        .unwrap();
        assert_eq!(result.0, rebound_binding());
        assert!(result.1 > initial_publication.service_generation);
        assert_eq!(result.2, 9);
        assert_eq!(platform.send_count, 2);
        assert_eq!(platform.close_count, 0);
        assert_eq!(devmgr().generation, 7);
        assert_eq!(platform.registry_service_generation, Some(result.1));
        assert_eq!(
            platform.controller_request,
            Some(ControllerMessage::RebindPublication {
                supervisor_generation: SupervisorGeneration(7),
                binding: result.0,
                transaction_id: result.2,
            })
        );
        #[cfg(any(feature = "wyr1d-selector32", feature = "wyr1e-production"))]
        assert_eq!(platform.controller_service_generation, Some(result.1));
        #[cfg(not(any(feature = "wyr1d-selector32", feature = "wyr1e-production")))]
        assert_eq!(platform.controller_service_generation, None);
    }

    #[cfg(feature = "wyr1e8-selector33")]
    #[test]
    fn e8_rebind_expiry_precedes_namespace_and_endpoint_effects() {
        let mut platform = RebindPlatform::with_status(waiting_device_status());
        let mut waits = StatusWaits { fail: false };
        let mut topology = RegistryTopology::new(2).unwrap();
        let mut publications = PublicationAllocator::new();

        assert_eq!(
            perform_rebind(
                &mut platform,
                &mut waits,
                &mut topology,
                &mut publications,
                DwHandle(40),
                devmgr(),
                9,
                StatusCode::OperationalWaitingForDeviceBundle,
                Some(100),
            ),
            Err(InitError::Supervision)
        );
        assert_eq!(platform.send_count, 0);
        assert_eq!(platform.close_count, 0);
        assert_eq!(
            topology
                .issue(7, EndpointKind::Publication)
                .unwrap()
                .endpoint_id,
            1
        );
        let mut untouched = PublicationAllocator::new();
        assert_eq!(publications.issue().unwrap(), untouched.issue().unwrap());
    }

    #[test]
    fn selected_initial_publication_request_keeps_issued_namespace() {
        let request = ControllerMessage::InstallPublication {
            supervisor_generation: SupervisorGeneration(7),
            binding: binding(),
            transaction_id: 9,
        };
        let bytes = encode_publication_request(request, 0xC1_0801).unwrap();
        #[cfg(any(feature = "wyr1d-selector32", feature = "wyr1e-production"))]
        {
            let parsed = wyrmroot_device_proto::controller_v1_1::parse(&bytes).unwrap();
            assert_eq!(parsed.controller, request);
            assert_eq!(parsed.service_generation, 0xC1_0801);
            assert_ne!(parsed.service_generation, binding().generation.0);
            assert!(parse_controller(&bytes).is_err());
        }
        #[cfg(not(any(feature = "wyr1d-selector32", feature = "wyr1e-production")))]
        assert_eq!(parse_controller(&bytes), Ok(request));
    }

    #[test]
    fn failed_rebind_send_closes_only_the_unmoved_devmgr_endpoint() {
        let mut platform = RebindPlatform::with_status(waiting_device_status());
        platform.fail_send_at = 2;
        let error = perform_rebind(
            &mut platform,
            &mut StatusWaits { fail: false },
            &mut RegistryTopology::new(2).unwrap(),
            &mut PublicationAllocator::new(),
            DwHandle(40),
            devmgr(),
            9,
            StatusCode::OperationalWaitingForDeviceBundle,
            None,
        )
        .unwrap_err();
        assert_eq!(error, InitError::Native(FAILURE));
        assert_eq!(&platform.closed[..platform.close_count], &[DwHandle(51)]);
    }

    #[test]
    fn failed_rebind_status_is_reported_after_both_moves_commit() {
        let mut platform = RebindPlatform::with_status(waiting_device_status());
        let error = perform_rebind(
            &mut platform,
            &mut StatusWaits { fail: true },
            &mut RegistryTopology::new(2).unwrap(),
            &mut PublicationAllocator::new(),
            DwHandle(40),
            devmgr(),
            9,
            StatusCode::OperationalWaitingForDeviceBundle,
            None,
        )
        .unwrap_err();
        assert_eq!(error, InitError::Native(FAILURE));
        assert_eq!(platform.send_count, 2);
        assert_eq!(platform.close_count, 0);
    }

    #[test]
    fn publication_peer_close_status_requires_exact_generation_and_transaction() {
        let message = ControllerMessage::Status {
            supervisor_generation: SupervisorGeneration(7),
            binding: None,
            transaction_id: 8,
            status: StatusCode::OperationalWaitingForRegistry,
            attempt_generation: None,
        };
        let mut platform = RebindPlatform::with_status(message);
        receive_waiting_for_registry(&mut platform, devmgr(), 7, 8).unwrap();

        let mut stale = RebindPlatform::with_status(message);
        assert_eq!(
            receive_waiting_for_registry(&mut stale, devmgr(), 7, 9),
            Err(InitError::WrongManifestProfile)
        );
    }

    #[test]
    fn resident_poll_distinguishes_devmgr_and_registry_failures() {
        let event = |index, observed| {
            classify_resident_poll(
                DwWaitResultV1 {
                    index,
                    observed,
                    ..DwWaitResultV1::default()
                },
                true,
                false,
            )
            .unwrap()
        };
        assert_eq!(event(0, DW_SIGNAL_EXITED), ResidentPollEvent::DevmgrExited);
        assert_eq!(
            event(1, DW_SIGNAL_PEER_CLOSED),
            ResidentPollEvent::DevmgrControlLost
        );
        assert_eq!(
            event(1, DW_SIGNAL_READABLE),
            ResidentPollEvent::DevmgrControlReadable
        );
        assert_eq!(
            event(2, DW_SIGNAL_PEER_CLOSED),
            ResidentPollEvent::RegistryControlLost
        );
        assert_eq!(
            event(3, DW_SIGNAL_EXITED),
            ResidentPollEvent::RegistryExited
        );
    }

    #[test]
    fn registry_exhaustion_enters_degraded_without_a_stale_status_wait() {
        assert_eq!(
            registry_recovery_step(true, false),
            RegistryRecoveryStep::Degraded
        );
        assert_eq!(
            registry_recovery_step(false, false),
            RegistryRecoveryStep::AwaitStatus
        );
        assert_eq!(
            registry_recovery_step(false, true),
            RegistryRecoveryStep::Restart
        );
    }

    #[test]
    fn publication_correlations_advance_across_devmgr_and_registry_recovery() {
        let mut allocator = PublicationAllocator::new();
        let initial = allocator.issue().unwrap();
        let after_devmgr_exit = allocator.issue().unwrap();
        let after_registry_exit = allocator.issue().unwrap();

        assert!(after_devmgr_exit.publication_id > initial.publication_id);
        assert!(after_devmgr_exit.service_generation > initial.service_generation);
        assert!(after_devmgr_exit.transaction_id > initial.transaction_id);
        assert!(after_registry_exit.publication_id > after_devmgr_exit.publication_id);
        assert!(after_registry_exit.service_generation > after_devmgr_exit.service_generation);
        assert!(after_registry_exit.transaction_id > after_devmgr_exit.transaction_id);
        assert_ne!(initial.publication_id, initial.service_generation);
        assert_ne!(initial.publication_id, initial.transaction_id);
        assert_ne!(initial.service_generation, initial.transaction_id);
    }

    #[cfg(feature = "wyr1c6-selector29")]
    #[test]
    fn c6_publication_records_use_service_generation_not_registry_generation() {
        let registry_generation = 7;
        let p1_service_generation = 0xC1_0801;
        let p2_service_generation = 0xC1_0802;

        assert_eq!(
            c6_evidence_binding(5, registry_generation, p1_service_generation, 0, 0),
            p1_service_generation
        );
        assert_eq!(
            c6_evidence_binding(
                7,
                registry_generation,
                p2_service_generation,
                p1_service_generation,
                0,
            ),
            p1_service_generation
        );
        assert_eq!(
            c6_evidence_binding(
                12,
                registry_generation,
                p2_service_generation,
                p1_service_generation,
                0,
            ),
            p2_service_generation
        );
        assert_eq!(
            c6_evidence_binding(
                14,
                registry_generation,
                p2_service_generation,
                p1_service_generation,
                p2_service_generation,
            ),
            p2_service_generation
        );
        assert!(p2_service_generation > p1_service_generation);
        assert_ne!(p1_service_generation, registry_generation);
    }

    fn wrdm(identity: [u8; 32]) -> [u8; WRDM_HEADER_BYTES + WRDM_RECORD_BYTES] {
        let mut out = [0; WRDM_HEADER_BYTES + WRDM_RECORD_BYTES];
        out[..4].copy_from_slice(&WRDM_MAGIC);
        out[4..6].copy_from_slice(&WRDM_MAJOR.to_le_bytes());
        out[6..8].copy_from_slice(&WRDM_MINOR.to_le_bytes());
        let total = out.len() as u32;
        out[8..12].copy_from_slice(&total.to_le_bytes());
        out[12..14].copy_from_slice(&1u16.to_le_bytes());
        out[16..20].copy_from_slice(&PROFILE_Q35.0.to_le_bytes());
        out[20..24].copy_from_slice(&PROFILE_Q35_VERSION.0.to_le_bytes());
        let base = WRDM_HEADER_BYTES;
        out[base..base + 8].copy_from_slice(&1u64.to_le_bytes());
        out[base + 8..base + 12].copy_from_slice(&2u32.to_le_bytes());
        out[base + 12..base + 16].copy_from_slice(&1u32.to_le_bytes());
        out[base + 16..base + 18].copy_from_slice(&0x2f8u16.to_le_bytes());
        out[base + 18..base + 20].copy_from_slice(&8u16.to_le_bytes());
        out[base + 20..base + 24].copy_from_slice(&3u32.to_le_bytes());
        out[base + 24..base + 26].copy_from_slice(&(UART16550D_PATH.len() as u16).to_le_bytes());
        out[base + 28..base + 60].copy_from_slice(&identity);
        out[base + 60..base + 64].copy_from_slice(&1u32.to_le_bytes());
        out[base + 72..base + 72 + UART16550D_PATH.len()].copy_from_slice(UART16550D_PATH);
        out
    }

    #[test]
    fn wrdm_uart_identity_must_match_the_independent_wrrm_identity() {
        let bytes = wrdm([7; 32]);
        let manifest = DeviceManifest::parse(&bytes).unwrap();
        validate_device_identity(manifest, [7; 32]).unwrap();
        assert_eq!(
            validate_device_identity(manifest, [8; 32]),
            Err(InitError::WrongManifestProfile)
        );
    }

    struct ControlInputPlatform {
        inbound: [u8; LAUNCH_REQUEST_BYTES],
        inbound_len: usize,
        received: DwReceivedHandleInfoV1,
        received_count: usize,
        queried: CapabilityInfo<DwObjectType, DwRights>,
        closed: Option<DwHandle>,
    }

    impl InitPlatform for ControlInputPlatform {
        fn query_capability_info(
            &mut self,
            _handle: DwHandle,
        ) -> Result<CapabilityInfo<DwObjectType, DwRights>, NativeError> {
            Ok(self.queried)
        }
        fn receive_channel(
            &mut self,
            _channel: DwHandle,
            bytes: &mut [u8],
            handles: &mut [DwReceivedHandleInfoV1],
        ) -> Result<ReceiveCounts, NativeError> {
            bytes[..self.inbound_len].copy_from_slice(&self.inbound[..self.inbound_len]);
            if self.received_count == 1 {
                handles[0] = self.received;
            }
            Ok(ReceiveCounts {
                bytes: self.inbound_len,
                handles: self.received_count,
            })
        }
        fn query_memory_object_size(&mut self, _handle: DwHandle) -> Result<u64, NativeError> {
            Err(FAILURE)
        }
        fn with_bootfs_bytes<R>(
            &mut self,
            _root: DwHandle,
            _bootfs: DwHandle,
            _plan: MappingPlan,
            _use_bytes: impl for<'a> FnOnce(&mut Self, &'a [u8]) -> R,
        ) -> Result<R, NativeError> {
            Err(FAILURE)
        }
        fn send_channel(&mut self, _channel: DwHandle, _bytes: &[u8]) -> Result<(), NativeError> {
            Err(FAILURE)
        }
        fn close_handle(&mut self, handle: DwHandle) -> Result<(), NativeError> {
            self.closed = Some(handle);
            Ok(())
        }
        fn create_attempt_task_group(
            &mut self,
            _parent: DwHandle,
        ) -> Result<DwHandle, NativeError> {
            Err(FAILURE)
        }
        fn terminate_task_group(&mut self, _task_group: DwHandle) -> Result<(), NativeError> {
            Err(FAILURE)
        }
        fn now(&mut self) -> Result<u64, NativeError> {
            Err(FAILURE)
        }
        fn wait_until(&mut self, _deadline_ns: u64) -> Result<(), NativeError> {
            Err(FAILURE)
        }
    }

    fn driver_request() -> DriverLaunchRequest {
        DriverLaunchRequest {
            supervisor_generation: SupervisorGeneration(7),
            role_id: COM2_ROLE_ID,
            attempt_generation: wyrmroot_device_proto::coordinator::AttemptGeneration(1),
            launch_session: wyrmroot_device_proto::coordinator::LaunchSessionGeneration(2),
            endpoint: wyrmroot_device_proto::ControlEndpoint {
                id: wyrmroot_device_proto::coordinator::EndpointId(3),
                generation: wyrmroot_device_proto::coordinator::EndpointGeneration(1),
            },
            transaction_id: 9,
            driver_path: wyrmroot_device_proto::DEVICE_DRIVER_PATH,
            actor_identity: ContentIdentity([0x5a; 32]),
            child_is_channel: true,
            child_rights: wyrmroot_device_proto::DirectControlRights::ExactReduced,
        }
    }

    fn control_input_platform(request: DriverLaunchRequest) -> ControlInputPlatform {
        let mut inbound = [0u8; LAUNCH_REQUEST_BYTES];
        wyrmroot_device_proto::encode_request(request, &mut inbound).unwrap();
        ControlInputPlatform {
            inbound,
            inbound_len: LAUNCH_REQUEST_BYTES,
            received: DwReceivedHandleInfoV1 {
                handle: DwHandle(91),
                object_type: DW_OBJECT_TYPE_CHANNEL,
                rights: DRIVER_CONTROL_INGRESS_RIGHTS,
                reserved0: 0,
                reserved: [0; 2],
            },
            received_count: 1,
            queried: CapabilityInfo {
                object_type: DW_OBJECT_TYPE_CHANNEL,
                rights: DRIVER_CONTROL_INGRESS_RIGHTS,
            },
            closed: None,
        }
    }

    #[test]
    fn native_driver_request_dispatch_moves_exactly_one_reduced_channel() {
        let request = driver_request();
        let mut platform = control_input_platform(request);
        assert_eq!(
            receive_devmgr_control(&mut platform, DwHandle(12)).unwrap(),
            DevmgrControlInput::DriverLaunch {
                request,
                child_endpoint: DwHandle(91),
            }
        );
        assert_eq!(platform.closed, None);
    }

    #[cfg(feature = "wyr1c5-production")]
    #[test]
    fn native_driver_request_requires_transfer_staging_before_actor_reduction() {
        assert_eq!(DRIVER_CONTROL_INGRESS_RIGHTS.0, 0x193);
        assert_eq!(CHILD_CHANNEL_RIGHTS.0, 0x113);
        assert_ne!(
            DRIVER_CONTROL_INGRESS_RIGHTS.0 & deepwyrm_syscall::DW_RIGHT_TRANSFER.0,
            0
        );

        let mut final_actor_rights_are_not_staging = control_input_platform(driver_request());
        final_actor_rights_are_not_staging.received.rights = CHILD_CHANNEL_RIGHTS;
        final_actor_rights_are_not_staging.queried.rights = CHILD_CHANNEL_RIGHTS;
        assert_eq!(
            receive_devmgr_control(&mut final_actor_rights_are_not_staging, DwHandle(12)),
            Err(InitError::ResourceIdentityMismatch)
        );
        assert_eq!(
            final_actor_rights_are_not_staging.closed,
            Some(DwHandle(91))
        );
    }

    #[test]
    fn native_driver_request_rejects_wrong_received_type_or_rights() {
        let mut wrong_rights = control_input_platform(driver_request());
        wrong_rights.received.rights = DEVICE_MANIFEST_RIGHTS;
        assert_eq!(
            receive_devmgr_control(&mut wrong_rights, DwHandle(12)),
            Err(InitError::ResourceIdentityMismatch)
        );
        assert_eq!(wrong_rights.closed, Some(DwHandle(91)));

        let mut wrong_type = control_input_platform(driver_request());
        wrong_type.received.object_type = deepwyrm_syscall::DW_OBJECT_TYPE_MEMORY_OBJECT;
        assert_eq!(
            receive_devmgr_control(&mut wrong_type, DwHandle(12)),
            Err(InitError::ResourceIdentityMismatch)
        );
        assert_eq!(wrong_type.closed, Some(DwHandle(91)));
    }

    #[test]
    fn native_driver_correlation_rejects_replay_and_supervisor_replacement() {
        let request = driver_request();
        assert!(driver_correlation_is_fresh(7, 0, 0, 0, 0, request));
        assert!(!driver_correlation_is_fresh(8, 0, 0, 0, 0, request));
        assert!(!driver_correlation_is_fresh(7, 1, 0, 0, 0, request));
        assert!(!driver_correlation_is_fresh(7, 0, 2, 0, 0, request));
        assert!(!driver_correlation_is_fresh(7, 0, 0, 3, 0, request));
        assert!(!driver_correlation_is_fresh(7, 0, 0, 0, 9, request));

        let mut stale_endpoint_generation = request;
        stale_endpoint_generation.endpoint.generation =
            wyrmroot_device_proto::coordinator::EndpointGeneration(2);
        assert!(!driver_correlation_is_fresh(
            7,
            0,
            0,
            0,
            0,
            stale_endpoint_generation,
        ));
    }

    #[test]
    fn native_replacement_accepts_first_fresh_namespace_and_rejects_old_endpoint() {
        let mut old = driver_request();
        let old_namespace = 7 * (1u64 << 32);
        old.attempt_generation.0 = old_namespace + 1;
        old.launch_session.0 = old_namespace + (1u64 << 30) + 1;
        old.endpoint.id.0 = old_namespace + (2u64 << 30) + 1;
        old.transaction_id = old_namespace + (3u64 << 30) + 1;

        let mut fresh = driver_request();
        let fresh_namespace = 8 * (1u64 << 32);
        fresh.supervisor_generation = SupervisorGeneration(8);
        fresh.attempt_generation.0 = fresh_namespace + 1;
        fresh.launch_session.0 = fresh_namespace + (1u64 << 30) + 1;
        fresh.endpoint.id.0 = fresh_namespace + (2u64 << 30) + 1;
        fresh.transaction_id = fresh_namespace + (3u64 << 30) + 1;

        assert!(driver_correlation_is_fresh(
            8,
            old.attempt_generation.0,
            old.launch_session.0,
            old.endpoint.id.0,
            old.transaction_id,
            fresh,
        ));
        assert!(!driver_correlation_is_fresh(
            8,
            old.attempt_generation.0,
            old.launch_session.0,
            old.endpoint.id.0,
            old.transaction_id,
            old,
        ));
    }

    #[test]
    fn resident_poll_observes_driver_exit_separately_from_registry_exit() {
        assert_eq!(
            classify_resident_poll(
                DwWaitResultV1 {
                    index: 4,
                    observed: DW_SIGNAL_EXITED,
                    ..DwWaitResultV1::default()
                },
                true,
                true,
            ),
            Ok(ResidentPollEvent::DriverExited)
        );
        assert_eq!(
            classify_resident_poll(
                DwWaitResultV1 {
                    index: 2,
                    observed: DW_SIGNAL_EXITED,
                    ..DwWaitResultV1::default()
                },
                false,
                true,
            ),
            Ok(ResidentPollEvent::DriverExited)
        );
    }

    #[cfg(feature = "wyr1c6-selector29")]
    #[test]
    fn selector29_d1_restart_survives_u2_reaping_but_not_d2_replacement() {
        let mut u1 = driver_request();
        u1.supervisor_generation = SupervisorGeneration(1);
        u1.attempt_generation = wyrmroot_device_proto::coordinator::AttemptGeneration(
            wyrmroot_device_proto::SELECTOR29_FAILURE_ATTEMPT_GENERATION,
        );
        let mut u2 = u1;
        u2.attempt_generation.0 += 1;

        assert!(selector29_restarting_d1(1, Some(u2), Some(u1)));
        assert!(selector29_restarting_d1(1, None, Some(u2)));
        assert!(!selector29_restarting_d1(1, None, Some(u1)));
        assert!(!selector29_restarting_d1(2, None, Some(u2)));
    }

    #[cfg(feature = "wyr1c6-selector29")]
    #[test]
    fn selector29_d1_exit_drains_stale_and_failure_before_p2_retirement() {
        assert_eq!(
            selector29_terminal_fact_for_event(crate::wyr1c6_gate::GateEvent::StaleReject),
            Ok(Some(13))
        );
        assert_eq!(
            selector29_terminal_fact_for_event(crate::wyr1c6_gate::GateEvent::D1Failure),
            Ok(Some(14))
        );
        assert_eq!(
            selector29_terminal_fact_for_event(crate::wyr1c6_gate::GateEvent::P2Retire),
            Ok(None)
        );
        assert_eq!(
            selector29_terminal_fact_for_event(crate::wyr1c6_gate::GateEvent::P2Publish),
            Err(InitError::WrongManifestProfile)
        );
    }
}
