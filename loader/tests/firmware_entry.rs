#[path = "../src/diagnostics.rs"]
mod diagnostics;
#[path = "../src/entry.rs"]
mod entry;
#[path = "../src/firmware.rs"]
mod firmware;

use diagnostics::LoaderDiagnostic;
use entry::{UefiEntryResult, enter_x86_64_uefi};
use firmware::{
    ExitBootServicesError, ExitBootServicesRetryLimit, FinalMemoryMap, Firmware, MemoryMapKey,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Event {
    Diagnostic(LoaderDiagnostic),
    Capture(u64),
    Exit(u64),
}

#[derive(Default)]
struct FakeFirmware {
    events: Vec<Event>,
    exit_results: Vec<Result<(), ExitBootServicesError<&'static str>>>,
    capture_key: u64,
}

impl FakeFirmware {
    fn with_exit_results(results: Vec<Result<(), ExitBootServicesError<&'static str>>>) -> Self {
        Self {
            exit_results: results,
            ..Self::default()
        }
    }
}

impl Firmware for FakeFirmware {
    type Error = &'static str;

    fn emit_diagnostic(&mut self, marker: LoaderDiagnostic) -> Result<(), Self::Error> {
        self.events.push(Event::Diagnostic(marker));
        Ok(())
    }

    fn capture_final_memory_map(&mut self) -> Result<FinalMemoryMap, Self::Error> {
        self.capture_key += 1;
        self.events.push(Event::Capture(self.capture_key));
        Ok(FinalMemoryMap::new(MemoryMapKey::new(self.capture_key)))
    }

    fn exit_boot_services(
        &mut self,
        key: MemoryMapKey,
    ) -> Result<(), ExitBootServicesError<Self::Error>> {
        self.events.push(Event::Exit(key.value()));
        self.exit_results.remove(0)
    }
}

#[test]
fn stale_map_retries_with_a_fresh_capture_and_no_post_capture_diagnostic() {
    let mut firmware =
        FakeFirmware::with_exit_results(vec![Err(ExitBootServicesError::StaleMemoryMap), Ok(())]);

    assert!(matches!(
        enter_x86_64_uefi(&mut firmware),
        UefiEntryResult::HandoffPending(_)
    ));

    assert_eq!(
        firmware.events,
        vec![
            Event::Diagnostic(LoaderDiagnostic::Entry),
            Event::Diagnostic(LoaderDiagnostic::FinalMemoryMapAttempt { attempt: 1 }),
            Event::Diagnostic(LoaderDiagnostic::LastHandoffMarker { attempt: 1 }),
            Event::Capture(1),
            Event::Exit(1),
            Event::Diagnostic(LoaderDiagnostic::ExitBootServicesRetry {
                rejected_attempt: 1,
            }),
            Event::Diagnostic(LoaderDiagnostic::FinalMemoryMapAttempt { attempt: 2 }),
            Event::Diagnostic(LoaderDiagnostic::LastHandoffMarker { attempt: 2 }),
            Event::Capture(2),
            Event::Exit(2),
        ]
    );
}

#[test]
fn exhausted_stale_maps_fail_closed_without_a_handoff() {
    let mut firmware = FakeFirmware::with_exit_results(vec![
        Err(ExitBootServicesError::StaleMemoryMap),
        Err(ExitBootServicesError::StaleMemoryMap),
        Err(ExitBootServicesError::StaleMemoryMap),
    ]);

    assert!(matches!(
        enter_x86_64_uefi(&mut firmware),
        UefiEntryResult::FirmwareFailure(firmware::ExitBootServicesFailure::RetryLimitExceeded)
    ));
    assert_eq!(
        firmware
            .events
            .iter()
            .filter(|event| matches!(event, Event::Capture(_)))
            .count(),
        3
    );
}

#[test]
fn non_retryable_firmware_exit_failure_blocks_handoff() {
    let mut firmware = FakeFirmware::with_exit_results(vec![Err(ExitBootServicesError::Firmware(
        "firmware refused boot-services exit",
    ))]);

    assert!(matches!(
        enter_x86_64_uefi(&mut firmware),
        UefiEntryResult::FirmwareFailure(firmware::ExitBootServicesFailure::Firmware(
            "firmware refused boot-services exit"
        ))
    ));
    assert_eq!(
        firmware
            .events
            .iter()
            .filter(|event| matches!(event, Event::Capture(_)))
            .count(),
        1
    );
}

#[test]
fn retry_policy_rejects_zero_attempts() {
    assert_eq!(ExitBootServicesRetryLimit::new(0), None);
    assert!(ExitBootServicesRetryLimit::new(1).is_some());
}
