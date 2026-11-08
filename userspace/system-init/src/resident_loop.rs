//! Permanent init's resident loop: tick, drain each selector's evidence, wait.
//!
//! Structural refactor S3. This was `continue_resident` in `main.rs`, whose
//! host build only type-checks the guest entry, so nothing on the host could
//! run it. It now takes its platform as a parameter like the rest of the
//! crate; `main.rs` supplies `NativeSystem`, whose evidence submissions are the
//! runtime's syscall wrappers.

use super::*;

/// Selector 34's evidence sink, which the loop's platform must provide only in
/// the build that relays R1 records.
#[cfg(feature = "r1-selector34")]
pub use crate::r1_relay::R1EvidenceSink as ResidentR1Sink;

/// Selector 34's evidence sink, which every platform trivially provides in a
/// build that relays no R1 records.
#[cfg(not(feature = "r1-selector34"))]
pub trait ResidentR1Sink {}

#[cfg(not(feature = "r1-selector34"))]
impl<T: ?Sized> ResidentR1Sink for T {}

/// The resident loop's platform: the WYR1-B operations, plus the evidence
/// submission each selector's drain makes.
pub trait ResidentLoopPlatform: Wyr1BPlatform + ResidentR1Sink {
    #[cfg(feature = "wyr1-test-evidence")]
    fn submit_wyr1_evidence(&mut self, record: &[u8; 114]) -> Result<(), NativeError>;

    #[cfg(feature = "wyr1b-test-evidence")]
    fn submit_wyr1b_evidence(
        &mut self,
        record: &[u8; wyr1b_gate::RECORD_BYTES],
    ) -> Result<(), NativeError>;

    #[cfg(feature = "wyr1c6-selector29")]
    fn submit_wyr1c6_evidence(
        &mut self,
        record: &[u8; wyr1c6_gate::RECORD_BYTES],
    ) -> Result<(), NativeError>;
}

/// The period of the resident loop's tick.
#[cfg(any(
    feature = "wyr1c6-selector29",
    feature = "dw1e3-selector31",
    feature = "wyr1d-selector32",
    feature = "wyr1e-production"
))]
pub const RESIDENT_TICK_NS: u64 = WYR0_I_SUPERVISION_POLICY.backoff_ns;
/// The period of the resident loop's tick.
#[cfg(not(any(
    feature = "wyr1c6-selector29",
    feature = "dw1e3-selector31",
    feature = "wyr1d-selector32",
    feature = "wyr1e-production"
)))]
pub const RESIDENT_TICK_NS: u64 = 1_000_000_000;

// Selectors 29, 31 and 32 run handshakes inside the resident loop, and a
// 1 s tick leaves them no headroom against their peers' deadlines: they tick
// at the supervision policy's backoff. The `selectors` host gate checks the
// library in each of these shapes, so losing one from the list above fails
// to build there.
#[cfg(any(
    feature = "wyr1c6-selector29",
    feature = "dw1e3-selector31",
    feature = "wyr1d-selector32"
))]
const _: () = assert!(
    RESIDENT_TICK_NS == WYR0_I_SUPERVISION_POLICY.backoff_ns,
    "a selector with resident handshakes must tick at the supervision backoff"
);

/// Permanent init's resident loop, entered once the product has activated.
///
/// It returns only to end permanent init's process: `0` when the interactive
/// session is complete, and a failure status otherwise.
#[inline(always)]
pub fn continue_resident<S, L, W>(
    resident: &mut ResidentSystemInit,
    system: &mut S,
    loader: &mut L,
    waits: &mut W,
) -> u32
where
    S: ResidentLoopPlatform,
    L: LoaderPlatform<Error = NativeError>,
    W: SupervisionPlatform<Error = NativeError>,
{
    #[cfg(feature = "wyr1b-test-evidence")]
    {
        let mut index = 0;
        while let Some(record) = resident.wyr1b_evidence_record(index) {
            if system.submit_wyr1b_evidence(record).is_err() {
                return 0xAF1B_0001;
            }
            index += 1;
        }
    }
    // Card R1's scenario driver. Its state lives here rather than in
    // ResidentSystemInit because the probe, its launch session and its relay are
    // one selector's scenario, and no production product has a field for them.
    #[cfg(feature = "r1-selector34")]
    let mut r1 = None;
    #[cfg(feature = "wyr1-test-evidence")]
    let mut evidence_submitted = false;
    #[cfg(feature = "wyr1c6-selector29")]
    let mut c6_evidence_submitted = false;
    loop {
        let Ok(now) = InitPlatform::now(system) else {
            return 0xAF01_0003;
        };
        let tick_ns = RESIDENT_TICK_NS;
        let Some(deadline) = now.checked_add(tick_ns) else {
            return 0xAF01_0004;
        };
        if let Err(error) = resident.control_tick_product(system, loader, waits, now) {
            // A fatally failed bring-up would otherwise discard its own
            // account of itself. The ordinary drain below is gated on
            // `evidence_finalized()`, and a tick that fails never finalizes,
            // so every record produced before the failure was thrown away and
            // the only thing reaching COM1 was the application status -- one
            // error class, with no indication of how far activation got.
            //
            // Nothing is added or rewritten here: the records already encoded
            // are submitted before the failure is reported. The transcript
            // will carry no terminal record, which is correct, because the run
            // did not reach one; a consumer that requires a terminal must
            // still refuse it. Submission errors are ignored deliberately --
            // this path is already failing, and the status that explains why
            // must not be replaced by a complaint about reporting it.
            #[cfg(feature = "wyr1-test-evidence")]
            if !evidence_submitted {
                let mut index = 0;
                while let Some(line) = resident.controller().evidence_line(index) {
                    if let Ok(record) = <&[u8; 114]>::try_from(line) {
                        let _ = system.submit_wyr1_evidence(record);
                    }
                    index += 1;
                }
            }
            return resident_tick_failure_application_status(&error);
        }
        // The probe named by the staged `WRR1` gate is launched on the first tick
        // and pumped on every later one. Its records are relayed through this
        // process because the kernel accepts R1 evidence only from permanent
        // init; `r1_driver` holds the paths and the sequence.
        #[cfg(feature = "r1-selector34")]
        if let Err(error) = crate::r1_driver::drive(resident, &mut r1, system, loader, waits, now) {
            return r1_test_failure_application_status(&error);
        }
        #[cfg(feature = "wyr1c6-selector29")]
        if !c6_evidence_submitted {
            match wyr1c_native::finish_c6_evidence(resident) {
                Ok(true) => {
                    for index in 0..wyr1c6_gate::EVIDENCE_RECORDS {
                        let mut record = [0u8; wyr1c6_gate::RECORD_BYTES];
                        let Some(()) = resident.write_wyr1c6_evidence_record(index, &mut record)
                        else {
                            return 0xAF1C_0001;
                        };
                        if system.submit_wyr1c6_evidence(&record).is_err() {
                            return 0xAF1C_0002;
                        }
                    }
                    c6_evidence_submitted = true;
                }
                Ok(false) => {}
                Err(_) => return 0xAF1C_0003,
            }
        }
        #[cfg(feature = "wyr1-test-evidence")]
        if resident.evidence_finalized() && !evidence_submitted {
            let mut index = 0;
            while let Some(line) = resident.controller().evidence_line(index) {
                let Ok(record) = <&[u8; 114]>::try_from(line) else {
                    return 0xAF01_0007;
                };
                if system.submit_wyr1_evidence(record).is_err() {
                    return 0xAF01_0008;
                }
                index += 1;
            }
            evidence_submitted = true;
        }
        // F3A.7g. The one way out of this loop that is not a failure.
        //
        // It is placed after every per-product drain above rather than beside
        // the tick that sets it: an instrumented product still owes its
        // evidence records, and a session that ended is not a reason to throw
        // them away. Production compiles none of those blocks and reaches
        // here directly.
        //
        // Returning ends permanent init's process, which is what leaves the
        // system with nothing runnable -- the condition the kernel's
        // primordial completion is waiting on.
        if resident.session_complete() {
            return 0;
        }
        if InitPlatform::wait_until(system, deadline).is_err() {
            return 0xAF01_0005;
        }
    }
}
