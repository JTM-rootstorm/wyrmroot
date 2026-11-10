//! Permanent init's resident loop: tick, drain each selector's evidence, wait.
//!
//! Structural refactor S3. This was `continue_resident` in `main.rs`, whose
//! host build only type-checks the guest entry, so nothing on the host could
//! run it. It now takes its platform as a parameter like the rest of the
//! crate; `main.rs` supplies `NativeSystem`, whose evidence submissions are the
//! runtime's syscall wrappers.

use super::*;

/// Selector 34's evidence sink, which every platform trivially provides in a
/// build that relays no R1 records.
pub trait ResidentR1Sink {}

impl<T: ?Sized> ResidentR1Sink for T {}

/// The resident loop's platform: the WYR1-B operations, plus the evidence
/// submission each selector's drain makes.
pub trait ResidentLoopPlatform: Wyr1BPlatform + ResidentR1Sink {}

/// The period of the resident loop's tick.
#[cfg(feature = "wyr1e-production")]
pub const RESIDENT_TICK_NS: u64 = WYR0_I_SUPERVISION_POLICY.backoff_ns;
/// The period of the resident loop's tick.
#[cfg(not(feature = "wyr1e-production"))]
pub const RESIDENT_TICK_NS: u64 = 1_000_000_000;

/// Permanent init's resident loop, entered once the product has activated.
///
/// It returns only to end permanent init's process: `0` when the interactive
/// session is complete, and a failure status otherwise.
///
/// It keeps its own frame, as it had in `main.rs` before S3 moved it here:
/// the WYR1-B init27 stack preflight measures it as a designated frame.
#[inline(never)]
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
    loop {
        let Ok(now) = InitPlatform::now(system) else {
            return 0xAF01_0003;
        };
        let tick_ns = RESIDENT_TICK_NS;
        let Some(deadline) = now.checked_add(tick_ns) else {
            return 0xAF01_0004;
        };
        if let Err(error) = resident.control_tick_product(system, loader, waits, now) {
            return resident_tick_failure_application_status(&error);
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
