//! Permanent init's resident loop: tick, serve the image read, then wait for
//! the next tick.

use super::*;
use crate::image_launch::ImageService;

/// The period of the resident loop's tick.
pub(crate) const RESIDENT_TICK_NS: u64 = WYR0_I_SUPERVISION_POLICY.backoff_ns;

/// The most WRFS replies one image read consumes between two ticks. With
/// 8 KiB replies that is 512 KiB a tick, so the bound is on the work one
/// iteration can be made to do and not on any launch a filesystem would
/// serve.
const IMAGE_STEPS_PER_TICK: usize = 64;

/// What the resident loop drives: the supervisor, as the loop sees it.
///
/// The loop is written against this rather than against
/// [`ResidentSystemInit`] so the loop itself -- the scratch region's
/// lifetime, the wait between ticks -- is the code a host test runs.
pub(crate) trait ResidentTicks<S> {
    /// One supervision tick. `Err` is the application status that ends
    /// permanent init.
    fn tick(&mut self, system: &mut S, now_ns: u64) -> Result<(), u32>;
    /// Whether the interactive session ended and nothing replaces it.
    fn session_complete(&self) -> bool;
    /// Advances the parked image read by one step, without waiting.
    fn service_image(
        &mut self,
        system: &mut S,
        now_ns: u64,
        scratch: Option<&mut [u8]>,
    ) -> Result<ImageService, u32>;
    /// Fails the parked image read because its scratch region could not be
    /// mapped.
    fn refuse_image_scratch(&mut self, system: &mut S, error: NativeError) -> Result<(), u32>;
    /// The address-space root the scratch region is mapped into.
    fn scratch_root(&self) -> DwHandle;
}

/// The product supervisor behind [`ResidentTicks`].
struct ProductResident<'a, L, W> {
    resident: &'a mut ResidentSystemInit,
    loader: &'a mut L,
    waits: &'a mut W,
}

impl<S, L, W> ResidentTicks<S> for ProductResident<'_, L, W>
where
    S: ResidentPlatform,
    L: LoaderPlatform<Error = NativeError>,
    W: SupervisionPlatform<Error = NativeError>,
{
    fn tick(&mut self, system: &mut S, now_ns: u64) -> Result<(), u32> {
        self.resident
            .control_tick_product(system, self.loader, self.waits, now_ns)
            .map(|_| ())
            .map_err(|error| resident_tick_failure_application_status(&error))
    }

    fn session_complete(&self) -> bool {
        self.resident.session_complete()
    }

    fn service_image(
        &mut self,
        system: &mut S,
        now_ns: u64,
        scratch: Option<&mut [u8]>,
    ) -> Result<ImageService, u32> {
        self.resident
            .service_image_launch(system, self.loader, self.waits, now_ns, scratch)
            .map_err(|error| resident_tick_failure_application_status(&error))
    }

    fn refuse_image_scratch(&mut self, system: &mut S, error: NativeError) -> Result<(), u32> {
        self.resident
            .refuse_image_scratch(system, self.waits, error)
            .map_err(|error| resident_tick_failure_application_status(&error))
    }

    fn scratch_root(&self) -> DwHandle {
        self.resident.scratch_root()
    }
}

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
    S: ResidentPlatform,
    L: LoaderPlatform<Error = NativeError>,
    W: SupervisionPlatform<Error = NativeError>,
{
    run_resident(
        &mut ProductResident {
            resident,
            loader,
            waits,
        },
        system,
    )
}

/// How one iteration of the loop ended.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Iteration {
    /// Go round again.
    Continue,
    /// Go round again, keeping the scratch region: an image read is using
    /// it.
    ImageReading,
    /// An image read needs this many bytes of scratch before the next
    /// iteration.
    NeedsScratch(u64),
    /// Permanent init ends with this status.
    Exit(u32),
}

/// The loop proper.
///
/// An image read needs memory that lasts as long as the read does, and init
/// has no allocator: the region is `with_private_memory`'s, which exists for
/// the length of one call. So while an image is being read the loop runs
/// *inside* that call -- the same iterations, ticks included, with the
/// region in hand -- and comes back out when the read is over. Supervision
/// does not pause for it; only the region's lifetime is the read's.
pub(crate) fn run_resident<S, R>(resident: &mut R, system: &mut S) -> u32
where
    S: ResidentPlatform,
    R: ResidentTicks<S>,
{
    let mut iteration = resident_iteration(resident, system, None);
    loop {
        iteration = match iteration {
            Iteration::Continue | Iteration::ImageReading => {
                resident_iteration(resident, system, None)
            }
            Iteration::Exit(status) => return status,
            Iteration::NeedsScratch(bytes) => {
                let root = resident.scratch_root();
                let mut entered = false;
                let scoped = system.with_private_memory(root, bytes, |system, scratch| {
                    entered = true;
                    loop {
                        match resident_iteration(resident, system, Some(&mut *scratch)) {
                            Iteration::ImageReading => {}
                            ended => break ended,
                        }
                    }
                });
                match scoped {
                    Ok(ended) => ended,
                    // The region could not be mapped. That costs the launch.
                    Err(error) if !entered => match resident.refuse_image_scratch(system, error) {
                        Ok(()) => Iteration::Continue,
                        Err(status) => Iteration::Exit(status),
                    },
                    // The region was used and could not be released: a
                    // mapping in init's own address space that nothing names.
                    Err(error) => {
                        let failed = attribute_failure(
                            RecoveryOperation::ResidentTick,
                            Err::<(), _>(InitError::Native(error)),
                        );
                        match failed {
                            Err(error) => {
                                Iteration::Exit(resident_tick_failure_application_status(&error))
                            }
                            Ok(()) => Iteration::Continue,
                        }
                    }
                }
            }
        };
    }
}

/// One iteration: a tick, the image read's share of the time until the next
/// one, and the wait for it.
fn resident_iteration<S, R>(
    resident: &mut R,
    system: &mut S,
    mut scratch: Option<&mut [u8]>,
) -> Iteration
where
    S: ResidentPlatform,
    R: ResidentTicks<S>,
{
    let Ok(now) = InitPlatform::now(system) else {
        return Iteration::Exit(0xAF01_0003);
    };
    let tick_ns = RESIDENT_TICK_NS;
    let Some(deadline) = now.checked_add(tick_ns) else {
        return Iteration::Exit(0xAF01_0004);
    };
    if let Err(status) = resident.tick(system, now) {
        return Iteration::Exit(status);
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
        return Iteration::Exit(0);
    }
    // The image read has the time until the next tick is due, and no more.
    // It never holds a tick back: every wait below ends at `deadline`, and a
    // peer that answers nothing leaves the loop exactly as it was -- asleep
    // until the tick, as if no image were being read.
    let mut ended = Iteration::Continue;
    for _ in 0..IMAGE_STEPS_PER_TICK {
        let Ok(now) = InitPlatform::now(system) else {
            return Iteration::Exit(0xAF01_0003);
        };
        match resident.service_image(system, now, scratch.as_deref_mut()) {
            Err(status) => return Iteration::Exit(status),
            Ok(ImageService::Idle) => {
                ended = Iteration::Continue;
                break;
            }
            Ok(ImageService::NeedsScratch { bytes }) => {
                ended = Iteration::NeedsScratch(bytes);
                break;
            }
            Ok(ImageService::Waiting {
                file,
                holds_scratch,
            }) => {
                ended = if holds_scratch {
                    Iteration::ImageReading
                } else {
                    Iteration::Continue
                };
                if now >= deadline {
                    break;
                }
                let item = DwWaitItemV1 {
                    handle: file,
                    signals: deepwyrm_syscall::DwSignals(
                        DW_SIGNAL_READABLE.0 | DW_SIGNAL_PEER_CLOSED.0,
                    ),
                };
                match system.wait_many(core::slice::from_ref(&item), DwDeadline(deadline)) {
                    // It answered, or went away. Either is the read's next
                    // step.
                    Ok(_) => {}
                    // The tick is due.
                    Err(NativeError::Status(status)) if status == DW_STATUS_TIMED_OUT => break,
                    // The wait itself failed. The read's own poll of the
                    // same handle is where that is classified; it runs at
                    // the top of the next iteration.
                    Err(NativeError::Status(_) | NativeError::Output(_)) => break,
                }
            }
        }
    }
    if InitPlatform::wait_until(system, deadline).is_err() {
        return Iteration::Exit(0xAF01_0005);
    }
    ended
}

#[cfg(test)]
mod tests;
