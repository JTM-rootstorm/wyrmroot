//! Reset card R1's no-yield CPU hog.
//!
//! Section 8.1 requires hogs that never yield, so this payload makes **no**
//! syscall after startup: no wait, no send, no sleep, no timer. The only ways
//! it can stop are preemption and the kernel's terminate path, which is
//! precisely the behaviour card R1 is measuring. Anything else here — a
//! progress ping, a status channel, a bounded run length — would let a stalled
//! scheduler look healthy.
//!
//! Startup is the one exception and it is required: the launch profile's INIT
//! must be answered with READY inside `WYR0_I_SUPERVISION_POLICY`'s
//! `ready_timeout_ns`, and A27 failed at exactly this handshake. A hog that
//! spun before answering would make its own admission unobservable.

#![no_std]
#![no_main]
#![deny(unsafe_code)]

use core::panic::PanicInfo;

// The hog needs none of the protocol crates the probe uses; naming them keeps
// the crate-wide unused-dependency lint on for both payloads.
use deepwyrm_syscall as _;
use wyrmroot_launch_proto as _;
use wyrmroot_loader::launch::{HEADER_BYTES, LaunchProfile, encode_ready_for_profile, parse_init};
use wyrmroot_r1_saturation as _;
use wyrmroot_registry_proto as _;
use wyrmroot_runtime::{StartupBlock, panic_abort, receive_channel, send_channel};

/// Distinct from the probe's base so a serial transcript attributes a startup
/// failure to the hog rather than to its launcher.
const HOG_ERROR_BASE: u32 = 0x8101_0000;

fn hog_main(startup: StartupBlock<'_>) -> u32 {
    let channel = startup.bootstrap_channel().as_abi();
    let mut header = [0_u8; HEADER_BYTES];
    let mut handles = [];
    let Ok(counts) = receive_channel(channel, &mut header, &mut handles) else {
        return HOG_ERROR_BASE + 0x0001;
    };
    // The hog is deliberately the least authorised process in the product: the
    // Hello profile carries no handles at all, so a hog cannot launch, publish,
    // map, or reach any service even if it misbehaves.
    if counts.bytes != HEADER_BYTES || counts.handles != 0 {
        return HOG_ERROR_BASE + 0x0002;
    }
    let Ok(init) = parse_init(LaunchProfile::Hello, &header, &[]) else {
        return HOG_ERROR_BASE + 0x0003;
    };
    let mut ready = [0_u8; HEADER_BYTES];
    let Ok(size) = encode_ready_for_profile(LaunchProfile::Hello, init.transaction_id, &mut ready)
    else {
        return HOG_ERROR_BASE + 0x0004;
    };
    if send_channel(channel, &ready[..size], &[]).is_err() {
        return HOG_ERROR_BASE + 0x0005;
    }
    burn()
}

/// Consumes its CPU until something outside this process stops it.
///
/// `black_box` is load-bearing rather than decorative: without it the optimiser
/// is free to collapse the loop body, and a hog that compiles to an empty
/// backward branch tells the scheduler something different from one doing work.
/// The loop is also genuinely infinite — a bounded spin would turn a scheduler
/// stall into a hog that merely finished early.
fn burn() -> ! {
    let mut counter = 0_u64;
    loop {
        counter = core::hint::black_box(counter.wrapping_add(1));
        core::hint::spin_loop();
    }
}

wyrmroot_runtime::native_entry!(crate::hog_main);

#[panic_handler]
fn panic(_info: &PanicInfo<'_>) -> ! {
    panic_abort()
}
