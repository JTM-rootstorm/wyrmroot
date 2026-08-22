//! Compiler-required freestanding byte primitives for the native target.

#![allow(
    unsafe_code,
    reason = "these target-only symbols implement the compiler's raw-pointer memory contracts without a hosted runtime"
)]

use core::ffi::{c_int, c_void};

/// Copies `length` non-overlapping bytes and returns `destination`.
///
/// # Safety
///
/// Both ranges must be valid for `length` bytes and must not overlap.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn memcpy(
    destination: *mut c_void,
    source: *const c_void,
    length: usize,
) -> *mut c_void {
    let source = source.cast::<u8>();
    let destination_bytes = destination.cast::<u8>();
    for index in 0..length {
        // SAFETY: the caller supplies non-overlapping ranges valid through `length`. Volatile
        // scalar operations prevent the compiler from lowering this defining symbol back into a
        // recursive call to `memcpy`.
        let byte = unsafe { source.add(index).read_volatile() };
        // SAFETY: the caller supplies the compiler-defined writable destination range.
        unsafe { destination_bytes.add(index).write_volatile(byte) };
    }
    destination
}

/// Copies `length` possibly overlapping bytes and returns `destination`.
///
/// # Safety
///
/// Both ranges must be valid for `length` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn memmove(
    destination: *mut c_void,
    source: *const c_void,
    length: usize,
) -> *mut c_void {
    let source = source.cast::<u8>();
    let destination_bytes = destination.cast::<u8>();
    if destination_bytes.addr() <= source.addr() {
        for index in 0..length {
            // SAFETY: forward traversal is valid when the destination does not begin above the
            // source. Volatile scalar operations avoid recursive `memmove` lowering.
            let byte = unsafe { source.add(index).read_volatile() };
            // SAFETY: the caller supplies a writable destination range through `length`.
            unsafe { destination_bytes.add(index).write_volatile(byte) };
        }
    } else {
        for index in (0..length).rev() {
            // SAFETY: backward traversal preserves an overlapping source below the destination.
            let byte = unsafe { source.add(index).read_volatile() };
            // SAFETY: the caller supplies a writable destination range through `length`.
            unsafe { destination_bytes.add(index).write_volatile(byte) };
        }
    }
    destination
}

/// Fills `length` bytes with the low byte of `value` and returns `destination`.
///
/// # Safety
///
/// `destination` must be valid for writes of `length` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn memset(
    destination: *mut c_void,
    value: c_int,
    length: usize,
) -> *mut c_void {
    let destination_bytes = destination.cast::<u8>();
    for index in 0..length {
        // SAFETY: the caller supplies a writable destination range through `length`. Volatile
        // scalar operations avoid recursive `memset` lowering.
        unsafe { destination_bytes.add(index).write_volatile(value as u8) };
    }
    destination
}

/// Lexicographically compares `length` bytes from two valid ranges.
///
/// # Safety
///
/// Both ranges must be valid for reads of `length` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn memcmp(left: *const c_void, right: *const c_void, length: usize) -> c_int {
    let left = left.cast::<u8>();
    let right = right.cast::<u8>();
    for index in 0..length {
        // SAFETY: both caller-provided ranges are readable through `length` bytes.
        let left_byte = unsafe { left.add(index).read() };
        // SAFETY: both caller-provided ranges are readable through `length` bytes.
        let right_byte = unsafe { right.add(index).read() };
        if left_byte != right_byte {
            return c_int::from(left_byte) - c_int::from(right_byte);
        }
    }
    0
}
