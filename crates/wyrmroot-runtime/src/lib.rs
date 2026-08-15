//! Minimal native runtime support for Wyrmroot.
//!
//! This WYR0-A crate establishes only a compile-time native-runtime boundary. Its empty
//! dependency set and `no_std` build make host `std`, libc, and POSIX APIs unavailable to the
//! crate. The native guest ABI is not available yet, so it deliberately exposes no startup,
//! allocation, syscall, diagnostic, or process-exit behavior.
//!
//! Once the canonical Deepwyrm ABI is consumable, WYR0-D may add narrow native implementations
//! behind these module boundaries. It must not turn this crate into a libc replacement or infer
//! bootstrap capabilities from ambient handles or environment strings.

#![no_std]
#![deny(unsafe_code)]
#![deny(unused_crate_dependencies)]

mod bootstrap;
mod diagnostics;
mod startup;
