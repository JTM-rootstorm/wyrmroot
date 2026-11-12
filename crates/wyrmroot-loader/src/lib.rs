//! Bounded userspace executable-loading support for Wyrmroot.

#![no_std]
#![forbid(unsafe_code)]

pub mod elf;
pub mod image;
/// The launch protocol, which lives in its own crate so SDK programs can
/// link it under the Classpath exception.
pub use wyrmroot_startup_proto as launch;
pub mod process;
