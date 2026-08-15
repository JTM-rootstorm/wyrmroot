//! Minimal native runtime support for Wyrmroot.
//!
//! This crate is a WYR0 bootstrap placeholder. Startup parsing, bootstrap-capability access,
//! allocation, syscall access, diagnostics, and process exit are intentionally not implemented
//! yet. This is a native runtime boundary, not a libc implementation.

#![no_std]

mod bootstrap;
mod diagnostics;
mod startup;
