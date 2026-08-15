//! Inert boundary for the future Wyrmroot EFI loader.
//!
//! This crate intentionally contains no executable entry point, firmware calls,
//! boot protocol definitions, or loading behavior. See the loader README and the
//! canonical WYR0 plans before adding implementation.

#![no_std]
#![forbid(unsafe_code)]
