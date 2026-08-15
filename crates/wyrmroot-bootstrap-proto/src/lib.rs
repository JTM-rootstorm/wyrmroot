//! Bootstrap protocol support for Wyrmroot.
//!
//! This WYR0-A crate establishes only the `no_std`, dependency-free boundary where the future
//! bootstrap protocol will live. The versioned envelope, message meanings, encoding, decoding,
//! transferred-handle expectations, and validation behavior are intentionally not defined or
//! implemented yet.
//!
//! In particular, this crate contains no provisional bytes, message IDs, versions, handle types,
//! rights, or reserved handle numbers. Those are protocol contract decisions for WYR0-D after the
//! canonical Deepwyrm/Wyrmroot handoff is available.

#![no_std]
#![deny(unsafe_code)]
#![deny(unused_crate_dependencies)]

mod envelope;
