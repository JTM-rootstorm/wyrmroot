#![no_std]
#![forbid(unsafe_code)]

//! Temporary WYR0 `init0` application contract.
//!
//! The D2 native executable validates the shared startup ABI and exits deterministically. Later
//! phases extend it with process creation and delegated bootfs loading.

#[cfg(feature = "native-init0")]
use wyrmroot_runtime as _;
