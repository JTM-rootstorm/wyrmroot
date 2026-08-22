#![no_std]
#![forbid(unsafe_code)]

//! WYR0 `hello` smoke-test application contract.
//!
//! The D2 native executable validates the shared startup ABI and exits deterministically. Later
//! phases add diagnostic output once its delegated capability is available.

#[cfg(feature = "native-hello")]
use wyrmroot_runtime as _;
