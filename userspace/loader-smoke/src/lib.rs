#![no_std]
#![forbid(unsafe_code)]

//! Test-only WYR0 loader protocol smoke process contract.

#[cfg(feature = "native-loader-smoke")]
use wyrmroot_loader as _;
#[cfg(feature = "native-loader-smoke")]
use wyrmroot_runtime as _;
