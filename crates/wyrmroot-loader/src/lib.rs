//! Bounded userspace executable-loading support for Wyrmroot.

#![no_std]
#![forbid(unsafe_code)]

pub mod elf;
pub mod image;
mod process;
