//! Userspace executable-loading support for Wyrmroot.
//!
//! This crate is a WYR0 bootstrap placeholder. Hostile-input ELF parsing, image layout,
//! process mapping, capability delegation, and launch behavior are intentionally not
//! implemented yet.

#![no_std]

mod elf;
mod image;
mod process;
