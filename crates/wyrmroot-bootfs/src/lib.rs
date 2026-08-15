//! Bootstrap archive support for Wyrmroot.
//!
//! This crate is a WYR0 bootstrap placeholder. Archive construction, hostile-input parsing,
//! path handling, and lookup behavior are intentionally not implemented yet.
//!
//! The three modules keep the eventual host builder and native parser responsibilities separate.
//! They currently expose no format policy or public implementation.

#![no_std]
#![forbid(unsafe_code)]

mod archive;
mod builder;
mod path;
