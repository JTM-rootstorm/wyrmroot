//! The generation-neutral native-artifact build and inspect engine.
//!
//! Structural refactor S2T (`DW1_WYR1_STRUCTURAL_REFACTOR_PLAN.md` §4 S2T
//! item 1). This is a move out of `wyr1c.rs`, behavior-preserving: every item
//! below is unchanged from its previous form in that file, and `wyr1c.rs`
//! re-exports all of them (`pub(crate) use crate::product_engine::*;`) so
//! every existing `wyr1c::` path -- `wyr1c::NativeSpec`, `wyr1c::build_native`,
//! `wyr1c::inspect_native_bytes`, and so on -- keeps compiling unchanged.
//!
//! What moved here is exactly the part of `wyr1c.rs` that does not vary by
//! generation: a native binary is built the same way and inspected the same
//! way whether the caller is preparing a C6, E3A, D5, E6, E7, E8 or F product.
//! The per-generation product-spec tables, snapshot builders, product
//! assemblers and product-specific validators stay in `wyr1c.rs` (structural
//! cause 4 in the plan's §1 -- "generation unnesting" is explicitly not this
//! phase's authorized scope, so those stay nested where they were).
//!
//! Checked behavior-preserving by: `cargo test -- --list` test-count parity
//! for the `xtask` binary before and after the move, and a byte-identical
//! `wyr1f prepare --scenario normal` artifact digest set before and after
//! (both recorded in the commit that performs this move).

use std::fs;
use std::path::Path;

use crate::error::Failure;

/// The one native target every product's roles are built for.
pub(crate) const NATIVE_TARGET: &str = "x86_64-unknown-wyrmroot";
pub(crate) const MAX_ARTIFACT_BYTES: usize = 64 * 1024 * 1024;
pub(crate) const MAX_BOOTFS_BYTES: usize = crate::g3_image::IMAGE_BYTES as usize;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct NativeSpec {
    pub(crate) label: &'static str,
    pub(crate) package: &'static str,
    pub(crate) binary: &'static str,
    pub(crate) features: &'static str,
    pub(crate) artifact: &'static str,
}

pub(crate) fn native_remap_flags(
    repository: &Path,
    cargo_home: &Path,
    target: &Path,
) -> Result<String, Failure> {
    let repository = fs::canonicalize(repository)
        .map_err(|error| Failure::task(format!("could not resolve source root: {error}")))?;
    let cargo_home = fs::canonicalize(cargo_home)
        .map_err(|error| Failure::task(format!("could not resolve Cargo home: {error}")))?;
    let target = fs::canonicalize(target)
        .map_err(|error| Failure::task(format!("could not resolve target root: {error}")))?;
    Ok([
        format!(
            "--remap-path-prefix={}=/source/wyrmroot",
            repository.display()
        ),
        format!("--remap-path-prefix={}=/cargo-home", cargo_home.display()),
        format!("--remap-path-prefix={}=/cargo-target", target.display()),
    ]
    .join("\u{1f}"))
}
