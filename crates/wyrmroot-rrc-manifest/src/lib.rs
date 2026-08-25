//! Deterministic WRRM v1 Root Recovery Closure manifest support.
//!
//! The default parser is allocation-free and borrows every string and identity
//! from an immutable manifest byte slice. Host-side deterministic construction
//! is available through the opt-in `builder` feature.

#![no_std]
#![forbid(unsafe_code)]

#[cfg(feature = "builder")]
pub mod builder;
mod format;
mod product;

pub use format::{
    Activation, DependencyEdge, DependencyEdges, DependencyKind, EDGE_RECORD_SIZE, HEADER_SIZE,
    MANIFEST_PATH, MAX_EDGES, MAX_JUSTIFICATION_BYTES, MAX_PATH_BYTES, MAX_ROLES, MAX_STRING_BYTES,
    MAX_TOTAL_BYTES, Manifest, ParseError, ROLE_RECORD_SIZE, Role, RoleId, Roles, StartupProfile,
};
pub use product::{MaterialResidence, ProductError, RetainedMaterial, Wyr1aProductProfile};
