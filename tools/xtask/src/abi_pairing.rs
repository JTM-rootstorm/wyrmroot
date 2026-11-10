//! Deepwyrm/Wyrmroot ABI revision pairing.
//!
//! Wyrmroot compiles against the generated `deepwyrm-abi` and
//! `deepwyrm-syscall` crates at the pinned Deepwyrm revision, the canonical
//! `[deepwyrm]` record in `toolchain/versions.toml`. A product kernel may come
//! from a different Deepwyrm revision. The two pair when both revisions carry
//! the same semantic ABI fingerprint, Deepwyrm's generated
//! `abi/generated/abi_fingerprint.toml`, and that fingerprint is the pinned
//! `[deepwyrm] abi_fingerprint`.
//!
//! The fingerprint covers syscall numbers, arguments, directions and rights,
//! objects, rights, signals, statuses, boot enumerations, constants and record
//! layouts. It excludes documentation text, so a documentation-only schema
//! edit leaves it unchanged and needs no repin, although it does change the
//! `abi/` Git tree that these gates used to compare. The exact revisions and
//! both `abi` trees stay available as provenance.

pub(crate) fn is_lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
