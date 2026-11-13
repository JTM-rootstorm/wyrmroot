//! Deepwyrm/Wyrmroot ABI pairing (root `CLAUDE.md` §7).
//!
//! Wyrmroot compiles against the generated `deepwyrm-abi` and
//! `deepwyrm-syscall` crates at the pinned Deepwyrm revision, the canonical
//! `[deepwyrm]` record in `toolchain/versions.toml`. The product kernel is
//! built from the Deepwyrm checkout's working tree, which may be at another
//! revision. The two pair when that checkout's semantic ABI fingerprint,
//! Deepwyrm's generated `abi/generated/abi_fingerprint.toml`, is the pinned
//! `[deepwyrm] abi_fingerprint`. [`require`] checks that, and
//! `product::build` calls it before anything is built, so `xtask product` and
//! `xtask dev-boot` both refuse an unpaired kernel.
//!
//! The fingerprint covers syscall numbers, arguments, directions and rights,
//! objects, rights, signals, statuses, boot enumerations, constants and record
//! layouts. It excludes documentation text, so a documentation-only schema
//! edit leaves it unchanged and needs no repin.
//!
//! The fingerprint file is read from the checkout, not from Git, because the
//! kernel is built from the working tree. It is treated as hostile: it must
//! be a small regular file that resolves inside the checkout, in exactly the
//! encoding below, and anything else fails closed.

use std::fs;
use std::path::Path;

use crate::error::Failure;

/// Path of the generated fingerprint inside a Deepwyrm checkout.
pub(crate) const FINGERPRINT_PATH: &str = "abi/generated/abi_fingerprint.toml";
/// The only fingerprint encoding this consumer accepts.
pub(crate) const FINGERPRINT_SCHEMA: &str = "deepwyrm-abi-fingerprint-v1";
const MAX_FINGERPRINT_BYTES: u64 = 4096;

/// Refuses a kernel checkout whose ABI fingerprint is not the pinned one, and
/// returns the fingerprint otherwise.
///
/// `deep_repository` is the canonical path of the Deepwyrm checkout the kernel
/// is built from and `deep_revision` its HEAD, which only labels the error.
pub(crate) fn require(
    deep_repository: &Path,
    deep_revision: &str,
    pinned_fingerprint: &str,
) -> Result<String, Failure> {
    if !is_lower_hex(pinned_fingerprint, 64) {
        return Err(Failure::task(
            "the pinned [deepwyrm] abi_fingerprint is not 64 lowercase hexadecimal digits",
        ));
    }
    let refused = |reason: String| {
        Failure::task(format!(
            "the Deepwyrm checkout at {} (HEAD {deep_revision}) cannot be paired: {reason}",
            deep_repository.display()
        ))
    };
    let path = deep_repository.join(FINGERPRINT_PATH);
    // A linked `abi` or `abi/generated` would let the file come from outside
    // the checkout; the final component is refused by the no-follow read.
    let parent = path
        .parent()
        .and_then(|parent| fs::canonicalize(parent).ok())
        .ok_or_else(|| refused(format!("it has no {FINGERPRINT_PATH}")))?;
    if path.parent() != Some(parent.as_path()) {
        return Err(refused(format!(
            "{FINGERPRINT_PATH} does not resolve inside the checkout"
        )));
    }
    let bytes = crate::product::read_regular_bounded(
        &path,
        MAX_FINGERPRINT_BYTES,
        "the Deepwyrm ABI fingerprint",
    )
    .map_err(|failure| refused(failure.message))?;
    let contents = String::from_utf8(bytes)
        .map_err(|_| refused(format!("{FINGERPRINT_PATH} is not UTF-8")))?;
    let kernel_fingerprint = parse_fingerprint(&contents)
        .map_err(|message| refused(format!("{FINGERPRINT_PATH} {message}")))?;
    if kernel_fingerprint != pinned_fingerprint {
        return Err(Failure::task(format!(
            "the Deepwyrm kernel does not pair with this Wyrmroot checkout:\n  \
             kernel ABI fingerprint {kernel_fingerprint} ({}, HEAD {deep_revision})\n  \
             pinned ABI fingerprint {pinned_fingerprint} (toolchain/versions.toml [deepwyrm])\n\
             Userspace is compiled against the pinned ABI, so this kernel would run it with \
             another one. Either check out a Deepwyrm revision that carries the pinned \
             fingerprint, or repin Wyrmroot to this kernel: `revision` and `abi_fingerprint` \
             in toolchain/versions.toml, the Deepwyrm revision in Cargo.toml and Cargo.lock, \
             and wyrmroot-sdk's pin, then rebuild.",
            path.display()
        )));
    }
    Ok(kernel_fingerprint)
}

/// Strictly parses Deepwyrm's generated fingerprint file and returns the
/// digest. The file is a flat list of `key = value` lines with exactly the
/// five keys below, each once; strings are plain double-quoted.
pub(crate) fn parse_fingerprint(contents: &str) -> Result<String, String> {
    let mut schema = None;
    let mut algorithm = None;
    let mut fingerprint = None;
    let mut abi_name = None;
    let mut abi_version = None;
    for line in contents.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (key, value) = line
            .split_once(" = ")
            .ok_or_else(|| "has a malformed line".to_owned())?;
        let slot = match key {
            "schema" => &mut schema,
            "algorithm" => &mut algorithm,
            "fingerprint" => &mut fingerprint,
            "abi_name" => &mut abi_name,
            "abi_version" => &mut abi_version,
            _ => return Err("has an unsupported key".to_owned()),
        };
        if slot.replace(value).is_some() {
            return Err(format!("repeats key `{key}`"));
        }
    }
    let quoted = |value: Option<&str>, key: &str| -> Result<String, String> {
        value
            .and_then(|value| value.strip_prefix('"'))
            .and_then(|value| value.strip_suffix('"'))
            .filter(|value| !value.contains(['"', '\\']))
            .map(str::to_owned)
            .ok_or_else(|| format!("is missing quoted key `{key}`"))
    };
    if quoted(schema, "schema")? != FINGERPRINT_SCHEMA {
        return Err(format!("does not use encoding {FINGERPRINT_SCHEMA}"));
    }
    if quoted(algorithm, "algorithm")? != "sha256" {
        return Err("does not use sha256".to_owned());
    }
    quoted(abi_name, "abi_name")?;
    if abi_version
        .is_none_or(|value| value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()))
    {
        return Err("is missing an integer abi_version".to_owned());
    }
    let digest = quoted(fingerprint, "fingerprint")?;
    if !is_lower_hex(&digest, 64) {
        return Err("does not carry a 64-digit lowercase SHA-256 fingerprint".to_owned());
    }
    Ok(digest)
}

pub(crate) fn is_lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU32, Ordering};

    const HEAD: &str = "0123456789abcdef0123456789abcdef01234567";

    fn fingerprint_file(digest: &str) -> String {
        format!(
            "# @generated by abi-gen from abi/schema.\n# Do not edit this file directly.\n\n\
             schema = \"{FINGERPRINT_SCHEMA}\"\nabi_name = \"Deepwyrm\"\nabi_version = 0\n\
             algorithm = \"sha256\"\nfingerprint = \"{digest}\"\n"
        )
    }

    /// A stand-in Deepwyrm checkout in a temporary directory.
    struct Checkout(PathBuf);

    impl Checkout {
        fn empty() -> Self {
            static NEXT: AtomicU32 = AtomicU32::new(0);
            let root = std::env::temp_dir().join(format!(
                "xtask-abi-pairing-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            let _ = fs::remove_dir_all(&root);
            fs::create_dir_all(&root).unwrap();
            Self(fs::canonicalize(&root).unwrap())
        }

        fn with(contents: &str) -> Self {
            let checkout = Self::empty();
            fs::create_dir_all(checkout.0.join("abi/generated")).unwrap();
            fs::write(checkout.0.join(FINGERPRINT_PATH), contents).unwrap();
            checkout
        }

        fn require(&self, pinned: &str) -> Result<String, Failure> {
            require(&self.0, HEAD, pinned)
        }
    }

    impl Drop for Checkout {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn a_kernel_with_the_pinned_fingerprint_pairs() {
        let pinned = "ab".repeat(32);
        let checkout = Checkout::with(&fingerprint_file(&pinned));
        assert_eq!(checkout.require(&pinned), Ok(pinned));
    }

    #[test]
    fn a_kernel_with_another_fingerprint_is_refused_and_both_are_named() {
        let (kernel, pinned) = ("cd".repeat(32), "ab".repeat(32));
        let checkout = Checkout::with(&fingerprint_file(&kernel));
        let message = checkout.require(&pinned).unwrap_err().message;
        for part in [
            kernel.as_str(),
            pinned.as_str(),
            HEAD,
            checkout.0.to_str().unwrap(),
            "repin",
        ] {
            assert!(message.contains(part), "{message} lacks {part}");
        }
    }

    #[test]
    fn a_checkout_without_a_fingerprint_is_refused() {
        let pinned = "ab".repeat(32);
        assert!(Checkout::empty().require(&pinned).is_err());
        let checkout = Checkout::empty();
        fs::create_dir_all(checkout.0.join("abi/generated")).unwrap();
        assert!(checkout.require(&pinned).is_err());
        // A directory, and an empty file, where the fingerprint belongs.
        fs::create_dir(checkout.0.join(FINGERPRINT_PATH)).unwrap();
        assert!(checkout.require(&pinned).is_err());
        assert!(Checkout::with("").require(&pinned).is_err());
    }

    #[test]
    fn a_malformed_fingerprint_file_is_refused() {
        let digest = "ab".repeat(32);
        for (from, to) in [
            (FINGERPRINT_SCHEMA, "deepwyrm-abi-fingerprint-v2"),
            ("algorithm = \"sha256\"", "algorithm = \"sha1\""),
            (digest.as_str(), &"AB".repeat(32)),
            (digest.as_str(), &"ab".repeat(20)),
            (digest.as_str(), &"ab".repeat(33)),
            (digest.as_str(), &"zz".repeat(32)),
            ("abi_version = 0", "abi_version = zero"),
            ("abi_version = 0\n", ""),
            ("schema = ", "[table]\nschema = "),
            (
                "abi_name = \"Deepwyrm\"\n",
                "abi_name = \"Deepwyrm\"\nextra = \"x\"\n",
            ),
            (
                "algorithm = \"sha256\"\n",
                "algorithm = \"sha256\"\nalgorithm = \"sha256\"\n",
            ),
            ("fingerprint = ", "fingerprint="),
            ("fingerprint = \"", "fingerprint = "),
            ("fingerprint = ", "not toml at all "),
        ] {
            let mutated = fingerprint_file(&digest).replacen(from, to, 1);
            assert_ne!(mutated, fingerprint_file(&digest));
            let checkout = Checkout::with(&mutated);
            assert!(checkout.require(&digest).is_err(), "accepted {to}");
        }
        let not_utf8 = Checkout::empty();
        fs::create_dir_all(not_utf8.0.join("abi/generated")).unwrap();
        fs::write(not_utf8.0.join(FINGERPRINT_PATH), [0xff, 0xfe, b'\n']).unwrap();
        assert!(not_utf8.require(&digest).is_err());
    }

    #[test]
    fn an_oversized_fingerprint_file_is_refused() {
        let digest = "ab".repeat(32);
        let padded = format!("{}{}", "# padding\n".repeat(500), fingerprint_file(&digest));
        assert!(Checkout::with(&padded).require(&digest).is_err());
    }

    #[test]
    fn a_fingerprint_reached_through_a_link_is_refused() {
        use std::os::unix::fs::symlink;
        let digest = "ab".repeat(32);
        let elsewhere = Checkout::with(&fingerprint_file(&digest));

        let linked_file = Checkout::empty();
        fs::create_dir_all(linked_file.0.join("abi/generated")).unwrap();
        symlink(
            elsewhere.0.join(FINGERPRINT_PATH),
            linked_file.0.join(FINGERPRINT_PATH),
        )
        .unwrap();
        assert!(linked_file.require(&digest).is_err());

        let linked_directory = Checkout::empty();
        symlink(elsewhere.0.join("abi"), linked_directory.0.join("abi")).unwrap();
        assert!(linked_directory.require(&digest).is_err());
    }

    #[test]
    fn a_malformed_pin_is_refused() {
        let digest = "ab".repeat(32);
        let checkout = Checkout::with(&fingerprint_file(&digest));
        assert!(checkout.require(&"AB".repeat(32)).is_err());
        assert!(checkout.require(&"ab".repeat(20)).is_err());
    }
}
