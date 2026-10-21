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

use std::path::Path;
use std::process::Command;

use crate::error::Failure;

/// Path of the generated fingerprint inside a Deepwyrm revision.
pub(crate) const FINGERPRINT_PATH: &str = "abi/generated/abi_fingerprint.toml";
/// The only fingerprint encoding this consumer accepts.
pub(crate) const FINGERPRINT_SCHEMA: &str = "deepwyrm-abi-fingerprint-v1";
const MAX_FINGERPRINT_BYTES: usize = 4096;

/// How a kernel revision was shown to carry the pinned ABI.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PairingBasis {
    /// The kernel revision's generated fingerprint is the pinned one.
    Fingerprint,
    /// The kernel revision predates generated fingerprints, and its
    /// `abi/schema` tree is identical to the generated revision's, so it has
    /// the generated revision's (pinned) fingerprint by construction.
    IdenticalSchema,
}

/// A verified kernel/generated-ABI pair.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct AbiPairing {
    pub(crate) fingerprint: String,
    pub(crate) basis: PairingBasis,
    pub(crate) kernel_abi_tree: String,
    pub(crate) generated_abi_tree: String,
}

/// Verify that `kernel_revision` may run with Wyrmroot built against
/// `generated_revision`, both resolved in the paired Deepwyrm repository.
///
/// The generated revision must carry a well-formed fingerprint equal to the
/// pinned one. The kernel revision must carry the same fingerprint, or, if it
/// predates generated fingerprints, the identical `abi/schema` tree. Anything
/// else fails closed.
pub(crate) fn verify(
    deep_repository: &Path,
    kernel_revision: &str,
    generated_revision: &str,
    pinned_fingerprint: &str,
    label: &str,
) -> Result<AbiPairing, Failure> {
    require_lower_hex(kernel_revision, 40, label, "Deepwyrm kernel revision")?;
    require_lower_hex(generated_revision, 40, label, "generated ABI revision")?;
    require_lower_hex(pinned_fingerprint, 64, label, "pinned ABI fingerprint")?;
    match revision_fingerprint(deep_repository, generated_revision, label)? {
        Some(generated) if generated == pinned_fingerprint => {}
        Some(_) => {
            return Err(Failure::task(format!(
                "{label} pinned Deepwyrm ABI fingerprint does not match the generated ABI revision"
            )));
        }
        None => {
            return Err(Failure::task(format!(
                "{label} generated ABI revision {generated_revision} has no generated ABI fingerprint ({FINGERPRINT_PATH})"
            )));
        }
    }
    let basis = match revision_fingerprint(deep_repository, kernel_revision, label)? {
        Some(kernel) if kernel == pinned_fingerprint => PairingBasis::Fingerprint,
        Some(_) => {
            return Err(Failure::task(format!(
                "{label} selected kernel's ABI fingerprint does not match the pinned ABI fingerprint"
            )));
        }
        None => {
            let kernel_schema = tree(deep_repository, kernel_revision, "abi/schema", label)?;
            let generated_schema = tree(deep_repository, generated_revision, "abi/schema", label)?;
            if kernel_schema != generated_schema {
                return Err(Failure::task(format!(
                    "{label} selected kernel has no ABI fingerprint and its ABI schema differs from the generated ABI revision"
                )));
            }
            PairingBasis::IdenticalSchema
        }
    };
    Ok(AbiPairing {
        fingerprint: pinned_fingerprint.to_owned(),
        basis,
        kernel_abi_tree: tree(deep_repository, kernel_revision, "abi", label)?,
        generated_abi_tree: tree(deep_repository, generated_revision, "abi", label)?,
    })
}

/// Read and parse the committed fingerprint of one Deepwyrm revision, or
/// `None` when that revision predates generated fingerprints.
pub(crate) fn revision_fingerprint(
    deep_repository: &Path,
    revision: &str,
    label: &str,
) -> Result<Option<String>, Failure> {
    require_lower_hex(revision, 40, label, "Deepwyrm revision")?;
    let object_type = git(
        deep_repository,
        &["cat-file", "-t", &format!("{revision}^{{commit}}")],
        label,
    )?;
    if object_type != "commit" {
        return Err(Failure::task(format!(
            "{label} Deepwyrm revision {revision} is not a commit"
        )));
    }
    let spec = format!("{revision}:{FINGERPRINT_PATH}");
    let present = Command::new("git")
        .arg("-C")
        .arg(deep_repository)
        .args(["cat-file", "-e", &spec])
        .output()
        .map_err(|error| Failure::task(format!("{label} could not query Git: {error}")))?;
    if !present.status.success() {
        return Ok(None);
    }
    let object_type = git(deep_repository, &["cat-file", "-t", &spec], label)?;
    if object_type != "blob" {
        return Err(Failure::task(format!(
            "{label} Deepwyrm ABI fingerprint at {revision} is not a regular file"
        )));
    }
    let output = Command::new("git")
        .arg("-C")
        .arg(deep_repository)
        .args(["cat-file", "blob", &spec])
        .output()
        .map_err(|error| Failure::task(format!("{label} could not query Git: {error}")))?;
    if !output.status.success() {
        return Err(Failure::task(format!(
            "{label} could not read the Deepwyrm ABI fingerprint at {revision}"
        )));
    }
    if output.stdout.len() > MAX_FINGERPRINT_BYTES {
        return Err(Failure::task(format!(
            "{label} Deepwyrm ABI fingerprint at {revision} is oversized"
        )));
    }
    let contents = String::from_utf8(output.stdout).map_err(|_| {
        Failure::task(format!(
            "{label} Deepwyrm ABI fingerprint at {revision} is not UTF-8"
        ))
    })?;
    parse_fingerprint(&contents).map(Some).map_err(|message| {
        Failure::task(format!(
            "{label} Deepwyrm ABI fingerprint at {revision} {message}"
        ))
    })
}

fn tree(repository: &Path, revision: &str, path: &str, label: &str) -> Result<String, Failure> {
    let object = git(
        repository,
        &["rev-parse", &format!("{revision}:{path}")],
        label,
    )?;
    require_lower_hex(&object, 40, label, &format!("Deepwyrm {path} tree"))?;
    Ok(object)
}

/// Strictly parse Deepwyrm's generated fingerprint file and return the digest.
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
            .ok_or_else(|| format!("has a malformed line `{line}`"))?;
        let slot = match key {
            "schema" => &mut schema,
            "algorithm" => &mut algorithm,
            "fingerprint" => &mut fingerprint,
            "abi_name" => &mut abi_name,
            "abi_version" => &mut abi_version,
            _ => return Err(format!("has an unsupported key `{key}`")),
        };
        if slot.replace(value).is_some() {
            return Err(format!("repeats key `{key}`"));
        }
    }
    let quoted = |value: Option<&str>, key: &str| -> Result<String, String> {
        value
            .and_then(|value| value.strip_prefix('"'))
            .and_then(|value| value.strip_suffix('"'))
            .filter(|value| !value.contains('"'))
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

fn git(repository: &Path, arguments: &[&str], label: &str) -> Result<String, Failure> {
    let output = Command::new("git")
        .arg("-C")
        .arg(repository)
        .args(arguments)
        .output()
        .map_err(|error| Failure::task(format!("{label} could not query Git: {error}")))?;
    if !output.status.success() {
        return Err(Failure::task(format!("{label} Git revision query failed")));
    }
    String::from_utf8(output.stdout)
        .map(|value| value.trim().to_owned())
        .map_err(|_| Failure::task(format!("{label} Git revision is not UTF-8")))
}

pub(crate) fn is_lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn require_lower_hex(value: &str, length: usize, label: &str, what: &str) -> Result<(), Failure> {
    if is_lower_hex(value, length) {
        Ok(())
    } else {
        Err(Failure::task(format!(
            "{label} {what} must be {length} lowercase hexadecimal digits"
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn fingerprint_file(digest: &str) -> String {
        format!(
            "# @generated by abi-gen from abi/schema.\n# Do not edit this file directly.\n\n\
             schema = \"{FINGERPRINT_SCHEMA}\"\nabi_name = \"Deepwyrm\"\nabi_version = 0\n\
             algorithm = \"sha256\"\nfingerprint = \"{digest}\"\n"
        )
    }

    #[test]
    fn fingerprint_parser_is_strict() {
        let digest = "ab".repeat(32);
        assert_eq!(
            parse_fingerprint(&fingerprint_file(&digest)).unwrap(),
            digest
        );
        for (from, to) in [
            (FINGERPRINT_SCHEMA, "deepwyrm-abi-fingerprint-v2"),
            ("algorithm = \"sha256\"", "algorithm = \"sha1\""),
            (digest.as_str(), &"AB".repeat(32)),
            (digest.as_str(), &"ab".repeat(20)),
            ("abi_version = 0", "abi_version = zero"),
            ("abi_version = 0\n", ""),
            (
                "abi_name = \"Deepwyrm\"\n",
                "abi_name = \"Deepwyrm\"\nextra = \"x\"\n",
            ),
            (
                "algorithm = \"sha256\"\n",
                "algorithm = \"sha256\"\nalgorithm = \"sha256\"\n",
            ),
            ("fingerprint = ", "fingerprint="),
        ] {
            let mutated = fingerprint_file(&digest).replacen(from, to, 1);
            assert!(parse_fingerprint(&mutated).is_err(), "accepted {to}");
        }
        let unquoted = fingerprint_file(&digest).replace(&format!("\"{digest}\""), &digest);
        assert!(parse_fingerprint(&unquoted).is_err());
    }

    struct Repository(PathBuf);

    impl Repository {
        fn new() -> Self {
            let root = std::env::temp_dir().join(format!(
                "abi-pairing-{}-{}",
                std::process::id(),
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            fs::create_dir(&root).unwrap();
            let repository = Self(root);
            repository.git(&["init", "-q"]);
            repository.git(&["config", "user.name", "Pairing Test"]);
            repository.git(&["config", "user.email", "pairing@example.invalid"]);
            fs::create_dir_all(repository.0.join("abi/generated")).unwrap();
            repository
        }

        fn git(&self, arguments: &[&str]) -> String {
            let output = Command::new("git")
                .args(["-c", "commit.gpgsign=false"])
                .arg("-C")
                .arg(&self.0)
                .args(arguments)
                .output()
                .unwrap();
            assert!(output.status.success(), "git {arguments:?} failed");
            String::from_utf8(output.stdout).unwrap().trim().to_owned()
        }

        fn commit(&self, schema: &str, digest: Option<&str>) -> String {
            fs::write(self.0.join("abi/schema"), schema).unwrap();
            let path = self.0.join(FINGERPRINT_PATH);
            match digest {
                Some(digest) => fs::write(&path, fingerprint_file(digest)).unwrap(),
                None => {
                    let _ = fs::remove_file(&path);
                }
            }
            self.git(&["add", "-A", "abi"]);
            self.git(&["commit", "-q", "--allow-empty", "-m", "abi"]);
            self.git(&["rev-parse", "HEAD"])
        }
    }

    impl Drop for Repository {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn documentation_only_abi_tree_change_still_pairs() {
        let repository = Repository::new();
        let pinned = "1".repeat(64);
        let generated = repository.commit("syscall docs v1", Some(&pinned));
        // A documentation-only schema edit moves the abi/ tree but not the
        // fingerprint, so the kernel pairs without a repin.
        let reworded = repository.commit("syscall docs v2", Some(&pinned));
        let pairing = verify(&repository.0, &reworded, &generated, &pinned, "TEST").unwrap();
        assert_eq!(pairing.basis, PairingBasis::Fingerprint);
        assert_ne!(pairing.kernel_abi_tree, pairing.generated_abi_tree);
        assert_eq!(pairing.fingerprint, pinned);
        assert_eq!(
            pairing.generated_abi_tree,
            repository.git(&["rev-parse", &format!("{generated}:abi")])
        );
        assert_eq!(
            pairing.kernel_abi_tree,
            repository.git(&["rev-parse", &format!("{reworded}:abi")])
        );

        let changed = repository.commit("syscall number moved", Some(&"2".repeat(64)));
        let error = verify(&repository.0, &changed, &generated, &pinned, "TEST").unwrap_err();
        assert!(error.message.contains("selected kernel's ABI fingerprint"));

        let error = verify(
            &repository.0,
            &generated,
            &generated,
            &"3".repeat(64),
            "TEST",
        )
        .unwrap_err();
        assert!(error.message.contains("pinned Deepwyrm ABI fingerprint"));
        assert!(verify(&repository.0, "HEAD", &generated, &pinned, "TEST").is_err());
        assert!(verify(&repository.0, &"f".repeat(40), &generated, &pinned, "TEST").is_err());
    }

    #[test]
    fn kernel_without_a_fingerprint_pairs_only_with_an_identical_schema() {
        let repository = Repository::new();
        let pinned = "1".repeat(64);
        let legacy = repository.commit("schema", None);
        let drifted_legacy = repository.commit("schema with another status", None);
        let generated = repository.commit("schema", Some(&pinned));
        let pairing = verify(&repository.0, &legacy, &generated, &pinned, "TEST").unwrap();
        assert_eq!(pairing.basis, PairingBasis::IdenticalSchema);
        let error =
            verify(&repository.0, &drifted_legacy, &generated, &pinned, "TEST").unwrap_err();
        assert!(
            error
                .message
                .contains("has no ABI fingerprint and its ABI schema differs")
        );

        // The generated (pinned) side must always carry its fingerprint.
        let error = verify(&repository.0, &generated, &legacy, &pinned, "TEST").unwrap_err();
        assert!(error.message.contains("has no generated ABI fingerprint"));
        assert_eq!(
            revision_fingerprint(&repository.0, &legacy, "TEST").unwrap(),
            None
        );
        assert_eq!(
            revision_fingerprint(&repository.0, &generated, "TEST").unwrap(),
            Some(pinned)
        );
    }
}
