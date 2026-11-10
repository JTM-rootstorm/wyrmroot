use super::{
    BuildManifest, LoaderProfile, has_abi_consumer, loader_has_optional_uefi_dependency,
    lock_has_git_package, lock_has_package, manifest_consumes_workspace_dependency,
    parse_scalar_toml, parse_workspace_members, root_has_deepwyrm_dependency,
    root_has_deepwyrm_package, root_has_uefi_dependency, validate_loader_profile_components,
    workspace_member_consumes_dependency,
};
use std::collections::BTreeMap;
use std::path::Path;

#[cfg(unix)]
use super::scan_policy_tree;
#[cfg(unix)]
use std::fs;

#[test]
fn scalar_manifest_parser_qualifies_sections_and_skips_arrays() {
    let values = parse_scalar_toml(
        "schema_version = 1\n[deepwyrm]\nrevision = \"0123\"\nitems = [\n  \"x\",\n]\n[constraints]\nstrict = false\n",
        Path::new("versions.toml"),
    )
    .unwrap();
    assert_eq!(values.get("schema_version").unwrap(), "1");
    assert_eq!(values.get("deepwyrm.revision").unwrap(), "0123");
    assert_eq!(values.get("constraints.strict").unwrap(), "false");
    assert!(!values.contains_key("deepwyrm.items"));
    assert!(
        parse_scalar_toml(
            "[metadata]\ndecoy = \"\"\"\n[deepwyrm]\nrevision = \"0123\"\n\"\"\"\n",
            Path::new("versions.toml")
        )
        .is_err()
    );
}

#[test]
fn host_tests_allow_pending_abi_but_build_states_fail_closed() {
    let pending = phase_a_manifest("not-yet-available", "reserved-not-yet-implemented");
    pending
        .validate_host_test_metadata()
        .expect("host metadata validation must remain independently runnable");
    assert!(pending.validate_phase_a_states().is_err());

    let ready = phase_a_manifest("available", "available");
    ready
        .validate_phase_a_states()
        .expect("available ABI and native target are the accepted WYR0-D build state");

    let premature_target = phase_a_manifest("available", "reserved-not-yet-implemented");
    assert!(premature_target.validate_phase_a_states().is_err());
}

#[test]
fn loader_profile_rejects_host_target_leakage_and_unsafe_components() {
    let valid = LoaderProfile {
        cargo_package: "wyrmroot-efi-loader".to_owned(),
        cargo_binary: "loader".to_owned(),
        cargo_features: "firmware".to_owned(),
        uefi_crate_version: "0.39.0".to_owned(),
        artifact_name: "loader.efi".to_owned(),
        rust_target: "x86_64-unknown-uefi".to_owned(),
        toolchain_inspection: "toolchain/verify-uefi-toolchain.sh".to_owned(),
        artifact_inspection: "toolchain/inspect-uefi-artifact.sh".to_owned(),
    };
    validate_loader_profile_components(&valid).expect("canonical loader profile rejected");

    let mut host_target = valid.clone();
    host_target.rust_target = "x86_64-unknown-linux-gnu".to_owned();
    assert!(validate_loader_profile_components(&host_target).is_err());

    let mut traversal = valid;
    traversal.artifact_name = "../loader.efi".to_owned();
    assert!(validate_loader_profile_components(&traversal).is_err());
}

#[test]
fn lockfile_dependency_check_rejects_mismatched_uefi_version() {
    let lockfile = "[[package]]\nname = \"uefi\"\nversion = \"0.38.0\"\n\n[[package]]\nname = \"other\"\nversion = \"0.39.0\"\n";
    assert!(!lock_has_package(lockfile, "uefi", "0.39.0"));
    assert!(lock_has_package(lockfile, "uefi", "0.38.0"));
    assert!(!lock_has_package(
        "version = 4\n# [[package]]\nname = \"uefi\"\nversion = \"0.39.0\"\n",
        "uefi",
        "0.39.0"
    ));
}

#[test]
fn deepwyrm_manifest_pin_rejects_comment_and_metadata_decoys() {
    const REPOSITORY: &str = "https://example.invalid/deepwyrm";
    const REVISION: &str = "0123456789abcdef0123456789abcdef01234567";
    const OTHER_REVISION: &str = "fedcba9876543210fedcba9876543210fedcba98";

    let valid = format!(
        "[workspace.dependencies]\ndeepwyrm-abi = {{ git = \"{REPOSITORY}.git\", rev = \"{REVISION}\" }}\n"
    );
    assert!(root_has_deepwyrm_dependency(&valid, REPOSITORY, REVISION));
    let syscall = valid.replace("deepwyrm-abi", "deepwyrm-syscall");
    assert!(root_has_deepwyrm_package(
        &syscall,
        "deepwyrm-syscall",
        REPOSITORY,
        REVISION
    ));

    let comment_decoy = format!(
        "[workspace.dependencies]\ndeepwyrm-abi = {{ git = \"{REPOSITORY}.git\", rev = \"{OTHER_REVISION}\" }} # expected {REVISION}\n# deepwyrm-abi = {{ git = \"{REPOSITORY}.git\", rev = \"{REVISION}\" }}\n"
    );
    assert!(!root_has_deepwyrm_dependency(
        &comment_decoy,
        REPOSITORY,
        REVISION
    ));

    let metadata_decoy = format!(
        "[workspace.dependencies]\ndeepwyrm-abi = {{ git = \"{REPOSITORY}.git\", rev = \"{OTHER_REVISION}\" }}\n[package.metadata]\ndeepwyrm-abi = {{ git = \"{REPOSITORY}.git\", rev = \"{REVISION}\" }}\n"
    );
    assert!(!root_has_deepwyrm_dependency(
        &metadata_decoy,
        REPOSITORY,
        REVISION
    ));

    let repeated_suffix = format!(
        "[workspace.dependencies]\ndeepwyrm-abi = {{ git = \"{REPOSITORY}.git.git\", rev = \"{REVISION}\" }}\n"
    );
    assert!(!root_has_deepwyrm_dependency(
        &repeated_suffix,
        REPOSITORY,
        REVISION
    ));

    let multiline_section_decoy = format!(
        "[package.metadata]\ndecoy = \"\"\"\n[workspace.dependencies]\ndeepwyrm-abi = {{ git = \"{REPOSITORY}.git\", rev = \"{REVISION}\" }}\n\"\"\"\n"
    );
    assert!(!root_has_deepwyrm_dependency(
        &multiline_section_decoy,
        REPOSITORY,
        REVISION
    ));

    const HASH_REPOSITORY: &str = "https://example.invalid/deepwyrm#quoted";
    let quoted_hash = format!(
        "[workspace.dependencies]\ndeepwyrm-abi = {{ git = \"{HASH_REPOSITORY}\", rev = \"{REVISION}\" }} # trailing comment\n"
    );
    assert!(root_has_deepwyrm_dependency(
        &quoted_hash,
        HASH_REPOSITORY,
        REVISION
    ));
}

#[test]
fn deepwyrm_lock_pin_rejects_comment_and_package_decoys() {
    const REPOSITORY: &str = "https://example.invalid/deepwyrm";
    const REVISION: &str = "0123456789abcdef0123456789abcdef01234567";
    const OTHER_REVISION: &str = "fedcba9876543210fedcba9876543210fedcba98";

    let valid = format!(
        "[[package]]\nname = \"deepwyrm-abi\"\nversion = \"0.0.0\"\nsource = \"git+{REPOSITORY}.git?rev={REVISION}#{REVISION}\"\n"
    );
    assert!(lock_has_git_package(
        &valid,
        "deepwyrm-abi",
        REPOSITORY,
        REVISION
    ));

    let comment_decoy = format!(
        "[[package]]\nname = \"deepwyrm-abi\"\nversion = \"0.0.0\"\nsource = \"git+{REPOSITORY}.git?rev={OTHER_REVISION}#{OTHER_REVISION}\" # expected {REVISION}\n# source = \"git+{REPOSITORY}.git?rev={REVISION}#{REVISION}\"\n"
    );
    assert!(!lock_has_git_package(
        &comment_decoy,
        "deepwyrm-abi",
        REPOSITORY,
        REVISION
    ));

    let other_package_decoy = format!(
        "[[package]]\nname = \"deepwyrm-abi\"\nversion = \"0.0.0\"\nsource = \"git+{REPOSITORY}.git?rev={OTHER_REVISION}#{OTHER_REVISION}\"\n\n[[package]]\nname = \"unrelated\"\nversion = \"0.0.0\"\nsource = \"git+{REPOSITORY}.git?rev={REVISION}#{REVISION}\"\n"
    );
    assert!(!lock_has_git_package(
        &other_package_decoy,
        "deepwyrm-abi",
        REPOSITORY,
        REVISION
    ));

    let commented_header_decoy = format!(
        "version = 4\n# [[package]]\nname = \"deepwyrm-abi\"\nsource = \"git+{REPOSITORY}.git?rev={REVISION}#{REVISION}\"\n"
    );
    assert!(!lock_has_git_package(
        &commented_header_decoy,
        "deepwyrm-abi",
        REPOSITORY,
        REVISION
    ));

    let multiline_string_decoy = format!(
        "description = \"\"\"\n[[package]]\n\"\"\"\nname = \"deepwyrm-abi\"\nversion = \"0.0.0\"\nsource = \"git+{REPOSITORY}.git?rev={REVISION}#{REVISION}\"\n"
    );
    assert!(!lock_has_git_package(
        &multiline_string_decoy,
        "deepwyrm-abi",
        REPOSITORY,
        REVISION
    ));

    let duplicate_source = format!(
        "[[package]]\nname = \"deepwyrm-abi\"\nversion = \"0.0.0\"\nsource = \"git+{REPOSITORY}.git?rev={REVISION}#{REVISION}\"\nsource = \"git+{REPOSITORY}.git?rev={REVISION}#{REVISION}\"\n"
    );
    assert!(!lock_has_git_package(
        &duplicate_source,
        "deepwyrm-abi",
        REPOSITORY,
        REVISION
    ));
}

#[test]
fn abi_consumer_check_requires_real_workspace_dependency() {
    assert!(manifest_consumes_workspace_dependency(
        "[dependencies]\ndeepwyrm-abi.workspace = true\n",
        "deepwyrm-abi"
    ));
    assert!(!manifest_consumes_workspace_dependency(
        "[dependencies]\ndeepwyrm-abi = { workspace = true }\n",
        "deepwyrm-abi"
    ));
    assert!(!manifest_consumes_workspace_dependency(
        "[dependencies.deepwyrm-abi]\nworkspace = true\n",
        "deepwyrm-abi"
    ));
    assert!(!manifest_consumes_workspace_dependency(
        "[dependencies]\ndeepwyrm-abi.workspace = true\ndeepwyrm-abi.optional = true\n",
        "deepwyrm-abi"
    ));
    assert!(!manifest_consumes_workspace_dependency(
        "[dependencies]\ndeepwyrm-abi.workspace = true\n\"deepwyrm-abi\".optional = true\n",
        "deepwyrm-abi"
    ));
    assert!(!manifest_consumes_workspace_dependency(
        "# deepwyrm-abi.workspace = true\n[package.metadata]\ndeepwyrm-abi.workspace = true\n",
        "deepwyrm-abi"
    ));
    assert!(!manifest_consumes_workspace_dependency(
        "[dependencies]\nunrelated = { package = \"deepwyrm-abi\", version = \"0.0.0\" } # deepwyrm-abi.workspace = true\n",
        "deepwyrm-abi"
    ));
    assert!(!manifest_consumes_workspace_dependency(
        "[package.metadata.dependencies]\ndeepwyrm-abi.workspace = true\n",
        "deepwyrm-abi"
    ));
    assert!(!manifest_consumes_workspace_dependency(
        "[target.'cfg(any())'.dependencies]\ndeepwyrm-abi.workspace = true\n",
        "deepwyrm-abi"
    ));
    assert!(!manifest_consumes_workspace_dependency(
        "[target.'cfg(any())'.dependencies.deepwyrm-abi]\nworkspace = true\n",
        "deepwyrm-abi"
    ));
    assert!(!manifest_consumes_workspace_dependency(
        "[dev-dependencies]\ndeepwyrm-abi.workspace = true\n",
        "deepwyrm-abi"
    ));
    assert!(!manifest_consumes_workspace_dependency(
        "[package.metadata]\ndecoy = '''\n[dependencies]\ndeepwyrm-abi.workspace = true\n'''\n",
        "deepwyrm-abi"
    ));
}

#[test]
fn workspace_members_parser_rejects_traversal_and_duplicates() {
    let members = parse_workspace_members(
        "[workspace]\nmembers = [\n  \"loader\",\n  \"crates/runtime\",\n]\n",
        Path::new("Cargo.toml"),
    )
    .expect("explicit workspace members rejected");
    assert_eq!(
        members,
        ["crates/runtime".to_owned(), "loader".to_owned()]
            .into_iter()
            .collect()
    );
    assert!(
        parse_workspace_members(
            "[workspace]\nmembers = [\"loader\", \"../decoy\"]\n",
            Path::new("Cargo.toml")
        )
        .is_err()
    );
    assert!(
        parse_workspace_members(
            "[workspace]\nmembers = [\"loader\", \"loader\"]\n",
            Path::new("Cargo.toml")
        )
        .is_err()
    );
    assert!(
        parse_workspace_members(
            "[workspace]\nmembers = [\"loader\"]\nexclude = [\"loader\"]\n",
            Path::new("Cargo.toml")
        )
        .is_err()
    );
    assert!(
        parse_workspace_members(
            "[workspace]\nmembers = [\"loader\"]\n\"exclude\" = [\"loader\"]\n",
            Path::new("Cargo.toml")
        )
        .is_err()
    );
    assert!(
        parse_workspace_members(
            "[package.metadata]\ndecoy = \"\"\"\n[workspace]\nmembers = [\"decoy\"]\n\"\"\"\n",
            Path::new("Cargo.toml")
        )
        .is_err()
    );
}

#[test]
fn abi_consumer_is_bound_to_an_explicit_workspace_member() {
    use std::time::{SystemTime, UNIX_EPOCH};

    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock precedes Unix epoch")
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "wyrmroot-xtask-member-test-{}-{nonce}",
        std::process::id()
    ));
    let member = root.join("member");
    let decoy = root.join("decoy/nested");
    std::fs::create_dir_all(&member).expect("create member fixture");
    std::fs::create_dir_all(&decoy).expect("create non-member fixture");
    std::fs::write(
        root.join("Cargo.toml"),
        "[workspace]\nmembers = [\"member\"]\n",
    )
    .expect("write root fixture manifest");
    std::fs::write(member.join("Cargo.toml"), "[package]\nname = \"member\"\n")
        .expect("write member fixture manifest");
    std::fs::write(
        decoy.join("Cargo.toml"),
        "[dependencies]\ndeepwyrm-abi.workspace = true\n",
    )
    .expect("write non-member decoy manifest");

    assert!(!has_abi_consumer(&root).expect("inspect non-consuming workspace"));

    std::fs::write(
        member.join("Cargo.toml"),
        "[dependencies]\ndeepwyrm-abi.workspace = true\n",
    )
    .expect("write consuming member fixture manifest");
    assert!(has_abi_consumer(&root).expect("inspect consuming workspace"));

    std::fs::remove_dir_all(&root).expect("remove workspace fixture");
}

#[test]
fn syscall_consumer_is_bound_to_the_runtime_workspace_member() {
    use std::time::{SystemTime, UNIX_EPOCH};

    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock precedes Unix epoch")
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "wyrmroot-xtask-runtime-consumer-test-{}-{nonce}",
        std::process::id()
    ));
    let runtime = root.join("crates/wyrmroot-runtime");
    let decoy = root.join("crates/decoy");
    std::fs::create_dir_all(&runtime).expect("create runtime fixture");
    std::fs::create_dir_all(&decoy).expect("create decoy fixture");
    std::fs::write(
        root.join("Cargo.toml"),
        "[workspace]\nmembers = [\"crates/wyrmroot-runtime\", \"crates/decoy\"]\n",
    )
    .expect("write workspace fixture");
    std::fs::write(
        runtime.join("Cargo.toml"),
        "[package]\nname = \"runtime\"\n",
    )
    .expect("write runtime manifest");
    std::fs::write(
        decoy.join("Cargo.toml"),
        "[dependencies]\ndeepwyrm-syscall.workspace = true\n",
    )
    .expect("write decoy manifest");

    assert!(
        !workspace_member_consumes_dependency(
            &root,
            "crates/wyrmroot-runtime",
            "deepwyrm-syscall",
        )
        .expect("inspect non-consuming runtime")
    );

    std::fs::write(
        runtime.join("Cargo.toml"),
        "[dependencies]\ndeepwyrm-syscall.workspace = true\n",
    )
    .expect("write consuming runtime manifest");
    assert!(
        workspace_member_consumes_dependency(&root, "crates/wyrmroot-runtime", "deepwyrm-syscall",)
            .expect("inspect consuming runtime")
    );

    std::fs::remove_dir_all(&root).expect("remove runtime consumer fixture");
}

#[test]
fn manifest_dependency_checks_require_exact_pin_and_optional_consumer() {
    let root = "[workspace.dependencies]\nuefi = { version = \"=0.39.0\", default-features = false, features = [\"panic_handler\", \"alloc\", \"global_allocator\"] }\n";
    assert!(root_has_uefi_dependency(root, "0.39.0"));
    assert!(!root_has_uefi_dependency(root, "0.38.0"));
    assert!(!root_has_uefi_dependency(
        "[workspace.dependencies]\nuefi = { version = \"0.39.0\", default-features = false }",
        "0.39.0"
    ));
    assert!(!root_has_uefi_dependency(
        "[workspace.dependencies]\nuefi = { version = \"=0.39.0\", default-features = false, features = [\"alloc\", \"global_allocator\"] }",
        "0.39.0"
    ));
    assert!(!root_has_uefi_dependency(
        "[workspace.dependencies]\nuefi = { version = \"=0.39.0\", default-features = false, features = [\"alloc\", \"global_allocator\", \"panic_handler\", \"logger\"] }",
        "0.39.0"
    ));
    assert!(!root_has_uefi_dependency(
        "[package.metadata]\nuefi = { version = \"=0.39.0\", default-features = false, features = [\"alloc\", \"global_allocator\", \"panic_handler\"] }",
        "0.39.0"
    ));

    assert!(loader_has_optional_uefi_dependency(
        "[dependencies]\nuefi = { workspace = true, optional = true }"
    ));
    assert!(!loader_has_optional_uefi_dependency(
        "[dependencies]\nuefi = { workspace = true }"
    ));
    assert!(!loader_has_optional_uefi_dependency(
        "[package.metadata]\nuefi = { workspace = true, optional = true }"
    ));
}

#[cfg(unix)]
#[test]
fn policy_scan_rejects_symlinks_without_following_them() {
    use std::os::unix::fs::symlink;
    use std::time::{SystemTime, UNIX_EPOCH};

    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock precedes Unix epoch")
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "wyrmroot-xtask-symlink-test-{}-{nonce}",
        std::process::id()
    ));
    fs::create_dir(&root).expect("create isolated test directory");
    symlink("/", root.join("escape")).expect("create test symlink");

    let failure = scan_policy_tree(&root, "x86_64-unknown-wyrmroot")
        .expect_err("policy scan followed or accepted a symlink");
    assert!(failure.message.contains("refusing to follow symlink"));

    fs::remove_dir_all(&root).expect("remove isolated test directory");
}

#[cfg(unix)]
#[test]
fn policy_scan_excludes_non_build_request_evidence() {
    use std::time::{SystemTime, UNIX_EPOCH};

    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock precedes Unix epoch")
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "wyrmroot-xtask-policy-evidence-test-{}-{nonce}",
        std::process::id()
    ));
    let toolchain = root.join("toolchain");
    let requests = toolchain.join("requests");
    fs::create_dir_all(&requests).expect("create request evidence fixture");
    fs::write(
        requests.join("accepted.toml"),
        "notes = \"validated absence of cfg(unix)\"\n",
    )
    .expect("write request evidence fixture");

    scan_policy_tree(&toolchain, "x86_64-unknown-wyrmroot")
        .expect("non-build request evidence was scanned as guest configuration");

    fs::remove_dir_all(&root).expect("remove policy evidence fixture");
}

fn phase_a_manifest(abi_state: &str, target_state: &str) -> BuildManifest {
    BuildManifest {
        values: BTreeMap::from([
            ("schema_version".to_owned(), "1".to_owned()),
            ("milestone".to_owned(), "WYR0".to_owned()),
            (
                "deepwyrm.revision".to_owned(),
                "0123456789abcdef0123456789abcdef01234567".to_owned(),
            ),
            ("deepwyrm.abi_fingerprint".to_owned(), "ab".repeat(32)),
            (
                "rust.upstream_stable_revision".to_owned(),
                "89abcdef0123456789abcdef0123456789abcdef".to_owned(),
            ),
            (
                "rust.wyrmroot_revision".to_owned(),
                "fedcba9876543210fedcba9876543210fedcba98".to_owned(),
            ),
            (
                "deepwyrm.repository".to_owned(),
                "https://example.invalid/deepwyrm".to_owned(),
            ),
            (
                "rust.upstream_stable_release".to_owned(),
                "1.97.1".to_owned(),
            ),
            (
                "rust.local_toolchain_name".to_owned(),
                "wyrmroot-test".to_owned(),
            ),
            (
                "rust.accepted_artifact_root".to_owned(),
                "artifacts/toolchains/accepted/test".to_owned(),
            ),
            (
                "rust.project_cargo_home".to_owned(),
                ".tmp/cargo-home/offline-v1".to_owned(),
            ),
            (
                "rust.native_target".to_owned(),
                "x86_64-unknown-wyrmroot".to_owned(),
            ),
            (
                "deepwyrm.abi_dependency_state".to_owned(),
                abi_state.to_owned(),
            ),
            (
                "rust.native_target_state".to_owned(),
                target_state.to_owned(),
            ),
            (
                "llvm.host_version_state".to_owned(),
                "not-yet-adopted".to_owned(),
            ),
            (
                "bootstrap_constraints.allow_moving_rust_channel".to_owned(),
                "false".to_owned(),
            ),
            (
                "bootstrap_constraints.allow_host_target_defaults_for_guest".to_owned(),
                "false".to_owned(),
            ),
            (
                "bootstrap_constraints.allow_host_libc_for_guest".to_owned(),
                "false".to_owned(),
            ),
            (
                "bootstrap_constraints.allow_unimplemented_deepwyrm_abi_dependency".to_owned(),
                "false".to_owned(),
            ),
            (
                "bootstrap_constraints.allow_unimplemented_native_target".to_owned(),
                "false".to_owned(),
            ),
        ]),
    }
}
