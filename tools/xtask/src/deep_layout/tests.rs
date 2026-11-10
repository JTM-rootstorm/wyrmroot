use super::{
    DeepLayoutBuild, KERNEL_BOOT_STACK_BYTES, LayoutPolicy, bounded_command_output,
    open_stable_regular_file, prepare_current_kernel_source, validate_git_status,
    validate_regular_path, verify_open_file_identity, verify_tracked_bytes, write_generated_policy,
    x86_64_page_table_indices,
};
use crate::sha256::bytes_digest;

#[cfg(unix)]
#[test]
fn bounded_command_terminates_an_over_limit_producer() {
    use std::process::Command;
    use std::time::{Duration, Instant};

    let started = Instant::now();
    let failure = bounded_command_output(
        Command::new("sh").args(["-c", "while :; do printf 0123456789abcdef; done"]),
        64,
        64,
        Duration::from_secs(5),
        "over-limit fixture",
    )
    .expect_err("unbounded producer unexpectedly succeeded");
    assert!(failure.message.contains("child was terminated"));
    assert!(started.elapsed() < Duration::from_secs(5));
}

#[cfg(unix)]
#[test]
fn bounded_command_times_out_a_silent_process() {
    use std::process::Command;
    use std::time::{Duration, Instant};

    let started = Instant::now();
    let failure = bounded_command_output(
        Command::new("sh").args(["-c", "exec sleep 30"]),
        64,
        64,
        Duration::from_millis(50),
        "silent fixture",
    )
    .expect_err("silent producer unexpectedly succeeded");
    assert!(failure.message.contains("wall-clock deadline"));
    assert!(started.elapsed() < Duration::from_secs(5));
}

#[cfg(unix)]
#[test]
fn git_status_capture_rejects_hostile_cardinality() {
    use std::fs;
    use std::process::Command;
    use std::time::{SystemTime, UNIX_EPOCH};

    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock precedes Unix epoch")
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "wyrmroot-git-status-bound-test-{}-{nonce}",
        std::process::id()
    ));
    fs::create_dir(&root).expect("create isolated Git fixture");
    assert!(
        Command::new("git")
            .arg("-C")
            .arg(&root)
            .args(["init", "-q"])
            .status()
            .expect("initialize Git fixture")
            .success()
    );
    for index in 0..32 {
        fs::write(
            root.join(format!("hostile-untracked-entry-{index:04}.txt")),
            b"x",
        )
        .expect("write hostile status fixture");
    }
    let failure = super::git_output_bounded(
        &root,
        ["status", "--porcelain=v1", "--untracked-files=all"],
        64,
        "hostile Git status fixture",
    )
    .expect_err("oversized Git status unexpectedly succeeded");
    assert!(failure.message.contains("limit"));
    fs::remove_dir_all(&root).expect("remove isolated Git fixture");
}

#[test]
fn layout_validation_is_strict_and_generation_is_path_neutral() {
    let valid = layout("0xffff800000200000");
    let policy = LayoutPolicy::parse(&valid).expect("locked layout fixture rejected");
    let generated = policy.render_rust();
    assert!(generated.contains("DEEPWYRM_LINK_BASE: u64 = 0xffff800000200000"));
    assert!(generated.contains("DEEPWYRM_KERNEL_BOOT_STACK_SIZE: u64 = 4194304"));
    assert!(generated.contains("DEEPWYRM_ELF_WINDOW_START: u64 = DEEPWYRM_LINK_BASE"));
    assert!(generated.contains("DEEPWYRM_ELF_WINDOW_END_EXCLUSIVE: u64 = u64::MAX"));
    assert!(
        generated.contains("DEEPWYRM_EARLY_INTAKE_MAX_NORMALIZED_MEMORY_MAP_ENTRIES: u64 = 128")
    );
    assert!(generated.contains(
        "DEEPWYRM_TRANSITION_TABLES_TEMPORARY_VIRTUAL_ADDRESS: u64 = 0xffffff0000000000"
    ));
    assert!(generated.contains("DEEPWYRM_TRANSITION_TABLES_MAXIMUM_TABLE_FRAME_COUNT: u64 = 256"));
    assert!(generated.contains(
        "DEEPWYRM_TRANSITION_TABLES_PML4_INDEX: u16 = ((DEEPWYRM_TRANSITION_TABLES_TEMPORARY_VIRTUAL_ADDRESS >> 39) & 0x1ff) as u16"
    ));
    assert!(generated.contains("deepwyrm_transition_table_policy_is_self_consistent"));
    assert!(
        generated.contains("deepwyrm_abi::DW_BOOT_X86_64_PAGING_HANDOFF_TEMPORARY_VIRTUAL_ADDRESS")
    );
    assert!(
        generated.contains("deepwyrm_abi::DW_BOOT_X86_64_PAGING_HANDOFF_MAX_TABLE_FRAME_COUNT")
    );
    assert!(!generated.contains("/synthetic/private/workspace"));

    let alternate = layout_with_transition("0xffff800000200000", "0xfffffe8000000000", 384);
    let alternate_generated = LayoutPolicy::parse(&alternate)
        .expect("semantically valid alternate manifest values rejected")
        .render_rust();
    assert!(alternate_generated.contains(
        "DEEPWYRM_TRANSITION_TABLES_TEMPORARY_VIRTUAL_ADDRESS: u64 = 0xfffffe8000000000"
    ));
    assert!(
        alternate_generated
            .contains("DEEPWYRM_TRANSITION_TABLES_MAXIMUM_TABLE_FRAME_COUNT: u64 = 384")
    );

    assert!(LayoutPolicy::parse(&valid.replace("version = 2", "version = 1")).is_err());
    assert!(
        LayoutPolicy::parse(&valid.replace(
            "p_paddr_policy = \"ignored\"",
            "p_paddr_policy = \"trusted\""
        ))
        .is_err()
    );
    assert!(
        LayoutPolicy::parse(&valid.replace("[\"PT_LOAD\"]", "[\"PT_LOAD\", \"PT_DYNAMIC\"]"))
            .is_err()
    );
    assert!(LayoutPolicy::parse(&format!("{valid}\nunknown = true\n")).is_err());
    assert!(
        LayoutPolicy::parse(&valid.replace(
            "max_normalized_memory_map_entries = 128",
            "max_normalized_memory_map_entries = 129"
        ))
        .is_err()
    );
    assert!(LayoutPolicy::parse(&layout("0x0000000000200000")).is_err());
    assert!(LayoutPolicy::parse(&valid.replace("pml4_index = 510", "pml4_index = 509")).is_err());
    assert!(
        LayoutPolicy::parse(&valid.replace(
            "maximum_table_frame_count = 256",
            "maximum_table_frame_count = 3"
        ))
        .is_err()
    );
    assert!(
        LayoutPolicy::parse(&valid.replace("temporary_page_count = 1", "temporary_page_count = 0"))
            .is_err()
    );
    assert!(
        LayoutPolicy::parse(&valid.replace(
            "minimum_table_frame_count = 4",
            "minimum_table_frame_count = 5"
        ))
        .is_err()
    );
    assert!(
        LayoutPolicy::parse(&valid.replace(
            "maximum_table_frame_count = 256",
            "maximum_table_frame_count = 4294967296"
        ))
        .is_err()
    );
    assert!(
        LayoutPolicy::parse(&valid.replace(
            "contract = \"DW_BOOT_X86_64_PAGING_HANDOFF_V1\"",
            "contract = \"loader-private\""
        ))
        .is_err()
    );
    assert!(
        LayoutPolicy::parse(&valid.replace("layout_version = 2", "layout_version = \"2\""))
            .is_err()
    );
    assert!(
        LayoutPolicy::parse(&valid.replace("referenced_ranges_mutable = false", "mutable = false"))
            .is_err()
    );
    assert!(
        LayoutPolicy::parse(&layout_with_transition(
            "0xffff800000200000",
            "0xffff800000300000",
            256,
        ))
        .is_err()
    );
    assert!(
        LayoutPolicy::parse(&layout_with_transition(
            "0xffff800000200000",
            "0xffffff0000000001",
            256,
        ))
        .is_err()
    );
    assert!(
        LayoutPolicy::parse(&layout_with_transition(
            "0xffff800000200000",
            "0xfffffffffffff000",
            256,
        ))
        .is_err()
    );
}

#[test]
fn kernel_boot_stack_contract_requires_four_mib() {
    let valid = layout("0xffff800000200000");
    LayoutPolicy::parse(&valid).expect("4 MiB kernel boot stack rejected");

    for (bytes, label) in [(1_048_576, "stale 1 MiB"), (8_388_608, "unbound 8 MiB")] {
        let candidate = valid.replace(
            "kernel_boot_stack_size = 4194304",
            &format!("kernel_boot_stack_size = {bytes}"),
        );
        assert_ne!(
            candidate, valid,
            "stack-size fixture substitution did not apply"
        );
        let failure = match LayoutPolicy::parse(&candidate) {
            Ok(_) => panic!("{label} kernel boot stack unexpectedly accepted"),
            Err(failure) => failure,
        };
        assert!(failure.message.contains(&format!(
            "kernel_boot_stack_size' is {bytes}, expected {KERNEL_BOOT_STACK_BYTES}"
        )));
    }
}

#[test]
#[ignore = "requires the canonical sibling Deepwyrm checkout"]
fn actual_current_kernel_layout_preflight_uses_the_sibling_source() {
    let repository = crate::tasks::repository_root().expect("resolve Wyrmroot source");
    let project =
        crate::tasks::canonical_project_root(&repository).expect("resolve OS-Project source");
    let deep = std::fs::canonicalize(project.join("deepwyrm"))
        .expect("resolve canonical Deepwyrm sibling");
    let revision = super::git_output_bounded(
        &deep,
        ["rev-parse", "HEAD"],
        super::MAX_GIT_REVISION_STDOUT_BYTES,
        "current Deepwyrm revision",
    )
    .expect("read current Deepwyrm revision");
    let build = prepare_current_kernel_source(&repository, &deep, revision.trim())
        .expect("current Deepwyrm layout preflight failed");
    let layout =
        std::fs::read(deep.join(super::LAYOUT_PATH)).expect("read current Deepwyrm layout");
    assert_eq!(build.layout_sha256, bytes_digest(&layout));
    let generated =
        std::fs::read_to_string(&build.policy_path).expect("read generated current layout policy");
    assert!(generated.contains("DEEPWYRM_KERNEL_BOOT_STACK_SIZE: u64 = 4194304"));
    build
        .verify_unchanged()
        .expect("current Deepwyrm layout changed during preflight");
}

#[cfg(unix)]
#[test]
fn source_tree_validation_rejects_symlinks() {
    use std::fs;
    use std::os::unix::fs::symlink;
    use std::time::{SystemTime, UNIX_EPOCH};

    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock precedes Unix epoch")
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "wyrmroot-deep-layout-test-{}-{nonce}",
        std::process::id()
    ));
    fs::create_dir_all(root.join("kernel/arch/x86_64")).expect("create isolated source tree");
    let outside = root.join("outside.toml");
    fs::write(&outside, layout("0xffff800000200000")).expect("write source fixture");
    let linked = root.join("kernel/arch/x86_64/layout.toml");
    symlink(&outside, &linked).expect("create source symlink");
    assert!(validate_regular_path(&root, &linked, "test layout").is_err());
    fs::remove_dir_all(root).expect("remove isolated source tree");
}

#[cfg(unix)]
#[test]
fn generated_policy_identity_rejects_content_and_symlink_swaps() {
    use std::fs;
    use std::os::unix::fs::symlink;
    use std::time::{SystemTime, UNIX_EPOCH};

    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock precedes Unix epoch")
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "wyrmroot-layout-policy-test-{}-{nonce}",
        std::process::id()
    ));
    let source_root = std::env::temp_dir().join(format!(
        "wyrmroot-layout-source-test-{}-{nonce}",
        std::process::id()
    ));
    fs::create_dir(&root).expect("create isolated generated directory");
    let layout_path = source_root.join(super::LAYOUT_PATH);
    fs::create_dir_all(layout_path.parent().expect("layout parent"))
        .expect("create source layout directory");
    fs::write(&layout_path, b"trusted layout").expect("write trusted source layout");
    for arguments in [
        vec!["init", "-q"],
        vec!["add", super::LAYOUT_PATH],
        vec![
            "-c",
            "user.name=Wyrmroot test",
            "-c",
            "user.email=wyrmroot-test@example.invalid",
            "-c",
            "commit.gpgsign=false",
            "commit",
            "-q",
            "-m",
            "fixture",
        ],
    ] {
        assert!(
            std::process::Command::new("git")
                .arg("-C")
                .arg(&source_root)
                .args(arguments)
                .status()
                .expect("run source fixture Git command")
                .success()
        );
    }
    let expected_revision = super::git_output_bounded(
        &source_root,
        ["rev-parse", "HEAD"],
        super::MAX_GIT_REVISION_STDOUT_BYTES,
        "source fixture revision",
    )
    .expect("read source fixture revision")
    .trim()
    .to_owned();
    let path = root.join("policy.rs");
    fs::write(&path, b"trusted policy").expect("write generated fixture");
    let build = DeepLayoutBuild {
        policy_path: path.clone(),
        layout_sha256: bytes_digest(b"trusted layout"),
        policy_sha256: bytes_digest(b"trusted policy"),
        source_root: source_root.clone(),
        expected_revision: expected_revision.clone(),
    };
    build.verify_unchanged().expect("trusted policy rejected");
    fs::write(&path, b"changed policy").expect("replace policy contents");
    assert!(build.verify_unchanged().is_err());
    fs::write(&path, b"trusted policy").expect("restore trusted policy");
    build.verify_unchanged().expect("restored policy rejected");
    fs::remove_file(&path).expect("remove trusted policy");
    let target = root.join("target.rs");
    fs::write(&target, b"trusted policy").expect("write symlink target");
    symlink(&target, &path).expect("swap policy for symlink");
    assert!(build.verify_unchanged().is_err());
    fs::remove_file(&path).expect("remove policy symlink");
    fs::write(&path, b"trusted policy").expect("restore policy after symlink");
    build
        .verify_unchanged()
        .expect("policy restored after symlink rejected");

    fs::write(&layout_path, b"changed layout").expect("change source layout");
    assert!(build.verify_unchanged().is_err());
    fs::write(&layout_path, b"trusted layout").expect("restore source layout");
    build
        .verify_unchanged()
        .expect("restored source layout rejected");

    assert!(
        std::process::Command::new("git")
            .arg("-C")
            .arg(&source_root)
            .args([
                "-c",
                "user.name=Wyrmroot test",
                "-c",
                "user.email=wyrmroot-test@example.invalid",
                "-c",
                "commit.gpgsign=false",
                "commit",
                "-q",
                "--allow-empty",
                "-m",
                "move head",
            ])
            .status()
            .expect("move source fixture HEAD")
            .success()
    );
    assert!(build.verify_unchanged().is_err());

    fs::remove_dir_all(root).expect("remove isolated generated directory");
    fs::remove_dir_all(source_root).expect("remove isolated source repository");
}

#[cfg(unix)]
#[test]
fn generated_policy_writer_rejects_symlink_ancestry_and_destination() {
    use std::fs;
    use std::os::unix::fs::symlink;
    use std::time::{SystemTime, UNIX_EPOCH};

    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock precedes Unix epoch")
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "wyrmroot-generated-write-test-{}-{nonce}",
        std::process::id()
    ));
    let outside = std::env::temp_dir().join(format!(
        "wyrmroot-generated-outside-test-{}-{nonce}",
        std::process::id()
    ));
    fs::create_dir(&root).expect("create generated root");
    fs::create_dir(&outside).expect("create outside root");
    symlink(&outside, root.join("target")).expect("create generated ancestry symlink");
    let path = root.join(super::GENERATED_POLICY_PATH);
    assert!(write_generated_policy(&root, &path, "trusted").is_err());

    fs::remove_file(root.join("target")).expect("remove ancestry symlink");
    fs::create_dir_all(path.parent().expect("generated parent")).expect("create generated parent");
    let outside_file = outside.join("outside.rs");
    fs::write(&outside_file, b"outside").expect("write outside file");
    symlink(&outside_file, &path).expect("create destination symlink");
    assert!(write_generated_policy(&root, &path, "trusted").is_err());
    assert_eq!(
        fs::read(&outside_file).expect("read outside file"),
        b"outside"
    );
    fs::remove_file(&path).expect("remove destination symlink");
    write_generated_policy(&root, &path, "trusted").expect("write generated policy");
    assert_eq!(fs::read(&path).expect("read generated policy"), b"trusted");
    assert!(
        fs::read_dir(path.parent().expect("generated parent"))
            .expect("read generated directory")
            .all(|entry| {
                !entry
                    .expect("read generated entry")
                    .file_name()
                    .to_string_lossy()
                    .contains(".tmp-")
            })
    );

    fs::remove_dir_all(&root).expect("remove generated root");
    fs::remove_dir_all(&outside).expect("remove outside root");
}

#[test]
fn exact_layout_bytes_are_bound_to_the_pinned_git_blob() {
    use std::fs;
    use std::process::Command;
    use std::time::{SystemTime, UNIX_EPOCH};

    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock precedes Unix epoch")
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "wyrmroot-layout-git-blob-test-{}-{nonce}",
        std::process::id()
    ));
    let layout_path = root.join(super::LAYOUT_PATH);
    fs::create_dir_all(layout_path.parent().expect("layout parent"))
        .expect("create layout fixture tree");
    fs::write(&layout_path, b"trusted layout bytes\n").expect("write layout fixture");
    for arguments in [
        vec!["init", "-q"],
        vec!["add", super::LAYOUT_PATH],
        vec![
            "-c",
            "user.name=Wyrmroot test",
            "-c",
            "user.email=wyrmroot-test@example.invalid",
            "-c",
            "commit.gpgsign=false",
            "commit",
            "-q",
            "-m",
            "fixture",
        ],
    ] {
        assert!(
            Command::new("git")
                .arg("-C")
                .arg(&root)
                .args(arguments)
                .status()
                .expect("run fixture Git command")
                .success()
        );
    }
    verify_tracked_bytes(&root, super::LAYOUT_PATH, b"trusted layout bytes\n")
        .expect("exact committed layout bytes rejected");
    assert!(verify_tracked_bytes(&root, super::LAYOUT_PATH, b"swapped layout bytes\n").is_err());
    fs::remove_dir_all(root).expect("remove isolated Git fixture");
}

#[test]
fn layout_read_detects_a_path_swap_after_open() {
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock precedes Unix epoch")
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "wyrmroot-layout-path-swap-test-{}-{nonce}",
        std::process::id()
    ));
    fs::create_dir(&root).expect("create isolated layout directory");
    let path = root.join("layout.toml");
    fs::write(&path, b"trusted").expect("write trusted layout");
    let open = open_stable_regular_file(&path, "test layout").expect("open trusted layout");
    fs::rename(&path, root.join("original.toml")).expect("move open layout");
    fs::write(&path, b"replacement").expect("install replacement layout");
    assert!(verify_open_file_identity(&open, &path, "test layout").is_err());
    fs::remove_dir_all(root).expect("remove isolated layout directory");
}

#[test]
fn cargo_checkout_marker_is_the_only_allowed_untracked_entry() {
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock precedes Unix epoch")
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "wyrmroot-cargo-marker-test-{}-{nonce}",
        std::process::id()
    ));
    fs::create_dir(&root).expect("create isolated checkout root");
    fs::write(root.join(".cargo-ok"), []).expect("write empty Cargo marker");
    validate_git_status(&root, "?? .cargo-ok\n").expect("canonical Cargo checkout marker rejected");
    assert!(validate_git_status(&root, "?? layout.toml\n").is_err());
    fs::write(root.join(".cargo-ok"), b"contaminated").expect("replace marker content");
    assert!(validate_git_status(&root, "?? .cargo-ok\n").is_err());
    fs::remove_dir_all(root).expect("remove isolated checkout root");
}

fn layout(link_base: &str) -> String {
    layout_with_transition(link_base, "0xffffff0000000000", 256)
}

fn layout_with_transition(
    link_base: &str,
    temporary_virtual_address: &str,
    maximum_table_frame_count: u64,
) -> String {
    let temporary = u64::from_str_radix(
        temporary_virtual_address
            .strip_prefix("0x")
            .expect("fixture temporary address must be hexadecimal"),
        16,
    )
    .expect("fixture temporary address must fit u64");
    let [pml4_index, pdpt_index, pd_index, pt_index] = x86_64_page_table_indices(temporary);
    format!(
        r#"schema = "deepwyrm-x86_64-layout"
version = 2
entry_contract = "DW_BOOT_X86_64_ENTRY_V1"
elf_type = "ET_EXEC"
entry_symbol = "_dw_kernel_entry"
link_base = "{link_base}"
base_page_size = 4096
red_zone = false
kernel_boot_stack_size = 4194304
kernel_boot_stack_alignment = 4096
loader_transition_stack_size = 16384
loader_transition_stack_alignment = 4096
p_paddr_policy = "ignored"
allowed_program_header_types = ["PT_LOAD"]

[load_policy]
upper_canonical = true
non_overlapping = true
writable_xor_executable = true
entry_in_executable_segment = true

[entry_state]
transfer = "jmp"
returns = false
boot_info_register = "RDI"
boot_info_address = "identity-mapped-physical"
boot_info_alignment = 8
defined_incoming_gprs = ["RDI"]
loader_stack_owner = "loader"
loader_stack_rsp = "one-past-end"
loader_stack_rsp_mod_16 = 0
loader_stack_lifetime = "until-kernel-page-table-replacement"
immediate_kernel_stack_switch = true
kernel_stack_owner = "kernel"
kernel_stack_rsp_mod_16_before_call = 0
rust_entry_rsp_mod_16 = 8
rust_entry_abi = "sysv64"
interrupts_enabled = false
direction_flag_set = false
cr0_write_protect = true
execute_disable = true
paging_mode = "x86_64-4-level"
initial_processor = "BSP"
descriptor_state = "valid-CS-SS-others-unspecified"
tls_state = "FS-GS-unspecified"
fp_simd_state = "unavailable-until-kernel-initialization"
uefi_services_available = false
firmware_exit = "ExitBootServices-complete"

[handoff_mappings]
kernel_load_segments = "mapped-at-p_vaddr"
physical_allocation = "arbitrary-suitable-firmware-pages"
boot_info = "identity-mapped"
referenced_ranges = "identity-mapped"
lifetime = "until-kernel-page-table-replacement"
referenced_ranges_mutable = false
page_zero_mapped = false
framebuffer_pixels_identity_mapped = false

[early_intake]
max_normalized_memory_map_entries = 128
max_module_entries = 16
acpi_scope = "rsdp-only"
acpi_guid_preference = "ACPI_20_TABLE_GUID-then-ACPI_TABLE_GUID"
acpi_duplicate_selected_guid = "reject"
acpi_preferred_invalid = "reject-no-downgrade"
acpi_rsdp_signature = "RSD PTR "
acpi_rsdp_length_rule = "revision-lt-2:20;revision-ge-2:declared-36..4096"
acpi_rsdp_checksum = "v1-first-20-and-v2-full-record"
acpi_rsdp_mapping = "validated-record-intersecting-base-pages-only"
acpi_rsdp_max_intersecting_pages = 2
acpi_mapping_overlap = "coalesce"
acpi_table_traversal = "deferred-dw0-c"
acpi_memory_types_identity_mapped = false

[transition_tables]
contract = "DW_BOOT_X86_64_PAGING_HANDOFF_V1"
layout_version = 2
temporary_virtual_address = "{temporary_virtual_address}"
temporary_page_count = 1
pml4_index = {pml4_index}
pdpt_index = {pdpt_index}
pd_index = {pd_index}
pt_index = {pt_index}
minimum_table_frame_count = 4
maximum_table_frame_count = {maximum_table_frame_count}
initial_leaf = "exactly-zero-non-present"
temporary_leaf_permissions = "supervisor-rw-nx-base-page"
identity_alias_permissions = "supervisor-rw-nx-base-page"
identity_alias_mutable_by_deepwyrm = true
cache_selection_bits = 0
pat_entry_zero = "observed-write-back"
mtrr_policy = "alias-consistent-no-effective-write-back-claim"
pcide_enabled = false
pge_enabled = false
cr3_low_bits_zero = true
ownership_transfer = "loader-to-deepwyrm-after-exit-boot-services"
lifetime = "until-deepwyrm-cr3-switch"
concurrency = "bsp-aps-off-if-clear-nonreentrant"
physical_role_policy = "exclusive-table-frames-no-kernel-module-data-alias"
new_root_table_access = "deepwyrm-owned-before-cr3-switch"
"#
    )
}
