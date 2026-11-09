use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use deepwyrm_syscall as _;
use wyrmroot_bootfs as _;
use wyrmroot_loader as _;
use wyrmroot_runtime as _;
use wyrmroot_wyr1e_test_actors as _;

/// Source text: the link arguments are `cargo:` directives a build script
/// prints for rustc; no host test or type can observe them, and the guest
/// link that consumes them runs only in the native product builds.
#[test]
fn binaries_use_canonical_linker_and_exact_paths() {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let build = fs::read_to_string(manifest_dir.join("build.rs")).unwrap();
    let main = &build[build.find("fn main()").expect("build script entry")..];
    assert!(main.contains("manifest.join(\"../../toolchain/native-user.ld\")"));
    // Every `[[bin]]` the manifest declares, and only those, is linked by
    // the loop, and the loop gives each one both arguments.
    let manifest = fs::read_to_string(manifest_dir.join("Cargo.toml")).unwrap();
    let declared = manifest
        .split("[[bin]]")
        .skip(1)
        .map(|table| {
            table
                .lines()
                .find_map(|line| line.strip_prefix("name = \""))
                .and_then(|name| name.strip_suffix('"'))
                .expect("bin name")
                .to_owned()
        })
        .collect::<BTreeSet<_>>();
    let list = &main[main.find("for binary in [").expect("binary loop")..];
    let (list, body) = list.split_once("] {").expect("binary list");
    let linked = list
        .split('"')
        .skip(1)
        .step_by(2)
        .map(str::to_owned)
        .collect::<BTreeSet<_>>();
    assert_eq!(linked, declared);
    let body = &body[..body.find("\n    }").expect("loop body")];
    assert!(body.contains("cargo:rustc-link-arg-bin={binary}=-T{}"));
    assert!(body.contains("cargo:rustc-link-arg-bin={binary}=--build-id=none"));
}

#[test]
fn fault_instruction_is_narrow_and_other_actor_sources_forbid_unsafe() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let fault = fs::read_to_string(root.join("src/bin/fault.rs")).unwrap();
    let exit = fs::read_to_string(root.join("src/bin/exit_nonzero.rs")).unwrap();
    let library = fs::read_to_string(root.join("src/lib.rs")).unwrap();
    assert_eq!(fault.matches("unsafe {").count(), 1);
    assert!(fault.contains("core::arch::asm!(\"ud2\""));
    assert!(fault.contains("options(noreturn, nostack, nomem)"));
    assert!(!exit.contains("unsafe {"));
    assert!(library.contains("#![forbid(unsafe_code)]"));
}

/// Source text: the actors must link `wyrmroot-runtime` and `deepwyrm-syscall`,
/// which export the device, publication and test-syscall surface
/// unconditionally (e.g. `wyrmroot_runtime::device_pio_read`), so neither the
/// dependency graph nor a feature set can keep these calls out.
#[test]
fn actors_have_no_privileged_or_test_evidence_calls() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    for path in [
        "src/lib.rs",
        "src/bin/exit_nonzero.rs",
        "src/bin/fault.rs",
        "src/bin/recovery_trigger.rs",
        "src/bin/stdout_pressure.rs",
    ] {
        let source = fs::read_to_string(root.join(path)).unwrap();
        for forbidden in [
            "submit_",
            "device_",
            "resource_domain",
            "SelfRoot",
            "PublicationAuthority",
            "DW_SYSCALL_TEST",
        ] {
            assert!(!source.contains(forbidden), "{path} contains {forbidden}");
        }
    }
}
