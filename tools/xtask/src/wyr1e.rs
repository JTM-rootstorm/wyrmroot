//! Deterministic, selector-free WYR1-E6 native product freeze and inspection.

use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::OsStr,
    fs::{self, File},
    path::{Component, Path, PathBuf},
};

use crate::{error::Failure, metadata::BuildManifest, secure_fs::Directory, sha256, wyr1c};

const PRODUCT_KIND: &str = "wyrmroot-wyr1-e6-normal-native-product";
const SOURCE_KIND: &str = "wyrmroot-wyr1-e6-source-build-v1";
const FREEZE_KIND: &str = "wyrmroot-wyr1-e6-freeze-v1";
const MAX_ARTIFACT_BYTES: u64 = 64 * 1024 * 1024;
const MAX_BOOTFS_BYTES: u64 = crate::g3_image::IMAGE_BYTES;
const MAX_REPORT_BYTES: u64 = 64 * 1024;
const ACCEPTED_RUST_REVISION: &str = "a92dc7f7464ad6ddfece4402bd7b86dbfa86166d";
const ACCEPTED_TOOLCHAIN_NAME: &str = "wyrmroot-1.97.1-a92dc7f7";

struct FrozenSnapshot {
    product: wyr1c::E6Snapshot,
    source_receipt: Vec<u8>,
    freeze_receipt: Vec<u8>,
}

struct Publication {
    artifacts_dir: Directory,
    inspections_dir: Directory,
    product_dir: Directory,
    artifacts: BTreeMap<String, File>,
    inspections: BTreeMap<String, File>,
    stack_report: File,
    rrc: File,
    wrdm: File,
    policy: File,
    bootfs: File,
    source_receipt: File,
    freeze_receipt: File,
}

pub(crate) fn product(output: &Path) -> Result<String, Failure> {
    wyr1c::reject_e6_ambient_build_environment(std::env::vars_os())?;
    let repository = crate::tasks::repository_root()?;
    let project = crate::tasks::canonical_project_root(&repository)?;
    let output = wyr1c::validate_fresh_output(&repository, &project, output)?;
    let parent_path = output
        .parent()
        .ok_or_else(|| Failure::task("WYR1-E6 output has no parent"))?;
    let name = output
        .file_name()
        .and_then(OsStr::to_str)
        .ok_or_else(|| Failure::task("WYR1-E6 output name is not UTF-8"))?;
    let parent = Directory::open_exact(parent_path, "WYR1-E6 output parent")?;
    let parent_mode = parent.owned_container_mode("WYR1-E6 output parent")?;
    let output_dir = parent.create_child(name, 0o700, "WYR1-E6 output")?;

    let product = wyr1c::build_e6_snapshot()?;
    let source_receipt = render_source_receipt(&repository, &product)?;
    let freeze_receipt = render_freeze_receipt(&product, &source_receipt);
    let snapshot = FrozenSnapshot {
        product,
        source_receipt: source_receipt.into_bytes(),
        freeze_receipt: freeze_receipt.into_bytes(),
    };
    validate_snapshot(&repository, &snapshot)?;
    let mut publication = publish(&output_dir, &snapshot)?;
    verify_publication(&parent, parent_mode, name, &output_dir, &publication)?;
    let reopened = snapshot_from_publication(&mut publication)?;
    validate_snapshot(&repository, &reopened)?;
    if reopened.source_receipt != snapshot.source_receipt
        || reopened.freeze_receipt != snapshot.freeze_receipt
        || reopened.product != snapshot.product
    {
        return Err(Failure::task(
            "WYR1-E6 frozen bytes changed during publication",
        ));
    }
    verify_publication(&parent, parent_mode, name, &output_dir, &publication)?;
    Ok(format!(
        "WYR1_E6_PRODUCT_PASS product_kind={PRODUCT_KIND} selector=none evidence=not-produced wyrmroot_revision={} bootfs_sha256={} receipt={}\n",
        snapshot.product.wyrmroot_revision,
        sha256::bytes_digest(&snapshot.product.bootfs),
        output.join("product/freeze-receipt.toml").display(),
    ))
}

pub(crate) fn inspect(output: &Path) -> Result<String, Failure> {
    wyr1c::reject_ambient_build_environment(std::env::vars_os())?;
    let repository = crate::tasks::repository_root()?;
    let project = crate::tasks::canonical_project_root(&repository)?;
    let output = validate_existing_output(&repository, &project, output)?;
    let output_dir = Directory::open_exact(&output, "WYR1-E6 output")?;
    let parent_path = output
        .parent()
        .ok_or_else(|| Failure::task("WYR1-E6 output has no parent"))?;
    let name = output
        .file_name()
        .and_then(OsStr::to_str)
        .ok_or_else(|| Failure::task("WYR1-E6 output name is not UTF-8"))?;
    let parent = Directory::open_exact(parent_path, "WYR1-E6 output parent")?;
    let parent_mode = parent.owned_container_mode("WYR1-E6 output parent")?;
    let mut publication = open_publication(&output_dir)?;
    verify_publication(&parent, parent_mode, name, &output_dir, &publication)?;
    let snapshot = snapshot_from_publication(&mut publication)?;
    validate_snapshot(&repository, &snapshot)?;
    verify_publication(&parent, parent_mode, name, &output_dir, &publication)?;
    Ok(format!(
        "WYR1_E6_INSPECT_PASS product_kind={PRODUCT_KIND} selector=none evidence=not-produced wyrmroot_revision={} bootfs_sha256={}\n",
        snapshot.product.wyrmroot_revision,
        sha256::bytes_digest(&snapshot.product.bootfs),
    ))
}

fn render_source_receipt(
    repository: &Path,
    product: &wyr1c::E6Snapshot,
) -> Result<String, Failure> {
    let manifest = BuildManifest::load(repository)?;
    if manifest.rust_revision()? != ACCEPTED_RUST_REVISION
        || manifest.rust_toolchain_name()? != ACCEPTED_TOOLCHAIN_NAME
    {
        return Err(Failure::task(
            "WYR1-E6 source receipt has the wrong Rust identity",
        ));
    }
    let profile = manifest.validate_loader_build_readiness(repository)?;
    let toolchain = crate::tasks::prepare_loader_toolchain(repository, &profile, &manifest)?;
    let cargo_home = crate::tasks::project_cargo_home(repository, &manifest)?;
    toolchain.accepted().verify_unchanged()?;
    let deep_source = wyr1c::inspect_e6_dependency_source(
        repository,
        &manifest,
        toolchain.accepted(),
        &cargo_home,
    )?;
    let analyzer = repository.join("tools/wyrmsh-native-stack.py");
    let assembled = wyr1c::reassemble_e6_snapshot(&product.wyrmroot_revision, &product.artifacts)?;
    let mut output = format!(
        "kind = \"{SOURCE_KIND}\"\nschema_version = 1\nproduct_kind = \"{PRODUCT_KIND}\"\nselector = \"none\"\nevidence = \"not-produced\"\nwyrmroot_revision = \"{}\"\ndeepwyrm_abi_revision = \"{}\"\ndeepwyrm_source_tree = \"{}\"\ndeepwyrm_source_archive_sha256 = \"{}\"\ngit_path = \"{}\"\ngit_sha256 = \"{}\"\ncargo_lock_sha256 = \"{}\"\nrust_revision = \"{}\"\nrust_toolchain_name = \"{}\"\nrustc_sha256 = \"{}\"\ncargo_sha256 = \"{}\"\nrust_lld_sha256 = \"{}\"\ntoolchain_manifest_sha256 = \"{}\"\ntoolchain_tree_sha256 = \"{}\"\nbuild_environment = \"env-clear PATH=accepted-toolchain-bin:/usr/lib/llvm/22/bin:/usr/bin:/bin LC_ALL=C CARGO_HOME=canonical-project-offline-v1 CARGO_INCREMENTAL=0 CARGO_NET_OFFLINE=true SOURCE_DATE_EPOCH=0 RUSTC=accepted-rustc TMPDIR=per-operation-project-scratch LD_AUDIT=unset LD_LIBRARY_PATH=unset LD_PRELOAD=unset\"\npath_remaps = \"wyrmroot=/source/wyrmroot cargo-home=/cargo-home per-artifact-target=/cargo-target\"\nstack_analyzer_path = \"tools/wyrmsh-native-stack.py\"\nstack_analyzer_sha256 = \"{}\"\nboot_generation = \"{}\"\n",
        product.wyrmroot_revision,
        manifest.deepwyrm_revision()?,
        deep_source.tree(),
        deep_source.archive_sha256(),
        crate::deep_layout::FIXED_GIT,
        deep_source.git_sha256(),
        sha256::file_digest(&repository.join("Cargo.lock"))
            .map_err(|error| Failure::task(format!("could not hash Cargo.lock: {error}")))?,
        manifest.rust_revision()?,
        manifest.rust_toolchain_name()?,
        toolchain.accepted().rustc_sha256,
        toolchain.accepted().cargo_sha256,
        toolchain.accepted().rust_lld_sha256,
        toolchain.accepted().manifest_sha256,
        toolchain.accepted().toolchain_tree_sha256,
        sha256::file_digest(&analyzer)
            .map_err(|error| Failure::task(format!("could not hash stack analyzer: {error}")))?,
        hex_digest(&assembled.generation),
    );
    for label in wyr1c::E6_ARTIFACT_LABELS {
        let bytes = product
            .artifacts
            .get(label)
            .ok_or_else(|| Failure::task(format!("WYR1-E6 source receipt lacks {label}")))?;
        let inspection = product.inspections.get(label).ok_or_else(|| {
            Failure::task(format!("WYR1-E6 source receipt lacks {label} inspection"))
        })?;
        output.push_str(&format!(
            "{label}_path = \"artifacts/{label}.elf\"\n{label}_sha256 = \"{}\"\n{label}_command = \"{}\"\n{label}_inspection_path = \"inspections/{label}.json\"\n{label}_inspection_sha256 = \"{}\"\n",
            sha256::bytes_digest(bytes),
            wyr1c::e6_native_command(label)?,
            sha256::bytes_digest(inspection),
        ));
    }
    output.push_str(&format!(
        "wyrmsh_stack_report_path = \"inspections/wyrmsh-stack.json\"\nwyrmsh_stack_report_sha256 = \"{}\"\n",
        sha256::bytes_digest(&product.stack_report),
    ));
    if output.len() as u64 > MAX_REPORT_BYTES {
        return Err(Failure::task(
            "WYR1-E6 source receipt exceeds its fixed bound",
        ));
    }
    deep_source.verify_unchanged()?;
    Ok(output)
}

fn render_freeze_receipt(product: &wyr1c::E6Snapshot, source_receipt: &str) -> String {
    format!(
        "kind = \"{FREEZE_KIND}\"\nschema_version = 1\nproduct_kind = \"{PRODUCT_KIND}\"\nselector = \"none\"\nevidence = \"not-produced\"\nwyrmroot_revision = \"{}\"\nsource_receipt_path = \"product/e6-source-build.toml\"\nsource_receipt_sha256 = \"{}\"\nrrc_manifest_path = \"product/rrc-e6-v1.bin\"\nrrc_manifest_sha256 = \"{}\"\ndevice_manifest_path = \"product/wrdm-e6-v1.bin\"\ndevice_manifest_sha256 = \"{}\"\nlaunch_policy_path = \"product/launch-policy-e6-v1.bin\"\nlaunch_policy_sha256 = \"{}\"\nbootfs_path = \"product/bootfs.img\"\nbootfs_sha256 = \"{}\"\nbootfs_bytes = {}\nstack_report_path = \"inspections/wyrmsh-stack.json\"\nstack_report_sha256 = \"{}\"\n",
        product.wyrmroot_revision,
        sha256::bytes_digest(source_receipt.as_bytes()),
        sha256::bytes_digest(&product.rrc_manifest),
        sha256::bytes_digest(&product.device_manifest),
        sha256::bytes_digest(&product.launch_policy),
        sha256::bytes_digest(&product.bootfs),
        product.bootfs.len(),
        sha256::bytes_digest(&product.stack_report),
    )
}

fn validate_snapshot(repository: &Path, snapshot: &FrozenSnapshot) -> Result<(), Failure> {
    let revision = wyr1c::clean_repository_revision(repository)?;
    if revision != snapshot.product.wyrmroot_revision {
        return Err(Failure::task("WYR1-E6 source revision changed"));
    }
    wyr1c::validate_e6_artifact_reports(
        repository,
        &snapshot.product.artifacts,
        &snapshot.product.inspections,
        &snapshot.product.stack_report,
    )?;
    let assembled = wyr1c::reassemble_e6_snapshot(&revision, &snapshot.product.artifacts)?;
    if assembled.rrc_manifest != snapshot.product.rrc_manifest
        || assembled.device_manifest != snapshot.product.device_manifest
        || assembled.launch_policy != snapshot.product.launch_policy
        || assembled.bootfs != snapshot.product.bootfs
    {
        return Err(Failure::task(
            "WYR1-E6 product bytes failed deterministic reconstruction",
        ));
    }
    let expected_source = render_source_receipt(repository, &snapshot.product)?;
    if snapshot.source_receipt != expected_source.as_bytes() {
        return Err(Failure::task("WYR1-E6 source receipt is not canonical"));
    }
    let expected_freeze = render_freeze_receipt(&snapshot.product, &expected_source);
    if snapshot.freeze_receipt != expected_freeze.as_bytes() {
        return Err(Failure::task("WYR1-E6 freeze receipt is not canonical"));
    }
    Ok(())
}

fn publish(output: &Directory, snapshot: &FrozenSnapshot) -> Result<Publication, Failure> {
    let artifacts_dir = output.create_child("artifacts", 0o700, "WYR1-E6 artifacts")?;
    let inspections_dir = output.create_child("inspections", 0o700, "WYR1-E6 inspections")?;
    let product_dir = output.create_child("product", 0o700, "WYR1-E6 product")?;
    let mut artifacts = BTreeMap::new();
    let mut inspections = BTreeMap::new();
    for label in wyr1c::E6_ARTIFACT_LABELS {
        artifacts.insert(
            label.to_owned(),
            artifacts_dir.write_new_retained(
                &format!("{label}.elf"),
                snapshot.product.artifacts.get(label).unwrap(),
                0o400,
                "WYR1-E6 artifact",
            )?,
        );
        inspections.insert(
            label.to_owned(),
            inspections_dir.write_new_retained(
                &format!("{label}.json"),
                snapshot.product.inspections.get(label).unwrap(),
                0o400,
                "WYR1-E6 inspection",
            )?,
        );
    }
    let stack_report = inspections_dir.write_new_retained(
        "wyrmsh-stack.json",
        &snapshot.product.stack_report,
        0o400,
        "WYR1-E6 stack report",
    )?;
    let rrc = product_dir.write_new_retained(
        "rrc-e6-v1.bin",
        &snapshot.product.rrc_manifest,
        0o400,
        "WYR1-E6 WRRM",
    )?;
    let wrdm = product_dir.write_new_retained(
        "wrdm-e6-v1.bin",
        &snapshot.product.device_manifest,
        0o400,
        "WYR1-E6 WRDM",
    )?;
    let policy = product_dir.write_new_retained(
        "launch-policy-e6-v1.bin",
        &snapshot.product.launch_policy,
        0o400,
        "WYR1-E6 launch policy",
    )?;
    let bootfs = product_dir.write_new_retained(
        "bootfs.img",
        &snapshot.product.bootfs,
        0o400,
        "WYR1-E6 bootfs",
    )?;
    let source_receipt = product_dir.write_new_retained(
        "e6-source-build.toml",
        &snapshot.source_receipt,
        0o400,
        "WYR1-E6 source receipt",
    )?;
    let freeze_receipt = product_dir.write_new_retained(
        "freeze-receipt.toml",
        &snapshot.freeze_receipt,
        0o400,
        "WYR1-E6 freeze receipt",
    )?;
    Ok(Publication {
        artifacts_dir,
        inspections_dir,
        product_dir,
        artifacts,
        inspections,
        stack_report,
        rrc,
        wrdm,
        policy,
        bootfs,
        source_receipt,
        freeze_receipt,
    })
}

fn open_publication(output: &Directory) -> Result<Publication, Failure> {
    let artifacts_dir = output.open_child("artifacts", "WYR1-E6 artifacts")?;
    let inspections_dir = output.open_child("inspections", "WYR1-E6 inspections")?;
    let product_dir = output.open_child("product", "WYR1-E6 product")?;
    let mut artifacts = BTreeMap::new();
    let mut inspections = BTreeMap::new();
    for label in wyr1c::E6_ARTIFACT_LABELS {
        artifacts.insert(
            label.to_owned(),
            artifacts_dir.open_retained_file(
                &format!("{label}.elf"),
                MAX_ARTIFACT_BYTES,
                "WYR1-E6 artifact",
            )?,
        );
        inspections.insert(
            label.to_owned(),
            inspections_dir.open_retained_file(
                &format!("{label}.json"),
                MAX_REPORT_BYTES,
                "WYR1-E6 inspection",
            )?,
        );
    }
    Ok(Publication {
        stack_report: inspections_dir.open_retained_file(
            "wyrmsh-stack.json",
            MAX_REPORT_BYTES,
            "WYR1-E6 stack report",
        )?,
        rrc: product_dir.open_retained_file("rrc-e6-v1.bin", MAX_REPORT_BYTES, "WYR1-E6 WRRM")?,
        wrdm: product_dir.open_retained_file("wrdm-e6-v1.bin", MAX_REPORT_BYTES, "WYR1-E6 WRDM")?,
        policy: product_dir.open_retained_file(
            "launch-policy-e6-v1.bin",
            MAX_REPORT_BYTES,
            "WYR1-E6 launch policy",
        )?,
        bootfs: product_dir.open_retained_file("bootfs.img", MAX_BOOTFS_BYTES, "WYR1-E6 bootfs")?,
        source_receipt: product_dir.open_retained_file(
            "e6-source-build.toml",
            MAX_REPORT_BYTES,
            "WYR1-E6 source receipt",
        )?,
        freeze_receipt: product_dir.open_retained_file(
            "freeze-receipt.toml",
            MAX_REPORT_BYTES,
            "WYR1-E6 freeze receipt",
        )?,
        artifacts_dir,
        inspections_dir,
        product_dir,
        artifacts,
        inspections,
    })
}

fn snapshot_from_publication(publication: &mut Publication) -> Result<FrozenSnapshot, Failure> {
    let mut artifacts = BTreeMap::new();
    let mut inspections = BTreeMap::new();
    for label in wyr1c::E6_ARTIFACT_LABELS {
        artifacts.insert(
            label.to_owned(),
            publication.artifacts_dir.read_retained_exact(
                &format!("{label}.elf"),
                publication.artifacts.get_mut(label).unwrap(),
                MAX_ARTIFACT_BYTES,
                0o400,
                "WYR1-E6 artifact",
            )?,
        );
        inspections.insert(
            label.to_owned(),
            publication.inspections_dir.read_retained_exact(
                &format!("{label}.json"),
                publication.inspections.get_mut(label).unwrap(),
                MAX_REPORT_BYTES,
                0o400,
                "WYR1-E6 inspection",
            )?,
        );
    }
    let source_receipt = publication.product_dir.read_retained_exact(
        "e6-source-build.toml",
        &mut publication.source_receipt,
        MAX_REPORT_BYTES,
        0o400,
        "WYR1-E6 source receipt",
    )?;
    let revision = receipt_revision(&source_receipt)?;
    Ok(FrozenSnapshot {
        product: wyr1c::E6Snapshot {
            wyrmroot_revision: revision,
            rrc_manifest: publication.product_dir.read_retained_exact(
                "rrc-e6-v1.bin",
                &mut publication.rrc,
                MAX_REPORT_BYTES,
                0o400,
                "WYR1-E6 WRRM",
            )?,
            device_manifest: publication.product_dir.read_retained_exact(
                "wrdm-e6-v1.bin",
                &mut publication.wrdm,
                MAX_REPORT_BYTES,
                0o400,
                "WYR1-E6 WRDM",
            )?,
            launch_policy: publication.product_dir.read_retained_exact(
                "launch-policy-e6-v1.bin",
                &mut publication.policy,
                MAX_REPORT_BYTES,
                0o400,
                "WYR1-E6 launch policy",
            )?,
            bootfs: publication.product_dir.read_retained_exact(
                "bootfs.img",
                &mut publication.bootfs,
                MAX_BOOTFS_BYTES,
                0o400,
                "WYR1-E6 bootfs",
            )?,
            artifacts,
            inspections,
            stack_report: publication.inspections_dir.read_retained_exact(
                "wyrmsh-stack.json",
                &mut publication.stack_report,
                MAX_REPORT_BYTES,
                0o400,
                "WYR1-E6 stack report",
            )?,
        },
        source_receipt,
        freeze_receipt: publication.product_dir.read_retained_exact(
            "freeze-receipt.toml",
            &mut publication.freeze_receipt,
            MAX_REPORT_BYTES,
            0o400,
            "WYR1-E6 freeze receipt",
        )?,
    })
}

fn receipt_revision(bytes: &[u8]) -> Result<String, Failure> {
    let text = std::str::from_utf8(bytes)
        .map_err(|_| Failure::task("WYR1-E6 source receipt is not UTF-8"))?;
    let prefix = "wyrmroot_revision = \"";
    let value = text
        .lines()
        .find_map(|line| {
            line.strip_prefix(prefix)
                .and_then(|value| value.strip_suffix('"'))
        })
        .ok_or_else(|| Failure::task("WYR1-E6 source receipt lacks its revision"))?;
    if value.len() != 40
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(Failure::task("WYR1-E6 source receipt revision is invalid"));
    }
    Ok(value.to_owned())
}

fn verify_publication(
    parent: &Directory,
    parent_mode: u32,
    name: &str,
    output: &Directory,
    publication: &Publication,
) -> Result<(), Failure> {
    parent.verify_owned_container_path_mode(parent_mode, "WYR1-E6 output parent")?;
    parent.verify_child_identity(name, output, 0o700, "WYR1-E6 output")?;
    output.verify_child_identity(
        "artifacts",
        &publication.artifacts_dir,
        0o700,
        "WYR1-E6 artifacts",
    )?;
    output.verify_child_identity(
        "inspections",
        &publication.inspections_dir,
        0o700,
        "WYR1-E6 inspections",
    )?;
    output.verify_child_identity(
        "product",
        &publication.product_dir,
        0o700,
        "WYR1-E6 product",
    )?;
    verify_entry_set(output.path(), &["artifacts", "inspections", "product"])?;
    let artifact_names = wyr1c::E6_ARTIFACT_LABELS
        .iter()
        .map(|label| format!("{label}.elf"))
        .collect::<Vec<_>>();
    verify_entry_set_owned(publication.artifacts_dir.path(), &artifact_names)?;
    let mut inspection_names = wyr1c::E6_ARTIFACT_LABELS
        .iter()
        .map(|label| format!("{label}.json"))
        .collect::<Vec<_>>();
    inspection_names.push("wyrmsh-stack.json".to_owned());
    verify_entry_set_owned(publication.inspections_dir.path(), &inspection_names)?;
    verify_entry_set(
        publication.product_dir.path(),
        &[
            "rrc-e6-v1.bin",
            "wrdm-e6-v1.bin",
            "launch-policy-e6-v1.bin",
            "bootfs.img",
            "e6-source-build.toml",
            "freeze-receipt.toml",
        ],
    )
}

fn verify_entry_set(path: &Path, expected: &[&str]) -> Result<(), Failure> {
    let expected = expected
        .iter()
        .map(|value| (*value).to_owned())
        .collect::<Vec<_>>();
    verify_entry_set_owned(path, &expected)
}

fn verify_entry_set_owned(path: &Path, expected: &[String]) -> Result<(), Failure> {
    let mut actual = BTreeSet::new();
    for entry in fs::read_dir(path)
        .map_err(|error| Failure::task(format!("could not enumerate WYR1-E6 product: {error}")))?
    {
        let entry = entry
            .map_err(|error| Failure::task(format!("could not inspect WYR1-E6 entry: {error}")))?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| Failure::task("WYR1-E6 entry name is not UTF-8"))?;
        actual.insert(name);
    }
    let expected = expected.iter().cloned().collect::<BTreeSet<_>>();
    if actual != expected {
        return Err(Failure::task("WYR1-E6 frozen entry set drifted"));
    }
    Ok(())
}

fn validate_existing_output(
    repository: &Path,
    project: &Path,
    output: &Path,
) -> Result<PathBuf, Failure> {
    if output.is_absolute()
        && output
            .components()
            .any(|component| matches!(component, Component::ParentDir | Component::CurDir))
    {
        return Err(Failure::task("WYR1-E6 output path is not canonical"));
    }
    let output = fs::canonicalize(output)
        .map_err(|error| Failure::task(format!("could not resolve WYR1-E6 output: {error}")))?;
    let project = fs::canonicalize(project)
        .map_err(|error| Failure::task(format!("could not resolve OS-Project root: {error}")))?;
    let repository = fs::canonicalize(repository)
        .map_err(|error| Failure::task(format!("could not resolve Wyrmroot source: {error}")))?;
    if !output.starts_with(project) || output.starts_with(repository) {
        return Err(Failure::task(
            "WYR1-E6 output must remain inside OS-Project and outside the Wyrmroot source tree",
        ));
    }
    Ok(output)
}

fn hex_digest(digest: &[u8; 32]) -> String {
    let mut output = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write;
        write!(&mut output, "{byte:02x}").expect("writing to String cannot fail");
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn freeze_receipt_excludes_selectors_and_test_fixtures() {
        let product = wyr1c::E6Snapshot {
            wyrmroot_revision: "1".repeat(40),
            rrc_manifest: vec![1],
            device_manifest: vec![2],
            launch_policy: vec![3],
            bootfs: vec![4],
            artifacts: BTreeMap::new(),
            inspections: BTreeMap::new(),
            stack_report: vec![5],
        };
        let receipt = render_freeze_receipt(&product, "source\n");
        assert!(receipt.contains("selector = \"none\""));
        assert!(receipt.contains("evidence = \"not-produced\""));
        assert!(!receipt.contains("selector = \"33\""));
        assert!(!receipt.contains("cpu-hog"));
    }
}
