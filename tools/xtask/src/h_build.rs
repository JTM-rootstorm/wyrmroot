//! `xtask wyr0 build`: the canonical builder for a WYR0-H candidate.
//!
//! `image`, `run` and `test integration wyr0` admit a candidate only with a
//! `build-receipt.toml` beside its request (`verify_build_receipt`). Before
//! this command nothing produced one, so a selector without its own product
//! path (selector 22, `smp-runtime-stress`) could not be imaged without a
//! hand-filled lineage record. This builder measures every value instead.
//!
//! It builds exactly the six artifacts the request names -- loader, kernel,
//! symbols, bootstrap, init0 and hello -- from the clean checkouts the request
//! pins, writes them to those request-relative paths, and writes the receipt
//! last. The request's firmware inputs are hashed, not built. Feature sets come
//! only from [`SELECTOR_BUILDS`]; a selector absent from it is refused before
//! any build or write. All build scratch is a [`ScratchDirectory`] retired on
//! every path, so a successful build leaves nothing beside its outputs.
//!
//! [`ScratchDirectory`]: crate::secure_fs::ScratchDirectory

use std::env;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::error::Failure;
use crate::h_integration::{self, ReceiptOutputs};
use crate::h_request::{self, BUILD_RECEIPT_FILE, CheckedOutputRoot, HRequest};
use crate::metadata::BuildManifest;
use crate::product_engine::{
    MAX_ARTIFACT_BYTES, NativeArtifact, NativeBuildOptions, NativeSpec, build_native_with_flags,
    inspect_native,
};
use crate::secure_fs::Directory;
use crate::sha256;

const KERNEL_TARGET: &str = "x86_64-unknown-none";
const MAX_FIRMWARE_BYTES: u64 = 64 * 1024 * 1024;

/// One selector's exact build recipe.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct SelectorBuild {
    pub(crate) selector: &'static str,
    pub(crate) test_id: u32,
    pub(crate) schema_version: u32,
    /// Features for `deepwyrm-kernel`, built with
    /// `DEEPWYRM_GUEST_TEST_SELECTOR` set to [`Self::selector`].
    pub(crate) kernel_features: &'static str,
    pub(crate) bootstrap: NativeSpec,
    pub(crate) init0: NativeSpec,
    /// The payload the image places at `bin/hello`.
    pub(crate) hello: NativeSpec,
}

/// The one table that derives a WYR0-H candidate's build from its selector.
pub(crate) const SELECTOR_BUILDS: &[SelectorBuild] = &[
    // DW0-I2 runtime stress (`Plans/WYR0_I2_STRESS_PAYLOAD.md`).
    SelectorBuild {
        selector: "smp-runtime-stress",
        test_id: 22,
        schema_version: 2,
        kernel_features: "test-support",
        bootstrap: NativeSpec {
            label: "bootstrap",
            package: "wyrmroot-bootstrap",
            binary: "wyrmroot-bootstrap",
            features: "native-bootstrap,wyr0-init0-integration,i2-bootstrap-supervision",
            artifact: "wyrmroot-bootstrap",
        },
        init0: NativeSpec {
            label: "init0",
            package: "wyrmroot-init0",
            binary: "wyrmroot-init0",
            features: "native-init0,i2-stress-integration",
            artifact: "wyrmroot-init0",
        },
        hello: NativeSpec {
            label: "hello",
            package: "wyrmroot-i2-stress",
            binary: "wyrmroot-i2-stress",
            features: "native-i2-stress",
            artifact: "wyrmroot-i2-stress",
        },
    },
];

/// The recipe for `selector`, refusing any selector, test ID or schema the
/// table does not name exactly.
pub(crate) fn selector_build(
    selector: &str,
    test_id: u32,
    schema_version: u32,
) -> Result<&'static SelectorBuild, Failure> {
    let build = SELECTOR_BUILDS
        .iter()
        .find(|build| build.selector == selector)
        .ok_or_else(|| {
            Failure::task(format!(
                "WYR0-H build has no recipe for selector '{selector}'; add it to SELECTOR_BUILDS"
            ))
        })?;
    if build.test_id != test_id || build.schema_version != schema_version {
        return Err(Failure::task(format!(
            "WYR0-H build recipe for '{selector}' is test_id {} schema_version {}, not test_id {test_id} schema_version {schema_version}",
            build.test_id, build.schema_version
        )));
    }
    Ok(build)
}

/// The six artifacts a build writes, in request order.
struct Outputs {
    loader: PathBuf,
    kernel: PathBuf,
    symbols: PathBuf,
    bootstrap: PathBuf,
    init0: PathBuf,
    hello: PathBuf,
    receipt: PathBuf,
}

impl Outputs {
    fn of(request: &HRequest) -> Result<Self, Failure> {
        Ok(Self {
            loader: request.loader.clone(),
            kernel: request.kernel.clone(),
            symbols: request.symbols.clone(),
            bootstrap: request.bootstrap.clone(),
            init0: request.init0.clone(),
            hello: request.hello.clone(),
            receipt: request
                .path
                .parent()
                .ok_or_else(|| Failure::task("WYR0-H request has no parent directory"))?
                .join(BUILD_RECEIPT_FILE),
        })
    }

    fn named(&self) -> [(&Path, &'static str); 6] {
        [
            (&self.loader, "loader"),
            (&self.kernel, "kernel"),
            (&self.symbols, "symbols"),
            (&self.bootstrap, "bootstrap"),
            (&self.init0, "init0"),
            (&self.hello, "hello"),
        ]
    }
}

/// Refuses an output that is outside the request directory, already exists,
/// or overlaps another output; `kernel` and `symbols` may name one file.
fn admit_outputs(
    request: &HRequest,
    root: &CheckedOutputRoot,
    outputs: &Outputs,
) -> Result<(), Failure> {
    let request_root = request
        .path
        .parent()
        .ok_or_else(|| Failure::task("WYR0-H request has no parent directory"))?;
    let reserved = [
        (request.bootfs.as_path(), "bootfs"),
        (request.esp.as_path(), "esp"),
        (request.provenance.as_path(), "provenance"),
        (request.run_directory.as_path(), "run_directory"),
        (outputs.receipt.as_path(), "build receipt"),
    ];
    let named = outputs.named();
    for (index, (path, label)) in named.iter().enumerate() {
        if !path.starts_with(request_root) {
            return Err(Failure::task(format!(
                "WYR0-H build writes {label} only beneath the request directory; name it request-relative"
            )));
        }
        h_request::validate_output_parent(request, path, label)?;
        if root.exists(path, label)? {
            return Err(Failure::task(format!(
                "WYR0-H build output {label} already exists"
            )));
        }
        for (other, other_label) in reserved {
            if path.starts_with(other) || other.starts_with(path) {
                return Err(Failure::task(format!(
                    "WYR0-H build output {label} overlaps the request's {other_label}"
                )));
            }
        }
        for (other, other_label) in named.iter().skip(index + 1) {
            let same_kernel_file = *label == "kernel" && *other_label == "symbols";
            if (path == other && !same_kernel_file)
                || (path != other && (path.starts_with(other) || other.starts_with(path)))
            {
                return Err(Failure::task(format!(
                    "WYR0-H build outputs {label} and {other_label} overlap"
                )));
            }
        }
    }
    if root.exists(&outputs.receipt, "build receipt")? {
        return Err(Failure::task("WYR0-H build receipt already exists"));
    }
    Ok(())
}

/// Every check that needs no build: request shape, clean exact-revision
/// checkouts, and fresh disjoint request-relative outputs.
fn admit(request: &HRequest) -> Result<(CheckedOutputRoot, Outputs), Failure> {
    if request.capability.is_some() || request.evidence.is_some() {
        return Err(Failure::task(
            "WYR0-H build covers only schema-2 candidates without evidence or capability content",
        ));
    }
    h_integration::qualify_request_sources(request)?;
    let root = CheckedOutputRoot::open(request)?;
    let outputs = Outputs::of(request)?;
    admit_outputs(request, &root, &outputs)?;
    Ok((root, outputs))
}

struct Built {
    loader: Vec<u8>,
    kernel: Vec<u8>,
    bootstrap: Vec<u8>,
    init0: Vec<u8>,
    hello: Vec<u8>,
}

/// `xtask wyr0 build --request <request.toml>`.
pub(crate) fn build(request_path: &str) -> Result<String, Failure> {
    let request = h_request::load(Path::new(request_path))?;
    // Selector first: an unknown selector is refused before any build or write.
    let recipe = selector_build(&request.selector, request.test_id, request.schema_version)?;
    crate::wyr1c::reject_e6_ambient_build_environment(env::vars_os())?;
    let (root, outputs) = admit(&request)?;
    let ovmf_code = firmware_digest(&request.ovmf_code, "OVMF code")?;
    let ovmf_vars_template = firmware_digest(&request.ovmf_vars_template, "OVMF vars template")?;

    let repository = crate::tasks::repository_root()?;
    let project = crate::tasks::canonical_project_root(&repository)?;
    let deepwyrm = h_integration::source_workspace_root(&repository)?.join("deepwyrm");
    let manifest = BuildManifest::load(&repository)?;
    // ABI pairing and the accepted-toolchain record, exactly as verification
    // re-derives them.
    let identity = h_integration::certificate_identity(&request)?;
    let layout = crate::deep_layout::prepare_current_kernel_source(
        &repository,
        &deepwyrm,
        &request.deepwyrm_revision,
    )?;
    let profile = manifest.validate_loader_build_readiness(&repository)?;
    let toolchain = crate::tasks::prepare_loader_toolchain(&repository, &profile, &manifest)?;
    let cargo_home = crate::tasks::project_cargo_home(&repository, &manifest)?;
    if env::var_os("CARGO_HOME").as_deref() != Some(cargo_home.as_os_str()) {
        return Err(Failure::task(
            "WYR0-H build requires the pinned launcher's exact CARGO_HOME",
        ));
    }

    let project_directory = Directory::open_exact(&project, "OS-Project root")?;
    let project_tmp = open_or_create_tmp(&project_directory, "project temporary root")?;
    let scratch_name = unique_scratch_name()?;
    let scratch = project_tmp.create_scratch(&scratch_name, "WYR0-H build scratch")?;
    let userspace = (|| {
        let loader = scratch.with_inheritable_anchor("WYR0-H build scratch", |anchor| {
            let build = anchor.path();
            let uefi = crate::tasks::build_deterministic_uefi_pair_in_scratch(
                &repository,
                &toolchain,
                &profile,
                &layout,
                &crate::tasks::IsolatedUefiBuild {
                    cargo_home: &cargo_home,
                    production_target: &build.join("uefi-production"),
                    retained_debug_target: &build.join("uefi-retained-debug"),
                    cargo_profile: crate::tasks::UefiCargoProfile::Release,
                },
                anchor,
            )?;
            Ok(uefi.loader_bytes)
        })?;
        let mut natives = Vec::with_capacity(3);
        for spec in [recipe.bootstrap, recipe.init0, recipe.hello] {
            toolchain.accepted().verify_unchanged()?;
            layout.verify_unchanged()?;
            natives.push(
                scratch.with_inheritable_anchor("WYR0-H build scratch", |anchor| {
                    build_native(&repository, &cargo_home, &toolchain, anchor, spec)
                })?,
            );
        }
        Ok::<_, Failure>((loader, natives))
    })();
    let (loader, natives) = scratch.finish(userspace)?;
    let [bootstrap, init0, hello]: [NativeArtifact; 3] = natives
        .try_into()
        .map_err(|_| Failure::task("WYR0-H build produced the wrong native artifact count"))?;
    let kernel = build_kernel(&deepwyrm, recipe)?;

    // The same checkouts, still clean and at the request's revisions, and the
    // same toolchain and layout bytes, after every build.
    h_integration::qualify_request_sources(&request)?;
    toolchain.accepted().verify_unchanged()?;
    layout.verify_unchanged()?;

    let built = Built {
        loader,
        kernel,
        bootstrap: bootstrap.bytes,
        init0: init0.bytes,
        hello: hello.bytes,
    };
    let receipt_outputs = ReceiptOutputs {
        loader: sha256::bytes_digest(&built.loader),
        kernel: sha256::bytes_digest(&built.kernel),
        symbols: sha256::bytes_digest(&built.kernel),
        bootstrap: sha256::bytes_digest(&built.bootstrap),
        init0: sha256::bytes_digest(&built.init0),
        hello: sha256::bytes_digest(&built.hello),
        ovmf_code,
        ovmf_vars_template,
    };
    let receipt = h_integration::render_build_receipt(
        &request,
        &identity,
        &h_integration::receipt_sources(&request)?,
        &receipt_outputs,
    )?;
    publish(&request, &root, &outputs, &built, receipt.as_bytes())?;
    Ok(format!(
        concat!(
            "WYR0_H_BUILD_PASS selector={} test_id={} deepwyrm_revision={} ",
            "wyrmroot_revision={} rust_revision={} loader_sha256={} kernel_sha256={} ",
            "bootstrap_sha256={} init0_sha256={} hello_sha256={} receipt={}\n"
        ),
        request.selector,
        request.test_id,
        request.deepwyrm_revision,
        request.wyrmroot_revision,
        request.rust_revision,
        receipt_outputs.loader,
        receipt_outputs.kernel,
        receipt_outputs.bootstrap,
        receipt_outputs.init0,
        receipt_outputs.hello,
        outputs.receipt.display(),
    ))
}

/// Writes every artifact create-new, the receipt last, then admits the result
/// through the same verification `image` applies. Any failure removes every
/// file this call created.
fn publish(
    request: &HRequest,
    root: &CheckedOutputRoot,
    outputs: &Outputs,
    built: &Built,
    receipt: &[u8],
) -> Result<(), Failure> {
    let mut writes: Vec<(&Path, &[u8], &'static str)> = vec![
        (&outputs.loader, &built.loader, "loader"),
        (&outputs.kernel, &built.kernel, "kernel"),
    ];
    if outputs.symbols != outputs.kernel {
        writes.push((&outputs.symbols, &built.kernel, "symbols"));
    }
    writes.extend([
        (
            outputs.bootstrap.as_path(),
            built.bootstrap.as_slice(),
            "bootstrap",
        ),
        (outputs.init0.as_path(), built.init0.as_slice(), "init0"),
        (outputs.hello.as_path(), built.hello.as_slice(), "hello"),
        (outputs.receipt.as_path(), receipt, "build receipt"),
    ]);
    let mut created: Vec<(&Path, &str)> = Vec::with_capacity(writes.len());
    let result = (|| {
        for (path, bytes, label) in &writes {
            h_integration::write_new(root, path, bytes, label)?;
            created.push((path, label));
        }
        h_integration::verify_candidate(request)
    })();
    result.map_err(|error| {
        h_integration::with_rollback(error, h_integration::rollback_created(root, &created))
    })
}

fn build_native(
    repository: &Path,
    cargo_home: &Path,
    toolchain: &crate::tasks::LoaderToolchain,
    anchor: &crate::secure_fs::InheritableDirectory,
    spec: NativeSpec,
) -> Result<NativeArtifact, Failure> {
    let mut artifact = build_native_with_flags(
        repository,
        cargo_home,
        toolchain.accepted(),
        anchor,
        spec,
        None,
        NativeBuildOptions::exact(&[]),
    )?;
    artifact.inspection = inspect_native(
        repository,
        &artifact.bytes,
        &artifact.sha256,
        spec.label,
        anchor,
    )?;
    Ok(artifact)
}

/// Builds the selector's kernel from the qualified Deepwyrm checkout through
/// its own launcher, in a scratch target beneath `deepwyrm/.tmp`.
fn build_kernel(deepwyrm: &Path, recipe: &SelectorBuild) -> Result<Vec<u8>, Failure> {
    let repository = Directory::open_exact(deepwyrm, "Deepwyrm source root")?;
    let temporary = open_or_create_tmp(&repository, "Deepwyrm temporary root")?;
    let scratch = temporary.create_scratch(
        &format!("{}-kernel", unique_scratch_name()?),
        "WYR0-H Deepwyrm target",
    )?;
    let result = (|| {
        let status = Command::new(repository.path().join("tools/pinned-cargo"))
            .args(kernel_arguments(recipe))
            .env("DEEPWYRM_PINNED_TARGET_DIR", scratch.path())
            .env("DEEPWYRM_GUEST_TEST_SELECTOR", recipe.selector)
            .env_remove("DEEPWYRM_GUEST_TEST_ID")
            .env_remove("CARGO_HOME")
            .env_remove("LD_AUDIT")
            .env_remove("LD_LIBRARY_PATH")
            .env_remove("LD_PRELOAD")
            .current_dir(repository.path())
            .stdin(Stdio::null())
            .status();
        scratch.verify_unchanged()?;
        let status = status
            .map_err(|error| Failure::task(format!("could not build WYR0-H kernel: {error}")))?;
        if !status.success() {
            return Err(Failure::task(format!(
                "WYR0-H selector '{}' Deepwyrm kernel build failed",
                recipe.selector
            )));
        }
        scratch.read_producer(
            &PathBuf::from(KERNEL_TARGET).join("release/deepwyrm-kernel"),
            MAX_ARTIFACT_BYTES as u64,
            "WYR0-H kernel",
        )
    })();
    scratch.finish(result)
}

fn kernel_arguments(recipe: &SelectorBuild) -> [&'static str; 13] {
    [
        "target",
        "build",
        "--locked",
        "--offline",
        "--release",
        "--target",
        KERNEL_TARGET,
        "--package",
        "deepwyrm-kernel",
        "--bin",
        "deepwyrm-kernel",
        "--features",
        recipe.kernel_features,
    ]
}

fn firmware_digest(path: &Path, label: &str) -> Result<String, Failure> {
    let bytes = crate::wyr1c6::read_regular_bounded(path, MAX_FIRMWARE_BYTES, label)?;
    Ok(sha256::bytes_digest(&bytes))
}

fn open_or_create_tmp(parent: &Directory, label: &str) -> Result<Directory, Failure> {
    let directory = if parent.exists(".tmp", label)? {
        parent.open_child(".tmp", label)?
    } else {
        parent.create_child(".tmp", 0o700, label)?
    };
    directory.verify_owned_container_path(label)?;
    Ok(directory)
}

fn unique_scratch_name() -> Result<String, Failure> {
    let time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| Failure::task("system clock is before the Unix epoch"))?
        .as_nanos();
    Ok(format!("wyr0-h-build-{}-{time}", std::process::id()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn fixture_root(label: &str) -> PathBuf {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../target")
            .join(format!(
                "xtask-wyr0-build-{label}-{}-{}",
                std::process::id(),
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .expect("system clock before epoch")
                    .as_nanos()
            ));
        fs::create_dir_all(&root).expect("create fixture root");
        root
    }

    fn request_text(selector: &str, test_id: u32) -> String {
        format!(
            concat!(
                "schema_version = 2\n",
                "deepwyrm_revision = \"{rev}\"\n",
                "wyrmroot_revision = \"{rev}\"\n",
                "rust_revision = \"{rev}\"\n",
                "selector = \"{selector}\"\n",
                "test_id = {test_id}\n",
                "expected_outcome = \"pass\"\n",
                "expected_detail = 0\n",
                "timeout_seconds = 240\n",
                "loader = \"artifacts/loader.efi\"\n",
                "kernel = \"artifacts/deepwyrm.elf\"\n",
                "symbols = \"artifacts/deepwyrm.elf\"\n",
                "bootstrap = \"artifacts/bootstrap.elf\"\n",
                "init0 = \"artifacts/init0.elf\"\n",
                "hello = \"artifacts/hello.elf\"\n",
                "bootfs = \"media/bootfs.img\"\n",
                "esp = \"media/wyrmroot-esp.img\"\n",
                "provenance = \"media/provenance.toml\"\n",
                "ovmf_code = \"/usr/share/edk2/OvmfX64/OVMF_CODE.fd\"\n",
                "ovmf_vars_template = \"/usr/share/edk2/OvmfX64/OVMF_VARS.fd\"\n",
                "run_directory = \"runs\"\n",
            ),
            rev = "1".repeat(40),
            selector = selector,
            test_id = test_id,
        )
    }

    #[test]
    fn selector_table_covers_selector_22_with_the_i2_feature_sets() {
        let recipe = selector_build("smp-runtime-stress", 22, 2).expect("selector 22 recipe");
        assert_eq!(recipe.kernel_features, "test-support");
        assert_eq!(
            recipe.bootstrap.features,
            "native-bootstrap,wyr0-init0-integration,i2-bootstrap-supervision"
        );
        assert_eq!(recipe.init0.features, "native-init0,i2-stress-integration");
        assert_eq!(recipe.hello.package, "wyrmroot-i2-stress");
        assert_eq!(recipe.hello.features, "native-i2-stress");
        // The kernel command matches the canonical selector build shape.
        assert_eq!(
            kernel_arguments(recipe).join(" "),
            "target build --locked --offline --release --target x86_64-unknown-none \
             --package deepwyrm-kernel --bin deepwyrm-kernel --features test-support"
        );
    }

    #[test]
    fn every_selector_recipe_is_unique_and_compiled_by_the_unfiltered_gate() {
        for (index, recipe) in SELECTOR_BUILDS.iter().enumerate() {
            assert!(
                SELECTOR_BUILDS[index + 1..]
                    .iter()
                    .all(|other| other.selector != recipe.selector)
            );
            for spec in [recipe.bootstrap, recipe.init0, recipe.hello] {
                assert_eq!(spec.binary, spec.artifact);
                assert!(
                    crate::tasks::is_listed_combination(spec.package, spec.features),
                    "{} {} is not in FEATURE_COMBINATIONS_HAND_MAINTAINED",
                    spec.package,
                    spec.features
                );
            }
        }
    }

    #[test]
    fn unknown_selector_test_id_or_schema_is_refused() {
        assert!(
            selector_build("primordial-bootstrap", 18, 2)
                .unwrap_err()
                .message
                .contains("no recipe")
        );
        assert!(selector_build("smp-runtime-stress", 23, 2).is_err());
        assert!(selector_build("smp-runtime-stress", 22, 3).is_err());
    }

    #[test]
    fn unknown_selector_request_is_refused_before_any_write() {
        let root = fixture_root("unknown-selector");
        let request = root.join("request.toml");
        fs::write(&request, request_text("primordial-bootstrap", 18)).expect("write request");
        let error = build(request.to_str().unwrap()).expect_err("built an unknown selector");
        assert!(error.message.contains("no recipe"), "{}", error.message);
        assert!(!root.join(BUILD_RECEIPT_FILE).exists());
        assert!(!root.join("artifacts").exists());
        fs::remove_dir_all(root).expect("remove fixture");
    }

    #[test]
    fn mismatched_request_revisions_are_refused_before_any_write() {
        // Selector 22 passes the table; the all-ones revisions match no checkout.
        let root = fixture_root("revision-mismatch");
        let request = root.join("request.toml");
        fs::write(&request, request_text("smp-runtime-stress", 22)).expect("write request");
        let request = h_request::load(&request).expect("load request");
        let error = admit(&request).err().expect("admitted foreign revisions");
        assert!(
            error
                .message
                .contains("does not match the current checkout"),
            "{}",
            error.message
        );
        assert!(!root.join(BUILD_RECEIPT_FILE).exists());
        assert!(!root.join("artifacts").exists());
        fs::remove_dir_all(root).expect("remove fixture");
    }

    fn git(repository: &Path, arguments: &[&str]) {
        let status = Command::new("git")
            .arg("-C")
            .arg(repository)
            .args([
                "-c",
                "user.name=fixture",
                "-c",
                "user.email=fixture@invalid",
                "-c",
                "commit.gpgsign=false",
            ])
            .args(arguments)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .expect("run git");
        assert!(status.success(), "git {arguments:?} failed");
    }

    #[test]
    fn dirty_checkout_is_refused_by_the_source_qualification() {
        let root = fixture_root("dirty-checkout");
        git(&root, &["init", "--quiet"]);
        fs::write(root.join("tracked"), b"one\n").expect("write tracked file");
        git(&root, &["add", "tracked"]);
        git(&root, &["commit", "--quiet", "-m", "fixture"]);
        let output = Command::new("git")
            .arg("-C")
            .arg(&root)
            .args(["rev-parse", "HEAD"])
            .output()
            .expect("read fixture revision");
        let revision = String::from_utf8(output.stdout).unwrap().trim().to_owned();

        h_integration::qualify_source(&root, &revision, "fixture").expect("clean checkout");
        fs::write(root.join("tracked"), b"two\n").expect("modify tracked file");
        let modified = h_integration::qualify_source(&root, &revision, "fixture")
            .expect_err("accepted a modified checkout");
        assert!(
            modified
                .message
                .contains("requires a clean fixture checkout")
        );
        git(&root, &["checkout", "--quiet", "--", "tracked"]);
        fs::write(root.join("untracked"), b"new\n").expect("write untracked file");
        assert!(h_integration::qualify_source(&root, &revision, "fixture").is_err());
        fs::remove_file(root.join("untracked")).expect("remove untracked file");
        assert!(h_integration::qualify_source(&root, &"0".repeat(40), "fixture").is_err());
        fs::remove_dir_all(root).expect("remove fixture");
    }

    #[test]
    fn outputs_must_be_fresh_request_relative_and_disjoint() {
        let root = fixture_root("output-admission");
        let request_path = root.join("request.toml");
        let write_request = |text: String| {
            fs::write(&request_path, text).expect("write request");
            h_request::load(&request_path).expect("load request")
        };
        let base = request_text("smp-runtime-stress", 22);

        let request = write_request(base.clone());
        let checked = CheckedOutputRoot::open(&request).unwrap();
        admit_outputs(&request, &checked, &Outputs::of(&request).unwrap())
            .expect("kernel and symbols may share one fresh file");

        let request = write_request(base.replace(
            "loader = \"artifacts/loader.efi\"",
            "loader = \"/tmp/loader.efi\"",
        ));
        let checked = CheckedOutputRoot::open(&request).unwrap();
        assert!(
            admit_outputs(&request, &checked, &Outputs::of(&request).unwrap())
                .unwrap_err()
                .message
                .contains("beneath the request directory")
        );

        let request = write_request(base.replace(
            "init0 = \"artifacts/init0.elf\"",
            "init0 = \"artifacts/hello.elf\"",
        ));
        let checked = CheckedOutputRoot::open(&request).unwrap();
        assert!(admit_outputs(&request, &checked, &Outputs::of(&request).unwrap()).is_err());

        let request = write_request(base.replace(
            "hello = \"artifacts/hello.elf\"",
            "hello = \"media/bootfs.img\"",
        ));
        let checked = CheckedOutputRoot::open(&request).unwrap();
        assert!(admit_outputs(&request, &checked, &Outputs::of(&request).unwrap()).is_err());

        let request = write_request(base.clone());
        fs::create_dir_all(root.join("artifacts")).unwrap();
        fs::write(root.join("artifacts/bootstrap.elf"), b"stale").unwrap();
        let checked = CheckedOutputRoot::open(&request).unwrap();
        assert!(
            admit_outputs(&request, &checked, &Outputs::of(&request).unwrap())
                .unwrap_err()
                .message
                .contains("already exists")
        );
        fs::remove_file(root.join("artifacts/bootstrap.elf")).unwrap();
        fs::write(root.join(BUILD_RECEIPT_FILE), b"hand-filled").unwrap();
        let checked = CheckedOutputRoot::open(&request).unwrap();
        assert!(admit_outputs(&request, &checked, &Outputs::of(&request).unwrap()).is_err());
        fs::remove_dir_all(root).expect("remove fixture");
    }
}
