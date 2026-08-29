//! Selector-free WYR1-C2 product binding.
//!
//! All frozen-product access is rooted in retained directory descriptors. C2
//! receipts are witnesses to a validated byte snapshot, never its authority.

use std::{
    collections::{BTreeMap, BTreeSet},
    env,
    ffi::{OsStr, OsString},
    fs::{self, File, Permissions},
    os::unix::fs::PermissionsExt,
    path::{Component, Path, PathBuf},
    process::{Command, Stdio},
    time::{SystemTime, UNIX_EPOCH},
};

use crate::{
    error::Failure,
    secure_fs::{Directory, ScratchDirectory},
    sha256, wyr1c,
};
use wyrmroot_device_proto::manifest::{
    ContentIdentity, HEADER_BYTES, RECORD_BYTES, encode_com2_manifest,
};

const REQUEST_KIND: &str = "wyrmroot-wyr1-c2-unselected-request";
const BASE_RECEIPT_KIND: &str = "wyrmroot-wyr1-c2-unselected-base-receipt";
const IMAGE_RECEIPT_KIND: &str = "wyrmroot-wyr1-c2-unselected-image-receipt";
const PROVENANCE_KIND: &str = "wyrmroot-wyr1-c2-production-provenance";
const SOURCE_NAME: &str = "q35-com2-role.toml";
const WRDM_NAME: &str = "wrdm-c2-v1.bin";
const CONFIG_NAME: &str = "inspection-policy.toml";
const REQUEST_NAME: &str = "wyr1-c2-request.toml";
const RECEIPT_NAME: &str = "c2-receipt.toml";
const IMAGE_RECEIPT_NAME: &str = "c2-image-receipt.toml";
const NATIVE_TARGET: &str = "x86_64-unknown-wyrmroot";
const KERNEL_TARGET: &str = "x86_64-unknown-none";
const MAX_BYTES: u64 = 64 * 1024 * 1024;
const MAX_REPORT_BYTES: u64 = 64 * 1024;
const GENERATED_ABI_REVISION: &str = "cfc69bd8a49819ce1cda1a132cf56e55c93f92e4";
const ACCEPTED_ABI_TREE: &str = "1c6a74f130e386eee95b3780c75950beefd0037d";
const LOADER_COMMAND: &str = "deterministic-release-uefi";
const KERNEL_COMMAND: &str = "tools/pinned-cargo target build --locked --offline --release --target x86_64-unknown-none --package deepwyrm-kernel --bin deepwyrm-kernel";
const BOOTSTRAP_COMMAND: &str = "accepted-cargo native bootstrap";
const SOURCE: &[u8] = include_bytes!("../../../products/wyr1c/q35-com2-role.toml");
const OBSERVATION: &str = concat!(
    "schema = 1\n",
    "selector = \"none\"\n",
    "evidence = \"not-produced\"\n",
    "allowed = \"CoordinatorOperational,WaitingForRegistry,WaitingForDeviceBundle,Rebind\"\n",
    "forbidden = \"DeviceBound,DriverLaunched,HardwareAccepted\"\n",
);

struct Snapshot {
    request: Vec<u8>,
    request_values: BTreeMap<String, String>,
    c1: wyr1c::FrozenSnapshot,
    loader: Vec<u8>,
    kernel: Vec<u8>,
    bootstrap: Vec<u8>,
    loader_inspection: Vec<u8>,
    provenance: Vec<u8>,
    source: Vec<u8>,
    wrdm: Vec<u8>,
    observation: Vec<u8>,
}

struct OpenedProduct {
    repository: PathBuf,
    deep: PathBuf,
    base: Directory,
    base_mode: u32,
    name: String,
    root: Directory,
    directories: wyr1c::FrozenDirectories,
    request: File,
}

pub(crate) fn freeze(output: &Path) -> Result<String, Failure> {
    reject_ambient()?;
    let (repository, project, deep, base) = project_context()?;
    let wyrm_revision = clean_revision(&repository, "Wyrmroot")?;
    let deep_revision = clean_revision(&deep, "Deepwyrm")?;
    validate_abi_tree(&deep, &deep_revision)?;
    let output_name = direct_output_name(output, base.path())?;
    let base_mode = base.owned_container_mode("C2 output base")?;
    if base.exists(&output_name, "C2 output")? {
        return Err(Failure::task("C2 output must be a fresh nonexistent path"));
    }
    let root = base.create_child(&output_name, 0o700, "C2 output")?;
    let mut c1 = wyr1c::build_into(&root)?;
    if c1.validated.wyrmroot_revision != wyrm_revision {
        return Err(Failure::task(
            "C2 C1 product revision changed during freeze",
        ));
    }

    let manifest = crate::metadata::BuildManifest::load(&repository)?;
    let profile = manifest.validate_loader_build_readiness(&repository)?;
    let layout = crate::deep_layout::prepare(
        &repository,
        manifest.deepwyrm_repository()?,
        manifest.deepwyrm_revision()?,
    )?;
    let toolchain = crate::tasks::prepare_loader_toolchain(&repository, &profile, &manifest)?;
    let cargo_home = crate::tasks::project_cargo_home(&repository, &manifest)?;
    let project_dir = Directory::open_exact(&project, "OS-Project root")?;
    let tmp = open_or_create_tmp(&project_dir, "project temporary root")?;
    let scratch_name = unique_scratch_name()?;
    let scratch = tmp.create_scratch(&scratch_name, "WYR1-C2 build scratch")?;
    let repository_dir = Directory::open_exact(&repository, "Wyrmroot source")?;
    let repository_tmp = open_or_create_tmp(&repository_dir, "Wyrmroot temporary root")?;
    let deep_dir = Directory::open_exact(&deep, "Deepwyrm source")?;
    let deep_tmp = open_or_create_tmp(&deep_dir, "Deepwyrm temporary root")?;
    let build_result = (|| {
        let (loader, loader_inspection) =
            scratch.with_inheritable_anchor("WYR1-C2 UEFI build scratch", |scratch| {
                let build = scratch.path();
                let uefi = crate::tasks::build_deterministic_uefi_pair_in_scratch(
                    &repository,
                    &toolchain,
                    &profile,
                    &layout,
                    &crate::tasks::IsolatedUefiBuild {
                        cargo_home: &cargo_home,
                        production_target: &build.join("uefi-release"),
                        retained_debug_target: &build.join("uefi-debug"),
                        cargo_profile: crate::tasks::UefiCargoProfile::Release,
                    },
                    scratch,
                )?;
                Ok((uefi.loader_bytes, uefi.inspection_report.into_bytes()))
            })?;
        let bootstrap_target = repository_tmp.create_scratch(
            &format!("{scratch_name}-bootstrap"),
            "WYR1-C2 bootstrap target",
        )?;
        let bootstrap_result = build_bootstrap(
            &repository,
            &cargo_home,
            toolchain.accepted(),
            &bootstrap_target,
        );
        let bootstrap = bootstrap_target.finish(bootstrap_result)?;
        let kernel_target =
            deep_tmp.create_scratch(&format!("{scratch_name}-kernel"), "WYR1-C2 kernel target")?;
        let kernel_result = build_kernel(&deep, &kernel_target);
        let kernel = kernel_target.finish(kernel_result)?;
        Ok::<_, Failure>((loader, loader_inspection, bootstrap, kernel))
    })();
    let (loader, loader_inspection, bootstrap, kernel) = scratch.finish(build_result)?;
    if loader_inspection.is_empty() || loader_inspection.len() as u64 > MAX_REPORT_BYTES {
        return Err(Failure::task("C2 loader inspection exceeds its bound"));
    }

    let artifacts = &c1.publication.directories.artifacts;
    let inspections = &c1.publication.directories.inspections;
    let product = &c1.publication.directories.product;
    artifacts.write_new("loader.efi", &loader, 0o400, "C2 loader")?;
    artifacts.write_new("bootstrap.elf", &bootstrap, 0o400, "C2 bootstrap")?;
    artifacts.write_new("deepwyrm.elf", &kernel, 0o400, "C2 kernel")?;
    inspections.write_new(
        "loader-c2.json",
        &loader_inspection,
        0o400,
        "C2 loader inspection",
    )?;
    let provenance = render_provenance(&wyrm_revision, &deep_revision);
    artifacts.write_new(
        "provenance.toml",
        provenance.as_bytes(),
        0o400,
        "C2 provenance",
    )?;
    let uart_digest = sha256::bytes_digest(
        c1.snapshot
            .artifacts
            .get("uart16550d")
            .ok_or_else(|| Failure::task("C2 C1 snapshot lacks uart16550d"))?,
    );
    let compiled = compile_source(SOURCE, decode_digest(&uart_digest)?)?;
    if compiled != c1.snapshot.device_manifest {
        return Err(Failure::task(
            "C2 compiler output disagrees with frozen C1 WRDM",
        ));
    }
    product.write_new(SOURCE_NAME, SOURCE, 0o400, "C2 reviewed source")?;
    product.write_new(WRDM_NAME, &compiled, 0o400, "C2 WRDM")?;
    product.write_new(
        CONFIG_NAME,
        OBSERVATION.as_bytes(),
        0o400,
        "C2 observation policy",
    )?;

    let fields = request_fields(RequestMaterials {
        c1: &c1.snapshot,
        loader: &loader,
        kernel: &kernel,
        bootstrap: &bootstrap,
        loader_inspection: &loader_inspection,
        provenance: provenance.as_bytes(),
        wyrm_revision: &wyrm_revision,
        deep_revision: &deep_revision,
    });
    let request = render(REQUEST_KIND, &fields);
    let mut request_file =
        root.write_new_retained(REQUEST_NAME, request.as_bytes(), 0o400, "C2 request")?;
    let base_receipt = render_base_receipt(request.as_bytes(), &fields);
    root.write_new(
        RECEIPT_NAME,
        base_receipt.as_bytes(),
        0o400,
        "C2 base receipt",
    )?;

    validate_root(
        &repository,
        &deep,
        &root,
        &c1.publication.directories,
        &mut request_file,
    )?;
    verify_clean_revision(&repository, "Wyrmroot", &wyrm_revision)?;
    verify_clean_revision(&deep, "Deepwyrm", &deep_revision)?;
    toolchain.accepted().verify_unchanged()?;
    c1.verify_published_contents(&root)?;
    verify_request_publication(
        (&base, base_mode),
        &output_name,
        &root,
        &c1.publication.directories,
        &mut request_file,
        request.as_bytes(),
        &output.join(REQUEST_NAME),
    )?;
    Ok(format!(
        "WYR1_C2_FREEZE_PASS selector=none evidence=not-produced request={}\n",
        output.join(REQUEST_NAME).display()
    ))
}

pub(crate) fn image(request: &Path) -> Result<String, Failure> {
    let mut opened = open_request_root(request)?;
    let initial = validate_root(
        &opened.repository,
        &opened.deep,
        &opened.root,
        &opened.directories,
        &mut opened.request,
    )?;
    let initial_request = initial.request.clone();
    let product = &opened.directories.product;
    if product.exists("esp.img", "C2 ESP")?
        || opened.root.exists(IMAGE_RECEIPT_NAME, "C2 image receipt")?
    {
        return Err(Failure::task("C2 ESP and image receipt must both be fresh"));
    }
    let mut image = product.create_file("esp.img", 0o600, "C2 ESP")?;
    let report = crate::g3_image::build_open(
        &mut image,
        &initial.loader,
        &initial.kernel,
        &initial.bootstrap,
        &initial.c1.bootfs,
    )?;
    image
        .set_permissions(Permissions::from_mode(0o400))
        .map_err(|error| Failure::task(format!("could not seal C2 ESP: {error}")))?;
    product.verify_file("esp.img", &image, "C2 ESP")?;
    let fields = canonical_request_fields(&initial)?;
    let receipt = render_image_receipt(&initial.request, &fields, &report);
    opened.root.write_new(
        IMAGE_RECEIPT_NAME,
        receipt.as_bytes(),
        0o400,
        "C2 image receipt",
    )?;
    let final_snapshot = validate_root(
        &opened.repository,
        &opened.deep,
        &opened.root,
        &opened.directories,
        &mut opened.request,
    )?;
    if final_snapshot.request != initial_request {
        return Err(Failure::task(
            "C2 request changed while constructing the ESP",
        ));
    }
    verify_request_publication(
        (&opened.base, opened.base_mode),
        &opened.name,
        &opened.root,
        &opened.directories,
        &mut opened.request,
        &initial_request,
        request,
    )?;
    Ok(format!(
        "WYR1_C2_IMAGE_PASS selector=none evidence=not-produced esp={}\n",
        opened.root.path().join("product/esp.img").display()
    ))
}

pub(crate) fn inspect(request: &Path) -> Result<String, Failure> {
    let mut opened = open_request_root(request)?;
    let snapshot = validate_root(
        &opened.repository,
        &opened.deep,
        &opened.root,
        &opened.directories,
        &mut opened.request,
    )?;
    verify_request_publication(
        (&opened.base, opened.base_mode),
        &opened.name,
        &opened.root,
        &opened.directories,
        &mut opened.request,
        &snapshot.request,
        request,
    )?;
    Ok(format!(
        "WYR1_C2_INSPECTION_PASS selector=none evidence=not-produced request_sha256={}\n",
        sha256::bytes_digest(&snapshot.request)
    ))
}

fn validate_root(
    repository: &Path,
    deep: &Path,
    root: &Directory,
    directories: &wyr1c::FrozenDirectories,
    request: &mut File,
) -> Result<Snapshot, Failure> {
    let artifacts = &directories.artifacts;
    let inspections = &directories.inspections;
    let product = &directories.product;
    let snapshot = Snapshot {
        request: root.read_retained_exact(
            REQUEST_NAME,
            request,
            MAX_REPORT_BYTES,
            0o400,
            "C2 request",
        )?,
        request_values: BTreeMap::new(),
        c1: wyr1c::snapshot_from_directories(directories)?,
        loader: artifacts.read("loader.efi", MAX_BYTES, "C2 loader")?,
        kernel: artifacts.read("deepwyrm.elf", MAX_BYTES, "C2 kernel")?,
        bootstrap: artifacts.read("bootstrap.elf", MAX_BYTES, "C2 bootstrap")?,
        loader_inspection: inspections.read(
            "loader-c2.json",
            MAX_REPORT_BYTES,
            "C2 loader inspection",
        )?,
        provenance: artifacts.read("provenance.toml", MAX_REPORT_BYTES, "C2 provenance")?,
        source: product.read(SOURCE_NAME, MAX_REPORT_BYTES, "C2 source")?,
        wrdm: product.read(WRDM_NAME, MAX_REPORT_BYTES, "C2 WRDM")?,
        observation: product.read(CONFIG_NAME, MAX_REPORT_BYTES, "C2 observation")?,
    };
    validate_snapshot(repository, deep, root, product, snapshot)
}

fn validate_snapshot(
    repository: &Path,
    deep: &Path,
    root: &Directory,
    product: &Directory,
    mut snapshot: Snapshot,
) -> Result<Snapshot, Failure> {
    let c1 = wyr1c::validate_frozen_product(repository, &snapshot.c1)?;
    crate::tasks::validate_uefi_inspection_report(&snapshot.loader_inspection, &snapshot.loader)?;
    if snapshot.source != SOURCE {
        return Err(Failure::task(
            "C2 source bytes differ from the reviewed source",
        ));
    }
    if snapshot.observation != OBSERVATION.as_bytes() {
        return Err(Failure::task("C2 observation policy drifted"));
    }
    let uart = snapshot
        .c1
        .artifacts
        .get("uart16550d")
        .ok_or_else(|| Failure::task("C2 C1 snapshot lacks uart16550d"))?;
    if compile_source(
        &snapshot.source,
        decode_digest(&sha256::bytes_digest(uart))?,
    )? != snapshot.wrdm
        || snapshot.wrdm != snapshot.c1.device_manifest
    {
        return Err(Failure::task(
            "C2 WRDM is not the reviewed semantic compilation",
        ));
    }
    let provenance = parse_scalars(&snapshot.provenance, "C2 provenance")?;
    let expected_provenance = [
        ("kind", PROVENANCE_KIND),
        ("schema", "1"),
        ("wyrmroot_revision", c1.wyrmroot_revision.as_str()),
        (
            "deepwyrm_revision",
            provenance
                .get("deepwyrm_revision")
                .map(String::as_str)
                .unwrap_or(""),
        ),
        ("loader_command", LOADER_COMMAND),
        ("kernel_command", KERNEL_COMMAND),
        ("bootstrap_command", BOOTSTRAP_COMMAND),
    ];
    if provenance.len() != expected_provenance.len()
        || expected_provenance
            .iter()
            .any(|(key, value)| provenance.get(*key).map(String::as_str) != Some(*value))
    {
        return Err(Failure::task("C2 provenance key set or values drifted"));
    }
    let deep_revision = provenance
        .get("deepwyrm_revision")
        .ok_or_else(|| Failure::task("C2 provenance lacks Deepwyrm revision"))?;
    validate_revision(deep_revision, "Deepwyrm")?;
    validate_abi_tree(deep, deep_revision)?;
    let canonical_provenance = render_provenance(&c1.wyrmroot_revision, deep_revision);
    if snapshot.provenance != canonical_provenance.as_bytes() {
        return Err(Failure::task("C2 provenance is not canonical"));
    }
    let fields = request_fields(RequestMaterials {
        c1: &snapshot.c1,
        loader: &snapshot.loader,
        kernel: &snapshot.kernel,
        bootstrap: &snapshot.bootstrap,
        loader_inspection: &snapshot.loader_inspection,
        provenance: &snapshot.provenance,
        wyrm_revision: &c1.wyrmroot_revision,
        deep_revision,
    });
    let request_values = parse_scalars(&snapshot.request, "C2 request")?;
    if snapshot.request != render(REQUEST_KIND, &fields).as_bytes() {
        return Err(Failure::task(
            "C2 request is not the exact canonical binding",
        ));
    }
    snapshot.request_values = request_values;
    let receipt = root.read(RECEIPT_NAME, MAX_REPORT_BYTES, "C2 base receipt")?;
    if receipt != render_base_receipt(&snapshot.request, &fields).as_bytes() {
        return Err(Failure::task(
            "C2 base receipt is not the canonical request witness",
        ));
    }

    let image_exists = product.exists("esp.img", "C2 ESP")?;
    let receipt_exists = root.exists(IMAGE_RECEIPT_NAME, "C2 image receipt")?;
    require_image_pair(image_exists, receipt_exists)?;
    if image_exists {
        let mut image =
            product.open_exact_file("esp.img", crate::g3_image::IMAGE_BYTES, "C2 ESP")?;
        let report = crate::g3_image::inspect_open(
            &mut image,
            &snapshot.loader,
            &snapshot.kernel,
            &snapshot.bootstrap,
            &snapshot.c1.bootfs,
        )?;
        product.verify_file("esp.img", &image, "C2 ESP")?;
        let image_receipt = root.read(IMAGE_RECEIPT_NAME, MAX_REPORT_BYTES, "C2 image receipt")?;
        if image_receipt != render_image_receipt(&snapshot.request, &fields, &report).as_bytes() {
            return Err(Failure::task(
                "C2 image receipt is not the canonical ESP witness",
            ));
        }
    }
    Ok(snapshot)
}

fn require_image_pair(image: bool, receipt: bool) -> Result<(), Failure> {
    if image != receipt {
        Err(Failure::task(
            "C2 ESP and image receipt presence is inconsistent",
        ))
    } else {
        Ok(())
    }
}

struct RequestMaterials<'a> {
    c1: &'a wyr1c::FrozenSnapshot,
    loader: &'a [u8],
    kernel: &'a [u8],
    bootstrap: &'a [u8],
    loader_inspection: &'a [u8],
    provenance: &'a [u8],
    wyrm_revision: &'a str,
    deep_revision: &'a str,
}

fn request_fields(materials: RequestMaterials<'_>) -> Vec<(&'static str, String)> {
    let c1 = materials.c1;
    let artifact =
        |name: &str| sha256::bytes_digest(c1.artifacts.get(name).expect("validated C1 artifact"));
    vec![
        ("output", ".".to_owned()),
        ("source_path", format!("product/{SOURCE_NAME}")),
        ("source_sha256", sha256::bytes_digest(SOURCE)),
        ("wrdm_path", format!("product/{WRDM_NAME}")),
        ("wrdm_sha256", sha256::bytes_digest(&c1.device_manifest)),
        ("observation_path", format!("product/{CONFIG_NAME}")),
        (
            "observation_sha256",
            sha256::bytes_digest(OBSERVATION.as_bytes()),
        ),
        ("devmgr_path", "artifacts/devmgr.elf".to_owned()),
        ("devmgr_sha256", artifact("devmgr")),
        (
            "uart16550d_retained_actor_path",
            "artifacts/uart16550d.elf".to_owned(),
        ),
        ("uart16550d_retained_actor_sha256", artifact("uart16550d")),
        ("rrc_manifest_path", "product/rrc-c1-v1.bin".to_owned()),
        (
            "rrc_manifest_sha256",
            sha256::bytes_digest(&c1.rrc_manifest),
        ),
        ("bootfs_path", "product/bootfs.img".to_owned()),
        ("bootfs_sha256", sha256::bytes_digest(&c1.bootfs)),
        ("c1_receipt_path", "product/build-receipt.toml".to_owned()),
        ("c1_receipt_sha256", sha256::bytes_digest(&c1.receipt)),
        ("loader_path", "artifacts/loader.efi".to_owned()),
        ("loader_sha256", sha256::bytes_digest(materials.loader)),
        ("kernel_path", "artifacts/deepwyrm.elf".to_owned()),
        ("kernel_sha256", sha256::bytes_digest(materials.kernel)),
        ("bootstrap_path", "artifacts/bootstrap.elf".to_owned()),
        (
            "bootstrap_sha256",
            sha256::bytes_digest(materials.bootstrap),
        ),
        (
            "loader_inspection_path",
            "inspections/loader-c2.json".to_owned(),
        ),
        (
            "loader_inspection_sha256",
            sha256::bytes_digest(materials.loader_inspection),
        ),
        ("provenance_path", "artifacts/provenance.toml".to_owned()),
        (
            "provenance_sha256",
            sha256::bytes_digest(materials.provenance),
        ),
        ("wyrmroot_revision", materials.wyrm_revision.to_owned()),
        ("deepwyrm_revision", materials.deep_revision.to_owned()),
        ("generated_abi_revision", GENERATED_ABI_REVISION.to_owned()),
        ("generated_abi_tree", ACCEPTED_ABI_TREE.to_owned()),
        ("loader_command", LOADER_COMMAND.to_owned()),
        ("kernel_command", KERNEL_COMMAND.to_owned()),
        ("bootstrap_command", BOOTSTRAP_COMMAND.to_owned()),
    ]
}

fn canonical_request_fields(snapshot: &Snapshot) -> Result<Vec<(&'static str, String)>, Failure> {
    let wyrm = snapshot
        .request_values
        .get("wyrmroot_revision")
        .ok_or_else(|| Failure::task("C2 request lacks Wyrmroot revision"))?;
    let deep = snapshot
        .request_values
        .get("deepwyrm_revision")
        .ok_or_else(|| Failure::task("C2 request lacks Deepwyrm revision"))?;
    Ok(request_fields(RequestMaterials {
        c1: &snapshot.c1,
        loader: &snapshot.loader,
        kernel: &snapshot.kernel,
        bootstrap: &snapshot.bootstrap,
        loader_inspection: &snapshot.loader_inspection,
        provenance: &snapshot.provenance,
        wyrm_revision: wyrm,
        deep_revision: deep,
    }))
}

fn render(kind: &str, fields: &[(&str, String)]) -> String {
    let mut text = format!(
        "kind = \"{kind}\"\nschema = 1\nselector = \"none\"\nevidence = \"not-produced\"\n"
    );
    for (key, value) in fields {
        text.push_str(&format!("{key} = \"{value}\"\n"));
    }
    text
}

fn render_base_receipt(request: &[u8], fields: &[(&str, String)]) -> String {
    let mut values = vec![("request_sha256", sha256::bytes_digest(request))];
    values.extend(fields.iter().cloned());
    render(BASE_RECEIPT_KIND, &values)
}

fn render_image_receipt(
    request: &[u8],
    fields: &[(&str, String)],
    report: &crate::g3_image::Inspection,
) -> String {
    let mut values = vec![
        ("request_sha256", sha256::bytes_digest(request)),
        ("esp_path", "product/esp.img".to_owned()),
        ("esp_sha256", report.image_sha256.clone()),
        ("image_bytes", crate::g3_image::IMAGE_BYTES.to_string()),
        (
            "g3_report_sha256",
            sha256::bytes_digest(report.render().as_bytes()),
        ),
        ("g3_loader_sha256", report.loader_sha256.clone()),
        ("g3_kernel_sha256", report.kernel_sha256.clone()),
        ("g3_bootstrap_sha256", report.bootstrap_sha256.clone()),
        ("g3_bootfs_sha256", report.bootfs_sha256.clone()),
    ];
    values.extend(fields.iter().cloned());
    render(IMAGE_RECEIPT_KIND, &values)
}

fn render_provenance(wyrm: &str, deep: &str) -> String {
    format!(
        "kind = \"{PROVENANCE_KIND}\"\nschema = 1\nwyrmroot_revision = \"{wyrm}\"\ndeepwyrm_revision = \"{deep}\"\nloader_command = \"{LOADER_COMMAND}\"\nkernel_command = \"{KERNEL_COMMAND}\"\nbootstrap_command = \"{BOOTSTRAP_COMMAND}\"\n"
    )
}

fn parse_scalars(bytes: &[u8], label: &str) -> Result<BTreeMap<String, String>, Failure> {
    let text =
        std::str::from_utf8(bytes).map_err(|_| Failure::task(format!("{label} is not UTF-8")))?;
    if !text.ends_with('\n') || text.contains('\r') {
        return Err(Failure::task(format!("{label} line endings drifted")));
    }
    let mut values = BTreeMap::new();
    for line in text.lines() {
        let (key, raw) = line
            .split_once(" = ")
            .ok_or_else(|| Failure::task(format!("{label} has a malformed line")))?;
        if key.is_empty()
            || !key
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
            || values.contains_key(key)
        {
            return Err(Failure::task(format!(
                "{label} has an invalid or duplicate key"
            )));
        }
        let value = if raw == "1" && key == "schema" {
            raw
        } else if raw.starts_with('"') && raw.ends_with('"') && raw.len() >= 2 {
            let value = &raw[1..raw.len() - 1];
            if value.is_empty() || value.contains(['"', '\\']) {
                return Err(Failure::task(format!("{label} has a malformed string")));
            }
            value
        } else {
            return Err(Failure::task(format!("{label} has a noncanonical scalar")));
        };
        values.insert(key.to_owned(), value.to_owned());
    }
    Ok(values)
}

fn project_context() -> Result<(PathBuf, PathBuf, PathBuf, Directory), Failure> {
    let repository = crate::tasks::repository_root()?;
    let project = repository
        .ancestors()
        .find(|path| path.ends_with("OS-Project"))
        .ok_or_else(|| Failure::task("C2 source is not beneath OS-Project"))?
        .to_path_buf();
    let project = fs::canonicalize(project)
        .map_err(|error| Failure::task(format!("could not resolve OS-Project: {error}")))?;
    let deep = project.join("deepwyrm");
    let _deep_directory = Directory::open_exact(&deep, "Deepwyrm source")?;
    let base_path = project.join("artifacts/wyr1-c");
    let base = Directory::open_exact(&base_path, "C2 output base")?;
    Ok((repository, project, deep, base))
}

fn direct_output_name(output: &Path, base: &Path) -> Result<String, Failure> {
    if !output.is_absolute()
        || output
            .components()
            .any(|part| !matches!(part, Component::RootDir | Component::Normal(_)))
        || output.parent() != Some(base)
    {
        return Err(Failure::task(
            "C2 output must be one canonical direct child of artifacts/wyr1-c",
        ));
    }
    output
        .file_name()
        .and_then(OsStr::to_str)
        .map(str::to_owned)
        .ok_or_else(|| Failure::task("C2 output name is not UTF-8"))
}

fn open_request_root(request: &Path) -> Result<OpenedProduct, Failure> {
    let (repository, _, deep, base) = project_context()?;
    if !request.is_absolute()
        || request.file_name() != Some(OsStr::new(REQUEST_NAME))
        || request
            .components()
            .any(|part| !matches!(part, Component::RootDir | Component::Normal(_)))
    {
        return Err(Failure::task("C2 request path is not canonical"));
    }
    let parent = request
        .parent()
        .ok_or_else(|| Failure::task("C2 request has no product root"))?;
    let name = direct_output_name(parent, base.path())?;
    let base_mode = base.owned_container_mode("C2 output base")?;
    let root = base.open_child(&name, "C2 product root")?;
    let directories = wyr1c::open_frozen_directories(&root)?;
    let mut request_file = root.open_retained_file(REQUEST_NAME, MAX_REPORT_BYTES, "C2 request")?;
    let request_bytes = root.read_retained_exact(
        REQUEST_NAME,
        &mut request_file,
        MAX_REPORT_BYTES,
        0o400,
        "C2 request",
    )?;
    verify_request_publication(
        (&base, base_mode),
        &name,
        &root,
        &directories,
        &mut request_file,
        &request_bytes,
        request,
    )?;
    Ok(OpenedProduct {
        repository,
        deep,
        base,
        base_mode,
        name,
        root,
        directories,
        request: request_file,
    })
}

fn verify_request_publication(
    base: (&Directory, u32),
    name: &str,
    root: &Directory,
    directories: &wyr1c::FrozenDirectories,
    request_file: &mut File,
    expected_request: &[u8],
    request: &Path,
) -> Result<(), Failure> {
    let (base, base_mode) = base;
    base.verify_owned_container_path_mode(base_mode, "C2 output base")?;
    base.verify_child_identity(name, root, 0o700, "C2 product root")?;
    if request != root.path().join(REQUEST_NAME) {
        return Err(Failure::task(
            "C2 request path does not name the retained product generation",
        ));
    }
    wyr1c::verify_published_contents_without_receipt(root, directories)?;
    let actual_request = root.read_retained_exact(
        REQUEST_NAME,
        request_file,
        MAX_REPORT_BYTES,
        0o400,
        "C2 request",
    )?;
    if actual_request != expected_request {
        return Err(Failure::task("C2 retained request bytes changed"));
    }
    Ok(())
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
    Ok(format!("wyr1c2-build-{}-{time}", std::process::id()))
}

fn clean_revision(repository: &Path, label: &str) -> Result<String, Failure> {
    let head = git_output(repository, &["rev-parse", "HEAD"], label)?;
    let revision = std::str::from_utf8(&head)
        .map(str::trim)
        .map(str::to_owned)
        .map_err(|_| Failure::task(format!("{label} revision is not UTF-8")))?;
    verify_clean_revision(repository, label, &revision)?;
    Ok(revision)
}

fn verify_clean_revision(repository: &Path, label: &str, expected: &str) -> Result<(), Failure> {
    let head = git_output(repository, &["rev-parse", "HEAD"], label)?;
    let status = git_output(
        repository,
        &["status", "--porcelain=v1", "--untracked-files=all"],
        label,
    )?;
    if !status.is_empty() || std::str::from_utf8(&head).ok().map(str::trim) != Some(expected) {
        return Err(Failure::task(format!(
            "C2 requires the captured clean {label} revision"
        )));
    }
    Ok(())
}

fn git_output(repository: &Path, args: &[&str], label: &str) -> Result<Vec<u8>, Failure> {
    let output = Command::new("git")
        .arg("-C")
        .arg(repository)
        .args(args)
        .output()
        .map_err(|error| Failure::task(format!("could not inspect {label}: {error}")))?;
    if !output.status.success() {
        return Err(Failure::task(format!(
            "could not resolve declared {label} commit"
        )));
    }
    Ok(output.stdout)
}

fn validate_revision(revision: &str, label: &str) -> Result<(), Failure> {
    if revision.len() != 40
        || !revision
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(Failure::task(format!(
            "{label} revision is not a commit ID"
        )));
    }
    Ok(())
}

fn validate_abi_tree(deep: &Path, kernel_revision: &str) -> Result<(), Failure> {
    wyr1c::validate_commit(deep, kernel_revision, "Deepwyrm")?;
    wyr1c::validate_commit(deep, GENERATED_ABI_REVISION, "generated ABI")?;
    let tree = |revision: &str| -> Result<String, Failure> {
        let object = format!("{revision}:abi");
        let bytes = git_output(deep, &["rev-parse", &object], "Deepwyrm ABI tree")?;
        std::str::from_utf8(&bytes)
            .map(str::trim)
            .map(str::to_owned)
            .map_err(|_| Failure::task("C2 ABI tree is not UTF-8"))
    };
    if tree(kernel_revision)? != ACCEPTED_ABI_TREE
        || tree(GENERATED_ABI_REVISION)? != ACCEPTED_ABI_TREE
    {
        return Err(Failure::task(
            "C2 kernel and generated ABI trees are incompatible",
        ));
    }
    Ok(())
}

fn decode_digest(value: &str) -> Result<[u8; 32], Failure> {
    crate::wyr1::decode_digest(value)
}

fn compile_source(source: &[u8], uart: [u8; 32]) -> Result<Vec<u8>, Failure> {
    let policy = parse_policy(source)?;
    if policy.profile != "q35"
        || policy.profile_version != 1
        || policy.role != 1
        || policy.hardware != "com2"
        || policy.resource != "pio-interrupt"
        || policy.pio_base != 760
        || policy.pio_length != 8
        || policy.irq != 3
        || policy.driver != "system/uart16550d"
        || policy.metadata_policy != "serial-console-v1"
    {
        return Err(Failure::task(
            "C2 device policy is not the reviewed q35 COM2 policy",
        ));
    }
    let mut output = [0; HEADER_BYTES + RECORD_BYTES];
    let length = encode_com2_manifest(ContentIdentity(uart), &mut output)
        .map_err(|_| Failure::task("C2 WRDM encoding failed"))?;
    Ok(output[..length].to_vec())
}

struct DevicePolicy<'a> {
    profile: &'a str,
    profile_version: u64,
    role: u64,
    hardware: &'a str,
    resource: &'a str,
    pio_base: u64,
    pio_length: u64,
    irq: u64,
    driver: &'a str,
    metadata_policy: &'a str,
}

fn parse_policy(source: &[u8]) -> Result<DevicePolicy<'_>, Failure> {
    let text = std::str::from_utf8(source).map_err(|_| Failure::task("C2 policy is not UTF-8"))?;
    if !text.starts_with("# Reviewed host policy for the immutable WYR1-C q35 COM2 role.\n")
        || !text.ends_with('\n')
        || text.contains('\r')
    {
        return Err(Failure::task("C2 policy preamble or line endings drifted"));
    }
    let mut values = BTreeMap::new();
    for line in text.lines().skip(1) {
        let (key, raw) = line
            .split_once(" = ")
            .ok_or_else(|| Failure::task("C2 policy line is malformed"))?;
        if !key
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte == b'_')
            || values.insert(key, raw).is_some()
        {
            return Err(Failure::task("C2 policy has a duplicate or invalid key"));
        }
    }
    let keys = [
        "schema",
        "profile",
        "profile_version",
        "role",
        "hardware",
        "resource",
        "pio_base",
        "pio_length",
        "irq",
        "driver",
        "metadata_policy",
    ]
    .into_iter()
    .collect::<BTreeSet<_>>();
    if values.keys().copied().collect::<BTreeSet<_>>() != keys || values.get("schema") != Some(&"1")
    {
        return Err(Failure::task("C2 policy key set or schema drifted"));
    }
    let string = |key| -> Result<&str, Failure> {
        let raw = values
            .get(key)
            .ok_or_else(|| Failure::task("C2 policy lacks a string"))?;
        if raw.starts_with('"')
            && raw.ends_with('"')
            && raw.len() > 2
            && !raw[1..raw.len() - 1].contains(['"', '\\'])
        {
            Ok(&raw[1..raw.len() - 1])
        } else {
            Err(Failure::task("C2 policy string is malformed"))
        }
    };
    let integer = |key| -> Result<u64, Failure> {
        values
            .get(key)
            .ok_or_else(|| Failure::task("C2 policy lacks an integer"))?
            .parse()
            .map_err(|_| Failure::task("C2 policy integer is malformed"))
    };
    Ok(DevicePolicy {
        profile: string("profile")?,
        profile_version: integer("profile_version")?,
        role: integer("role")?,
        hardware: string("hardware")?,
        resource: string("resource")?,
        pio_base: integer("pio_base")?,
        pio_length: integer("pio_length")?,
        irq: integer("irq")?,
        driver: string("driver")?,
        metadata_policy: string("metadata_policy")?,
    })
}

fn build_bootstrap(
    repository: &Path,
    cargo_home: &Path,
    toolchain: &crate::toolchain_artifact::AcceptedToolchain,
    target: &ScratchDirectory<'_>,
) -> Result<Vec<u8>, Failure> {
    target.verify_unchanged()?;
    let status = Command::new(&toolchain.cargo)
        .args([
            "build",
            "--offline",
            "--locked",
            "--release",
            "--target",
            NATIVE_TARGET,
            "--package",
            "wyrmroot-bootstrap",
            "--bin",
            "wyrmroot-bootstrap",
            "--features",
            "native-bootstrap",
            "--target-dir",
        ])
        .arg(target.path())
        .env("RUSTC", &toolchain.rustc)
        .env("CARGO_HOME", cargo_home)
        .env("CARGO_INCREMENTAL", "0")
        .env("CARGO_NET_OFFLINE", "true")
        .env("SOURCE_DATE_EPOCH", "0")
        .env_remove("LD_AUDIT")
        .env_remove("LD_LIBRARY_PATH")
        .env_remove("LD_PRELOAD")
        .current_dir(repository)
        .stdin(Stdio::null())
        .status();
    target.verify_unchanged()?;
    let status =
        status.map_err(|error| Failure::task(format!("could not build C2 bootstrap: {error}")))?;
    if !status.success() {
        return Err(Failure::task("C2 bootstrap build failed"));
    }
    let artifact = target.read_producer(
        &PathBuf::from(NATIVE_TARGET).join("release/wyrmroot-bootstrap"),
        MAX_BYTES,
        "bootstrap",
    )?;
    target.verify_unchanged()?;
    Ok(artifact)
}

fn build_kernel(deep: &Path, target: &ScratchDirectory<'_>) -> Result<Vec<u8>, Failure> {
    target.verify_unchanged()?;
    let status = Command::new(deep.join("tools/pinned-cargo"))
        .args([
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
        ])
        .env("DEEPWYRM_PINNED_TARGET_DIR", target.path())
        .env_remove("CARGO_HOME")
        .env_remove("DEEPWYRM_GUEST_TEST_SELECTOR")
        .env_remove("DEEPWYRM_GUEST_TEST_ID")
        .env_remove("LD_AUDIT")
        .env_remove("LD_LIBRARY_PATH")
        .env_remove("LD_PRELOAD")
        .current_dir(deep)
        .stdin(Stdio::null())
        .status();
    target.verify_unchanged()?;
    let status = status
        .map_err(|error| Failure::task(format!("could not build C2 production kernel: {error}")))?;
    if !status.success() {
        return Err(Failure::task("C2 production kernel build failed"));
    }
    let artifact = target.read_producer(
        &PathBuf::from(KERNEL_TARGET).join("release/deepwyrm-kernel"),
        MAX_BYTES,
        "kernel",
    )?;
    target.verify_unchanged()?;
    Ok(artifact)
}

fn reject_ambient() -> Result<(), Failure> {
    let variables = env::vars_os().collect::<BTreeMap<OsString, OsString>>();
    for name in [
        "DEEPWYRM_GUEST_TEST_SELECTOR",
        "DEEPWYRM_GUEST_TEST_ID",
        "DEEPWYRM_WYR1B_EVIDENCE_NONCE",
        "DEEPWYRM_WYR1_EVIDENCE_NONCE",
        "DEEPWYRM_WYR1_EVIDENCE_SCENARIO",
        "CARGO_TARGET_DIR",
        "RUSTC",
        "RUSTFLAGS",
    ] {
        if variables.contains_key(OsStr::new(name)) {
            return Err(Failure::task(format!("C2 freeze refuses ambient {name}")));
        }
    }
    if variables
        .keys()
        .any(|key| key.as_encoded_bytes().starts_with(b"CARGO_TARGET_"))
    {
        return Err(Failure::task("C2 freeze refuses ambient CARGO_TARGET_*"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{MetadataExt, symlink};

    fn publication_fixture(
        label: &str,
    ) -> (
        PathBuf,
        Directory,
        u32,
        Directory,
        wyr1c::FrozenDirectories,
        File,
        Vec<u8>,
    ) {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock precedes Unix epoch")
            .as_nanos();
        let parent = std::env::temp_dir().join(format!(
            "wyrmroot-c2-publication-{label}-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir(&parent).expect("create publication parent");
        fs::set_permissions(&parent, Permissions::from_mode(0o755))
            .expect("set publication parent mode");
        let base = Directory::open_exact(&parent, "publication parent").unwrap();
        let base_mode = base.owned_container_mode("publication parent").unwrap();
        let root = base
            .create_child("generation", 0o700, "generation")
            .unwrap();
        let directories = wyr1c::FrozenDirectories {
            artifacts: root.create_child("artifacts", 0o700, "artifacts").unwrap(),
            inspections: root
                .create_child("inspections", 0o700, "inspections")
                .unwrap(),
            product: root.create_child("product", 0o700, "product").unwrap(),
        };
        let request_bytes = b"bound request\n".to_vec();
        let request = root
            .write_new_retained(REQUEST_NAME, &request_bytes, 0o400, "request")
            .unwrap();
        (
            parent,
            base,
            base_mode,
            root,
            directories,
            request,
            request_bytes,
        )
    }

    #[test]
    fn reviewed_source_requires_byte_identity_and_semantic_identity() {
        let compiled = compile_source(SOURCE, [7; 32]).unwrap();
        assert_eq!(compiled, compile_source(SOURCE, [7; 32]).unwrap());
        let mut changed = SOURCE.to_vec();
        changed.extend_from_slice(b"# harmless-looking drift\n");
        assert!(compile_source(&changed, [7; 32]).is_err());
    }

    #[test]
    fn canonical_request_and_receipts_round_trip() {
        let fields = vec![
            ("output", ".".to_owned()),
            ("source_sha256", "00".repeat(32)),
        ];
        let request = render(REQUEST_KIND, &fields);
        assert_eq!(
            parse_scalars(request.as_bytes(), "request").unwrap()["kind"],
            REQUEST_KIND
        );
        let receipt = render_base_receipt(request.as_bytes(), &fields);
        assert_eq!(
            parse_scalars(receipt.as_bytes(), "receipt").unwrap()["kind"],
            BASE_RECEIPT_KIND
        );
        let report = crate::g3_image::Inspection {
            image_sha256: "11".repeat(32),
            loader_sha256: "22".repeat(32),
            kernel_sha256: "33".repeat(32),
            bootstrap_sha256: "44".repeat(32),
            bootfs_sha256: "55".repeat(32),
        };
        let image = render_image_receipt(request.as_bytes(), &fields, &report);
        assert_eq!(
            parse_scalars(image.as_bytes(), "image receipt").unwrap()["kind"],
            IMAGE_RECEIPT_KIND
        );
    }

    #[test]
    fn scalar_parser_rejects_duplicate_noncanonical_and_test_fields() {
        assert!(parse_scalars(b"a = \"x\"\na = \"y\"\n", "test").is_err());
        assert!(parse_scalars(b"a = x\n", "test").is_err());
        assert!(parse_scalars(b"a = \"x\"\r\n", "test").is_err());
        assert!(parse_scalars(b"test-id = \"29\"\n", "test").is_err());
    }

    #[test]
    fn esp_and_image_receipt_are_an_inseparable_pair() {
        assert!(require_image_pair(false, false).is_ok());
        assert!(require_image_pair(true, true).is_ok());
        assert!(require_image_pair(true, false).is_err());
        assert!(require_image_pair(false, true).is_err());
    }

    #[test]
    fn canonical_build_targets_are_private_direct_children_and_detect_replacement() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock precedes Unix epoch")
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "wyrmroot-c2-canonical-target-{}-{nonce}",
            std::process::id()
        ));
        let deep = root.join("deepwyrm");
        let outside = root.join("outside");
        fs::create_dir_all(&deep).expect("create synthetic Deepwyrm root");
        fs::create_dir(deep.join(".tmp")).expect("create shared temporary container");
        fs::set_permissions(deep.join(".tmp"), Permissions::from_mode(0o755))
            .expect("set shared temporary container mode");
        fs::create_dir(&outside).expect("create outside directory");
        let deep_dir = Directory::open_exact(&deep, "synthetic Deepwyrm").unwrap();
        let tmp = open_or_create_tmp(&deep_dir, "synthetic Deepwyrm temporary root").unwrap();
        let target = tmp.create_scratch("c2-kernel", "C2 kernel target").unwrap();
        assert_eq!(target.path(), deep.join(".tmp/c2-kernel"));
        assert_eq!(
            fs::symlink_metadata(target.path()).unwrap().mode() & 0o7777,
            0o700
        );
        target.verify_unchanged().unwrap();
        fs::set_permissions(target.path(), Permissions::from_mode(0o755))
            .expect("weaken task target mode");
        assert!(target.verify_unchanged().is_err());
        fs::set_permissions(target.path(), Permissions::from_mode(0o700))
            .expect("restore task target mode");
        target.verify_unchanged().unwrap();

        let moved = deep.join(".tmp/moved-kernel");
        fs::rename(target.path(), &moved).unwrap();
        symlink(&outside, target.path()).unwrap();
        assert!(target.verify_unchanged().is_err());
        drop(target);
        fs::remove_dir_all(root).expect("remove synthetic Deepwyrm root");
    }

    #[test]
    fn canonical_build_target_detects_temporary_parent_replacement() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock precedes Unix epoch")
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "wyrmroot-c2-target-parent-{}-{nonce}",
            std::process::id()
        ));
        let deep = root.join("deepwyrm");
        let outside = root.join("outside");
        fs::create_dir_all(&deep).expect("create synthetic Deepwyrm root");
        fs::create_dir(&outside).expect("create outside directory");
        let deep_dir = Directory::open_exact(&deep, "synthetic Deepwyrm").unwrap();
        let tmp = open_or_create_tmp(&deep_dir, "synthetic Deepwyrm temporary root").unwrap();
        let target = tmp.create_scratch("c2-kernel", "C2 kernel target").unwrap();
        let moved_tmp = deep.join(".tmp-moved");
        fs::rename(deep.join(".tmp"), &moved_tmp).unwrap();
        symlink(&outside, deep.join(".tmp")).unwrap();
        assert!(target.verify_unchanged().is_err());
        drop(target);
        fs::remove_dir_all(root).expect("remove synthetic Deepwyrm root");
    }

    #[test]
    fn temporary_container_rejects_writable_and_symlink_paths() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock precedes Unix epoch")
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "wyrmroot-c2-container-policy-{}-{nonce}",
            std::process::id()
        ));
        let writable = root.join("writable");
        let linked = root.join("linked");
        let outside = root.join("outside");
        fs::create_dir_all(writable.join(".tmp")).expect("create writable container");
        fs::set_permissions(writable.join(".tmp"), Permissions::from_mode(0o777))
            .expect("set writable container mode");
        fs::create_dir_all(&linked).expect("create linked parent");
        fs::create_dir(&outside).expect("create outside container");
        symlink(&outside, linked.join(".tmp")).expect("link temporary container");

        let writable = Directory::open_exact(&writable, "writable parent").unwrap();
        assert!(open_or_create_tmp(&writable, "writable temporary root").is_err());
        let linked = Directory::open_exact(&linked, "linked parent").unwrap();
        assert!(open_or_create_tmp(&linked, "linked temporary root").is_err());
        fs::remove_dir_all(root).expect("remove container policy fixture");
    }

    #[test]
    fn published_root_and_returned_request_path_cannot_be_redirected() {
        let (parent, base, base_mode, root, directories, mut request_file, request_bytes) =
            publication_fixture("root");
        let request_path = parent.join("generation").join(REQUEST_NAME);
        verify_request_publication(
            (&base, base_mode),
            "generation",
            &root,
            &directories,
            &mut request_file,
            &request_bytes,
            &request_path,
        )
        .unwrap();
        fs::set_permissions(parent.join("generation"), Permissions::from_mode(0o755)).unwrap();
        assert!(
            verify_request_publication(
                (&base, base_mode),
                "generation",
                &root,
                &directories,
                &mut request_file,
                &request_bytes,
                &request_path,
            )
            .is_err()
        );
        fs::set_permissions(parent.join("generation"), Permissions::from_mode(0o700)).unwrap();
        assert!(
            verify_request_publication(
                (&base, base_mode),
                "generation",
                &root,
                &directories,
                &mut request_file,
                &request_bytes,
                &parent.join("generation/not-the-request.toml"),
            )
            .is_err()
        );
        fs::rename(parent.join("generation"), parent.join("original")).unwrap();
        fs::create_dir(parent.join("generation")).unwrap();
        fs::set_permissions(parent.join("generation"), Permissions::from_mode(0o700)).unwrap();
        assert!(
            verify_request_publication(
                (&base, base_mode),
                "generation",
                &root,
                &directories,
                &mut request_file,
                &request_bytes,
                &request_path,
            )
            .is_err()
        );
        fs::remove_dir_all(parent).expect("remove publication fixture");
    }

    #[test]
    fn published_child_and_request_replacements_are_rejected() {
        let (parent, base, base_mode, root, directories, mut request_file, request_bytes) =
            publication_fixture("child");
        let request_path = parent.join("generation").join(REQUEST_NAME);
        fs::set_permissions(
            parent.join("generation/artifacts"),
            Permissions::from_mode(0o755),
        )
        .unwrap();
        assert!(
            verify_request_publication(
                (&base, base_mode),
                "generation",
                &root,
                &directories,
                &mut request_file,
                &request_bytes,
                &request_path,
            )
            .is_err()
        );
        fs::set_permissions(
            parent.join("generation/artifacts"),
            Permissions::from_mode(0o700),
        )
        .unwrap();
        fs::rename(
            parent.join("generation/artifacts"),
            parent.join("generation/artifacts-original"),
        )
        .unwrap();
        fs::create_dir(parent.join("generation/artifacts")).unwrap();
        fs::set_permissions(
            parent.join("generation/artifacts"),
            Permissions::from_mode(0o700),
        )
        .unwrap();
        assert!(
            verify_request_publication(
                (&base, base_mode),
                "generation",
                &root,
                &directories,
                &mut request_file,
                &request_bytes,
                &request_path,
            )
            .is_err()
        );
        fs::remove_dir_all(parent).expect("remove child replacement fixture");

        let (parent, base, base_mode, root, directories, mut request_file, request_bytes) =
            publication_fixture("request");
        let request_path = parent.join("generation").join(REQUEST_NAME);
        fs::set_permissions(&request_path, Permissions::from_mode(0o600)).unwrap();
        assert!(
            verify_request_publication(
                (&base, base_mode),
                "generation",
                &root,
                &directories,
                &mut request_file,
                &request_bytes,
                &request_path,
            )
            .is_err()
        );
        fs::set_permissions(&request_path, Permissions::from_mode(0o400)).unwrap();
        fs::rename(
            &request_path,
            parent.join("generation/request-original.toml"),
        )
        .unwrap();
        fs::write(&request_path, &request_bytes).unwrap();
        fs::set_permissions(&request_path, Permissions::from_mode(0o400)).unwrap();
        assert!(
            verify_request_publication(
                (&base, base_mode),
                "generation",
                &root,
                &directories,
                &mut request_file,
                &request_bytes,
                &request_path,
            )
            .is_err()
        );
        fs::remove_dir_all(parent).expect("remove request replacement fixture");
    }

    #[test]
    fn published_base_rename_and_replacement_is_rejected() {
        let (parent, base, base_mode, root, directories, mut request_file, request_bytes) =
            publication_fixture("base");
        let request_path = parent.join("generation").join(REQUEST_NAME);
        fs::set_permissions(&parent, Permissions::from_mode(0o700)).unwrap();
        assert!(
            verify_request_publication(
                (&base, base_mode),
                "generation",
                &root,
                &directories,
                &mut request_file,
                &request_bytes,
                &request_path,
            )
            .is_err()
        );
        fs::set_permissions(&parent, Permissions::from_mode(base_mode)).unwrap();
        let moved = parent.with_extension("moved");
        fs::rename(&parent, &moved).unwrap();
        fs::create_dir(&parent).unwrap();
        fs::set_permissions(&parent, Permissions::from_mode(0o755)).unwrap();
        assert!(
            verify_request_publication(
                (&base, base_mode),
                "generation",
                &root,
                &directories,
                &mut request_file,
                &request_bytes,
                &request_path,
            )
            .is_err()
        );
        fs::remove_dir_all(parent).expect("remove replacement base");
        fs::remove_dir_all(moved).expect("remove original base");
    }
}
