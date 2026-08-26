mod cli;
mod deep_layout;
mod elf_runtime;
mod error;
mod g3_image;
mod h_integration;
mod h_request;
mod i_b_closure;
mod metadata;
mod provenance;
mod sha256;
mod tasks;
mod toolchain_artifact;
mod wyr1;
mod wyr1_vm;
mod wyr1b;

use std::env;
use std::process::ExitCode;

use cli::{Action, USAGE, dispatch};
use error::Failure;
use metadata::BuildManifest;

fn main() -> ExitCode {
    let arguments: Vec<String> = env::args().skip(1).collect();

    match run(&arguments) {
        Ok(output) => {
            if let Some(output) = output {
                print!("{output}");
            }
            ExitCode::SUCCESS
        }
        Err(failure) => {
            eprintln!("xtask: {}", failure.message);
            ExitCode::from(failure.exit_code())
        }
    }
}

fn run(arguments: &[String]) -> Result<Option<String>, Failure> {
    match dispatch(arguments)? {
        Action::Help => Ok(Some(USAGE.to_owned())),
        Action::Build(scope) => {
            let repository = tasks::repository_root()?;
            let manifest = BuildManifest::load(&repository)?;
            let builds_host = scope.runs_workspace();
            let builds_bootfs = scope.runs_bootfs_package();
            let loader_profile = if scope.runs_loader() {
                Some(manifest.validate_loader_build_readiness(&repository)?)
            } else {
                None
            };
            if builds_host {
                manifest.validate_host_build_readiness(&repository)?;
            }
            tasks::run_host_tool_probe(&repository)?;
            let loader_layout = if loader_profile.is_some() {
                Some(deep_layout::prepare(
                    &repository,
                    manifest.deepwyrm_repository()?,
                    manifest.deepwyrm_revision()?,
                )?)
            } else {
                None
            };
            let loader_toolchain = if let Some(profile) = &loader_profile {
                Some(tasks::prepare_loader_toolchain(
                    &repository,
                    profile,
                    &manifest,
                )?)
            } else {
                None
            };
            if builds_host {
                tasks::run_workspace_build(&repository)?;
            }
            if builds_bootfs {
                tasks::run_bootfs_build(&repository)?;
            }
            if let (Some(profile), Some(toolchain), Some(layout)) =
                (loader_profile, loader_toolchain, loader_layout)
            {
                tasks::run_loader_build(&repository, &manifest, &profile, &toolchain, &layout)?;
            }
            Ok(None)
        }
        Action::HostTests(filter) => {
            let repository = tasks::repository_root()?;
            BuildManifest::load(&repository)?;
            tasks::run_host_tests(&repository, filter.as_deref())?;
            Ok(None)
        }
        Action::BuildG3Image(arguments) => g3_image::build(&arguments).map(Some),
        Action::InspectG3Image(arguments) => g3_image::inspect(&arguments).map(Some),
        Action::BuildHImage(request) => h_integration::build(&request).map(Some),
        Action::InspectHImage(request) => h_integration::inspect(&request).map(Some),
        Action::AuditIB {
            first_request,
            second_request,
        } => i_b_closure::audit(&first_request, &second_request).map(Some),
        Action::RunH { profile, request } => h_integration::run(profile, &request).map(Some),
        Action::GdbH { profile, request } => h_integration::gdb(profile, &request).map(Some),
        Action::IntegrationH { profile, request } => {
            h_integration::integration(profile, &request).map(Some)
        }
        Action::Wyr1Image(request) => wyr1_image(&request).map(Some),
        Action::Wyr1Inspect(request) => wyr1_inspect(&request).map(Some),
        Action::Wyr1Prepare(request) => wyr1_prepare(&request).map(Some),
        Action::Wyr1Evidence {
            request,
            default,
            smp,
        } => wyr1_evidence(&request, &default, &smp).map(Some),
        Action::Wyr1BImage(request) => wyr1b::build(std::path::Path::new(&request)).map(Some),
        Action::Wyr1BInspect(request) => wyr1b::inspect(std::path::Path::new(&request)).map(Some),
        Action::Wyr1BEvidence { request, log } => {
            wyr1b::evidence(std::path::Path::new(&request), std::path::Path::new(&log)).map(Some)
        }
        Action::Unavailable(command) => Err(Failure::unavailable(command)),
    }
}

fn wyr1_prepare(path: &str) -> Result<String, Failure> {
    let request = wyr1::load(std::path::Path::new(path))?;
    wyr1::verify_receipt(&request, wyr1::Profile::Default)?;
    let bundles = wyr1_vm::prepare(&request)?;
    Ok(format!(
        "WYR1_VM_HANDOFF_READY default={} smp={} shared_esp_sha256={}\n",
        bundles.default.display(),
        bundles.smp.display(),
        bundles.esp_sha256
    ))
}

fn wyr1_image(path: &str) -> Result<String, Failure> {
    let request = wyr1::load(std::path::Path::new(path))?;
    let identities = wyr1::build_bootfs(&request)?;
    let arguments = cli::G3ImageArguments {
        image: request.esp.display().to_string(),
        loader: request.loader.display().to_string(),
        kernel: request.kernel.display().to_string(),
        bootstrap: request.bootstrap.display().to_string(),
        bootfs: request.bootfs.display().to_string(),
    };
    let _ = g3_image::build(&arguments)?;
    let esp_sha256 = sha256::file_digest(&request.esp)
        .map_err(|error| Failure::task(format!("could not hash WYR1 ESP: {error}")))?;
    let receipt = wyr1::receipt_text(&request, &identities, &esp_sha256, wyr1::Profile::Default)?;
    wyr1::write_receipt(&request, &receipt)?;
    Ok(format!(
        "WYR1_IMAGE_PASS bootfs_sha256={} esp_sha256={esp_sha256}\n",
        identities.bootfs_observed
    ))
}

fn wyr1_inspect(path: &str) -> Result<String, Failure> {
    let request = wyr1::load(std::path::Path::new(path))?;
    let receipt_identities = wyr1::verify_receipt(&request, wyr1::Profile::Default)?;
    let bootfs = std::fs::read(&request.bootfs)
        .map_err(|error| Failure::task(format!("could not read WYR1 bootfs: {error}")))?;
    let archive = wyrmroot_bootfs::archive::Archive::new(&bootfs)
        .map_err(|error| Failure::task(format!("WYR1 bootfs inspection failed: {error:?}")))?;
    for (path, artifact) in request.artifact_paths() {
        let entry = archive
            .lookup(path.as_bytes())
            .map_err(|error| Failure::task(format!("WYR1 bootfs is missing {path}: {error:?}")))?;
        let expected = std::fs::read(artifact).map_err(|error| {
            Failure::task(format!("could not read WYR1 artifact {path}: {error}"))
        })?;
        let expected_executable = path != "system/bootstrap/rrc-a-v1";
        if entry.data() != expected || entry.is_executable() != expected_executable {
            return Err(Failure::task(format!(
                "WYR1 bootfs artifact substitution or mode mismatch at {path}"
            )));
        }
    }
    let gate_config = wyr1::gate_config_for_request(&request);
    let init = std::fs::read(&request.init)
        .map_err(|error| Failure::task(format!("could not read WYR1 init: {error}")))?;
    let registryd = std::fs::read(&request.registryd)
        .map_err(|error| Failure::task(format!("could not read WYR1 registryd: {error}")))?;
    let devmgr = std::fs::read(&request.devmgr)
        .map_err(|error| Failure::task(format!("could not read WYR1 devmgr: {error}")))?;
    let uart = std::fs::read(&request.uart16550d)
        .map_err(|error| Failure::task(format!("could not read WYR1 uart16550d: {error}")))?;
    let console = std::fs::read(&request.consoled)
        .map_err(|error| Failure::task(format!("could not read WYR1 consoled: {error}")))?;
    let shell = std::fs::read(&request.wyrmsh)
        .map_err(|error| Failure::task(format!("could not read WYR1 wyrmsh: {error}")))?;
    let manifest = std::fs::read(&request.rrc_manifest)
        .map_err(|error| Failure::task(format!("could not read WYR1 manifest: {error}")))?;
    let expected = wyr1::decode_request_identity(&request)?;
    let manifest_digest = wyr1::sha256_bytes(&manifest);
    let bootfs_digest = wyr1::sha256_bytes(&bootfs);
    let role_hashes = [
        wyr1::sha256_bytes(&registryd),
        wyr1::sha256_bytes(&devmgr),
        wyr1::sha256_bytes(&uart),
        wyr1::sha256_bytes(&console),
        wyr1::sha256_bytes(&shell),
    ];
    let expected_closure = wyr1::expected_closure_for_request(
        wyr1::sha256_bytes(&init),
        role_hashes,
        wyr1::sha256_bytes(&gate_config),
    );
    let observed_materials = wyr1::observe_closure_from_archive(&bootfs)?;
    let observed_manifest_digest = archive
        .lookup(b"system/bootstrap/rrc-a-v1")
        .map(|entry| wyr1::sha256_bytes(entry.data()))
        .map_err(|error| Failure::task(format!("WYR1 observed manifest is missing: {error:?}")))?;
    let observed_bootfs_digest = wyr1::sha256_bytes(&bootfs);
    let profile = wyr1::product_profile_for_request(
        wyr1::decode_digest(&receipt_identities.manifest_expected)?,
        observed_manifest_digest,
        wyr1::decode_digest(&receipt_identities.bootfs_expected)?,
        observed_bootfs_digest,
        &expected_closure,
        &observed_materials,
    );
    wyr1::validate_product(
        &expected,
        &manifest,
        manifest_digest,
        &bootfs,
        bootfs_digest,
        &gate_config,
        [&init, &registryd, &devmgr, &uart, &console, &shell],
        profile,
    )?;
    if archive.entries().count() != 8 {
        return Err(Failure::task("WYR1 bootfs contains an undeclared entry"));
    }
    Ok(format!(
        "WYR1_INSPECTION_PASS bootfs_sha256={} entries=8\n",
        sha256::bytes_digest(&bootfs)
    ))
}

fn wyr1_evidence(
    request_path: &str,
    default_path: &str,
    smp_path: &str,
) -> Result<String, Failure> {
    let request = wyr1::load(std::path::Path::new(request_path))?;
    let default = std::fs::read(default_path)
        .map_err(|error| Failure::task(format!("could not read default WYR1 evidence: {error}")))
        .and_then(|bytes| wyr1::parse_evidence(&bytes, request.evidence_nonce, request.scenario));
    let smp = std::fs::read(smp_path)
        .map_err(|error| Failure::task(format!("could not read SMP WYR1 evidence: {error}")))
        .and_then(|bytes| wyr1::parse_evidence(&bytes, request.evidence_nonce, request.scenario));
    let (default, smp) = wyr1::join_profiles(default, smp)?;
    Ok(format!(
        "WYR1_PAIRED_PASS default_records={} smp_records={} terminal={}\n",
        default.records.len(),
        smp.records.len(),
        default.terminal.name()
    ))
}
