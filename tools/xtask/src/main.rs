mod cli;
mod deep_layout;
mod elf_runtime;
mod error;
mod g3_image;
mod metadata;
mod provenance;
mod sha256;
mod tasks;
mod toolchain_artifact;

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
        Action::Unavailable(command) => Err(Failure::unavailable(command)),
    }
}
