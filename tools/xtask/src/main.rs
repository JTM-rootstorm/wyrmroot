mod cli;
mod error;
mod metadata;
mod provenance;
mod sha256;
mod tasks;

use std::env;
use std::process::ExitCode;

use cli::{Action, BuildScope, USAGE, dispatch};
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

fn run(arguments: &[String]) -> Result<Option<&'static str>, Failure> {
    match dispatch(arguments)? {
        Action::Help => Ok(Some(USAGE)),
        Action::Build(scope) => {
            let repository = tasks::repository_root()?;
            let manifest = BuildManifest::load(&repository)?;
            let builds_host = matches!(scope, BuildScope::All | BuildScope::Host);
            let loader_profile = if matches!(scope, BuildScope::All | BuildScope::Loader) {
                Some(manifest.validate_loader_build_readiness(&repository)?)
            } else {
                None
            };
            if builds_host {
                manifest.validate_host_build_readiness(&repository)?;
            }
            tasks::run_host_tool_probe(&repository)?;
            let loader_toolchain = if let Some(profile) = &loader_profile {
                Some(tasks::prepare_loader_toolchain(&repository, profile)?)
            } else {
                None
            };
            if builds_host {
                tasks::run_workspace_build(&repository)?;
            }
            if let (Some(profile), Some(toolchain)) = (loader_profile, loader_toolchain) {
                tasks::run_loader_build(&repository, &manifest, &profile, &toolchain)?;
            }
            Ok(None)
        }
        Action::HostTests(filter) => {
            let repository = tasks::repository_root()?;
            BuildManifest::load(&repository)?;
            tasks::run_host_tests(&repository, filter.as_deref())?;
            Ok(None)
        }
        Action::Unavailable(command) => Err(Failure::unavailable(command)),
    }
}
