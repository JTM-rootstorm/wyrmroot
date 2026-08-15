mod cli;
mod error;
mod metadata;
mod tasks;

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

fn run(arguments: &[String]) -> Result<Option<&'static str>, Failure> {
    match dispatch(arguments)? {
        Action::Help => Ok(Some(USAGE)),
        Action::Build => {
            let repository = tasks::repository_root()?;
            let manifest = BuildManifest::load(&repository)?;
            manifest.validate_build_readiness(&repository)?;
            tasks::run_host_tool_probe(&repository)?;
            tasks::run_workspace_build(&repository)?;
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
