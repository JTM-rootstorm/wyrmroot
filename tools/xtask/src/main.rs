mod abi_pairing;
mod cli;
mod deep_layout;
mod dev_boot;
mod elf_runtime;
mod error;
mod g3_image;
mod gate;
mod metadata;
mod product;
mod product_engine;
mod secure_fs;
mod sha256;
mod tasks;
mod toolchain_artifact;

use std::env;
use std::path::PathBuf;
use std::process::ExitCode;

use cli::{Action, dispatch};
use error::Failure;

fn main() -> ExitCode {
    let arguments: Vec<String> = env::args().skip(1).collect();
    match run(&arguments) {
        Ok(Some(output)) => {
            print!("{output}");
            ExitCode::SUCCESS
        }
        Ok(None) => ExitCode::SUCCESS,
        Err(failure) => {
            eprintln!("xtask: {}", failure.message);
            ExitCode::from(failure.exit_code())
        }
    }
}

fn run(arguments: &[String]) -> Result<Option<String>, Failure> {
    match dispatch(arguments)? {
        Action::DevBoot {
            check,
            smp,
            deep_repository,
        } => dev_boot::run(&dev_boot::DevBoot {
            check,
            smp,
            deep_repository,
        })
        .map(Some),
        Action::Product {
            output,
            deep_repository,
        } => {
            let deep = match deep_repository {
                Some(path) => PathBuf::from(path),
                None => {
                    let repository = tasks::repository_root()?;
                    tasks::canonical_project_root(&repository)?.join("deepwyrm")
                }
            };
            product::build(&PathBuf::from(&output), &deep)?;
            Ok(Some(format!("PRODUCT_BUILT output={output}\n")))
        }
        Action::Test(scope) => gate::run(scope).map(|()| None),
    }
}
