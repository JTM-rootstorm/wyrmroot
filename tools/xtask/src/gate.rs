//! `xtask test`: the host gate.
//!
//! Formatting, warnings-denied Clippy and the workspace tests, and the root
//! Python suites. The roles' default host shape is their production code; the
//! `native-*` features only add the guest binaries. The production natives themselves are compiled by
//! `xtask product` (and so by `dev-boot`), which is the native half of the
//! gate.

use std::{
    env,
    path::Path,
    process::{Command, Stdio},
};

use crate::{error::Failure, tasks};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Scope {
    All,
    Format,
    Clippy,
    Unit,
    Root,
}

impl Scope {
    pub(crate) fn parse(value: Option<&str>) -> Result<Self, Failure> {
        Ok(match value {
            None | Some("all") => Self::All,
            Some("fmt") => Self::Format,
            Some("clippy") => Self::Clippy,
            Some("unit") => Self::Unit,
            Some("root") => Self::Root,
            Some(other) => {
                return Err(Failure::usage(format!(
                    "unknown test scope '{other}'; expected all, fmt, clippy, unit or root"
                )));
            }
        })
    }
}

pub(crate) fn run(scope: Scope) -> Result<(), Failure> {
    let repository = tasks::repository_root()?;
    let all = scope == Scope::All;
    if all || scope == Scope::Format {
        cargo(&repository, &["fmt", "--all", "--", "--check"])?;
    }
    if all || scope == Scope::Clippy {
        let lint = ["--", "-D", "warnings"];
        cargo(
            &repository,
            &[
                &[
                    "clippy",
                    "--locked",
                    "--offline",
                    "--workspace",
                    "--all-targets",
                ][..],
                &lint,
            ]
            .concat(),
        )?;
    }
    if all || scope == Scope::Unit {
        cargo(
            &repository,
            &["test", "--locked", "--offline", "--workspace"],
        )?;
    }
    if all || scope == Scope::Root {
        root_tests(&repository)?;
    }
    Ok(())
}

fn cargo(repository: &Path, arguments: &[&str]) -> Result<(), Failure> {
    let cargo = env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    eprintln!("xtask test: cargo {}", arguments.join(" "));
    let status = Command::new(cargo)
        .args(arguments)
        .current_dir(repository)
        .stdin(Stdio::null())
        .status()
        .map_err(|error| Failure::task(format!("could not run Cargo: {error}")))?;
    if status.success() {
        Ok(())
    } else {
        Err(Failure::task(format!(
            "cargo {} failed ({status})",
            arguments.join(" ")
        )))
    }
}

fn root_tests(repository: &Path) -> Result<(), Failure> {
    let project = tasks::canonical_project_root(repository)?;
    let script = project.join("tools/run-root-tests.py");
    if !script.is_file() {
        return Ok(());
    }
    let status = Command::new("python3")
        .arg(&script)
        .env("ROOT_TESTS_WYRMROOT", repository)
        .current_dir(&project)
        .stdin(Stdio::null())
        .status()
        .map_err(|error| Failure::task(format!("could not run {}: {error}", script.display())))?;
    if status.success() {
        Ok(())
    } else {
        Err(Failure::task(format!(
            "root Python tests failed ({status})"
        )))
    }
}
