//! `xtask test`: the host gate.
//!
//! Formatting, warnings-denied Clippy and the workspace tests in the default
//! feature shape, the same two in each production role's feature shape, and
//! the root Python suites. The production natives themselves are compiled by
//! `xtask product` (and so by `dev-boot`), which is the native half of the
//! gate.

use std::{
    env,
    path::Path,
    process::{Command, Stdio},
};

use crate::{error::Failure, tasks};

/// Production feature shapes of the roles that also build on the host. Their
/// `native-*` features need the guest target and are covered by the product
/// build instead.
const PRODUCTION_SHAPES: [(&str, &str); 3] = [
    ("wyrmroot-system-init", "wyr1e-production"),
    ("wyrmroot-devmgr", "wyr1e8-production"),
    ("wyrmroot-consoled", "wyr1e-wyrmsh"),
];

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
        for (package, features) in PRODUCTION_SHAPES {
            cargo(
                &repository,
                &[
                    &[
                        "clippy",
                        "--locked",
                        "--offline",
                        "--all-targets",
                        "--package",
                        package,
                        "--features",
                        features,
                    ][..],
                    &lint,
                ]
                .concat(),
            )?;
        }
    }
    if all || scope == Scope::Unit {
        cargo(
            &repository,
            &["test", "--locked", "--offline", "--workspace"],
        )?;
        for (package, features) in PRODUCTION_SHAPES {
            cargo(
                &repository,
                &[
                    "test",
                    "--locked",
                    "--offline",
                    "--package",
                    package,
                    "--features",
                    features,
                ],
            )?;
        }
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
