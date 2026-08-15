use std::env;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use crate::cli::validate_filter;
use crate::error::Failure;

pub(crate) fn repository_root() -> Result<PathBuf, Failure> {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .map(Path::to_path_buf)
        .ok_or_else(|| Failure::task("could not resolve the Wyrmroot repository root"))
}

pub(crate) fn run_host_tool_probe(repository: &Path) -> Result<(), Failure> {
    let status = Command::new("sh")
        .arg("toolchain/verify-host-tools.sh")
        .arg("--json")
        .current_dir(repository)
        .stdin(Stdio::null())
        .status()
        .map_err(|error| Failure::task(format!("could not run host toolchain probe: {error}")))?;
    if status.success() {
        Ok(())
    } else {
        Err(Failure::task(format!(
            "host toolchain probe failed with {}",
            child_status(status.code())
        )))
    }
}

pub(crate) fn run_workspace_build(repository: &Path) -> Result<(), Failure> {
    run_cargo(
        repository,
        &["build", "--workspace", "--all-targets", "--locked"],
    )
}

pub(crate) fn run_host_tests(repository: &Path, filter: Option<&str>) -> Result<(), Failure> {
    let mut arguments = vec!["test", "--locked"];
    let owned_filter;

    match filter.and_then(component_package) {
        Some(package) => arguments.extend(["--package", package]),
        None => {
            arguments.extend(["--workspace", "--all-targets"]);
            if let Some(filter) = filter {
                owned_filter = explicit_test_filter(filter)?;
                arguments.extend(["--", owned_filter.as_str()]);
            }
        }
    }
    run_cargo(repository, &arguments)
}

fn component_package(filter: &str) -> Option<&'static str> {
    match filter {
        "bootfs" | "wyrmroot-bootfs" | "package:wyrmroot-bootfs" => Some("wyrmroot-bootfs"),
        "protocol"
        | "bootstrap-proto"
        | "wyrmroot-bootstrap-proto"
        | "package:wyrmroot-bootstrap-proto" => Some("wyrmroot-bootstrap-proto"),
        "elf" | "loader" | "wyrmroot-loader" | "package:wyrmroot-loader" => Some("wyrmroot-loader"),
        "runtime" | "wyrmroot-runtime" | "package:wyrmroot-runtime" => Some("wyrmroot-runtime"),
        "bootstrap" | "wyrmroot-bootstrap" | "package:wyrmroot-bootstrap" => {
            Some("wyrmroot-bootstrap")
        }
        "efi" | "uefi" | "efi-loader" | "wyrmroot-efi-loader" | "package:wyrmroot-efi-loader" => {
            Some("wyrmroot-efi-loader")
        }
        "init0" | "wyrmroot-init0" | "package:wyrmroot-init0" => Some("wyrmroot-init0"),
        "hello" | "wyrmroot-hello" | "package:wyrmroot-hello" => Some("wyrmroot-hello"),
        "xtask" | "package:xtask" => Some("xtask"),
        _ => None,
    }
}

fn explicit_test_filter(filter: &str) -> Result<String, Failure> {
    if let Some(package) = filter.strip_prefix("package:") {
        return Err(Failure::usage(format!(
            "unknown host-test package '{package}'"
        )));
    }
    let filter = filter.strip_prefix("test:").unwrap_or(filter);
    validate_filter(filter)?;
    Ok(filter.to_owned())
}

fn run_cargo(repository: &Path, arguments: &[&str]) -> Result<(), Failure> {
    let cargo = env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
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
            "Cargo task failed with {}",
            child_status(status.code())
        )))
    }
}

fn child_status(code: Option<i32>) -> String {
    code.map_or_else(
        || "termination by signal".to_owned(),
        |code| format!("exit code {code}"),
    )
}

#[cfg(test)]
mod tests {
    use super::{component_package, explicit_test_filter};

    #[test]
    fn component_filters_select_one_workspace_package() {
        assert_eq!(component_package("bootfs"), Some("wyrmroot-bootfs"));
        assert_eq!(
            component_package("protocol"),
            Some("wyrmroot-bootstrap-proto")
        );
        assert_eq!(component_package("elf"), Some("wyrmroot-loader"));
        assert_eq!(component_package("runtime"), Some("wyrmroot-runtime"));
        assert_eq!(component_package("hello"), Some("wyrmroot-hello"));
        assert_eq!(component_package("xtask"), Some("xtask"));
        assert_eq!(component_package("malformed"), None);
        assert_eq!(explicit_test_filter("test:malformed").unwrap(), "malformed");
        assert!(explicit_test_filter("package:unknown").is_err());
    }
}
