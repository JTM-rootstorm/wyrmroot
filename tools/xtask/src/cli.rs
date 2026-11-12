use crate::{error::Failure, gate::Scope};

pub(crate) const USAGE: &str = r#"Wyrmroot development task dispatcher

Usage:
    tools/pinned-cargo xtask dev-boot [--smp] [--check] [--deep-repository <path>] [--sdk <path>]
    tools/pinned-cargo xtask product --output <fresh-directory> [--deep-repository <path>]
    tools/pinned-cargo xtask test [all|fmt|clippy|unit|root]

dev-boot builds the current product from both working trees and boots it in
local QEMU; COM2 is the `wyrmsh` console. --check drives the prompt, sends
Ctrl-D and requires the kernel's power-off line instead. --sdk names a built
Wyrmroot SDK (`wyrmroot-sdk/out`): its test programs (hello, zlib, Lua) go
on the ESP, and --check runs them.

product builds the same product into a directory: artifacts/esp.img plus the
loader, kernel, bootstrap, natives, bootfs and OVMF pair.

test runs the host gate: formatting, warnings-denied Clippy and the workspace
tests, then the root Python suites. The production natives are compiled by product and dev-boot.
"#;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct G3ImageArguments {
    pub(crate) image: String,
    pub(crate) loader: String,
    pub(crate) kernel: String,
    pub(crate) bootstrap: String,
    pub(crate) bootfs: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum Action {
    DevBoot {
        check: bool,
        smp: bool,
        deep_repository: Option<String>,
        sdk: Option<String>,
    },
    Product {
        output: String,
        deep_repository: Option<String>,
    },
    Test(Scope),
}

pub(crate) fn dispatch(arguments: &[String]) -> Result<Action, Failure> {
    let Some(command) = arguments.first() else {
        return Err(Failure::usage(USAGE));
    };
    let rest = &arguments[1..];
    match command.as_str() {
        "dev-boot" => dispatch_dev_boot(rest),
        "product" => dispatch_product(rest),
        "test" => match rest {
            [] => Ok(Action::Test(Scope::All)),
            [scope] => Ok(Action::Test(Scope::parse(Some(scope))?)),
            _ => Err(Failure::usage(
                "test accepts one scope: all, fmt, clippy, unit or root",
            )),
        },
        "help" | "--help" | "-h" => Err(Failure::usage(USAGE)),
        unknown => Err(Failure::usage(format!(
            "unknown command '{unknown}'\n\n{USAGE}"
        ))),
    }
}

fn dispatch_dev_boot(arguments: &[String]) -> Result<Action, Failure> {
    let mut check = false;
    let mut smp = false;
    let mut deep_repository = None;
    let mut sdk = None;
    let mut rest = arguments.iter();
    while let Some(argument) = rest.next() {
        let slot = match argument.as_str() {
            "--check" if !check => {
                check = true;
                continue;
            }
            "--smp" if !smp => {
                smp = true;
                continue;
            }
            "--deep-repository" if deep_repository.is_none() => &mut deep_repository,
            "--sdk" if sdk.is_none() => &mut sdk,
            _ => {
                return Err(Failure::usage(
                    "dev-boot accepts [--smp] [--check] [--deep-repository <path>] [--sdk <path>]",
                ));
            }
        };
        *slot = Some(
            rest.next()
                .cloned()
                .ok_or_else(|| Failure::usage(format!("dev-boot {argument} requires a path")))?,
        );
    }
    Ok(Action::DevBoot {
        check,
        smp,
        deep_repository,
        sdk,
    })
}

fn dispatch_product(arguments: &[String]) -> Result<Action, Failure> {
    let mut output = None;
    let mut deep_repository = None;
    let mut rest = arguments.iter();
    while let Some(argument) = rest.next() {
        let slot = match argument.as_str() {
            "--output" if output.is_none() => &mut output,
            "--deep-repository" if deep_repository.is_none() => &mut deep_repository,
            _ => {
                return Err(Failure::usage(
                    "product accepts --output <fresh-directory> [--deep-repository <path>]",
                ));
            }
        };
        *slot = Some(
            rest.next()
                .cloned()
                .ok_or_else(|| Failure::usage(format!("product {argument} requires a path")))?,
        );
    }
    Ok(Action::Product {
        output: output
            .ok_or_else(|| Failure::usage("product requires --output <fresh-directory>"))?,
        deep_repository,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn arguments(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_owned()).collect()
    }

    #[test]
    fn the_three_commands_parse() {
        assert_eq!(
            dispatch(&arguments(&["dev-boot", "--check"])),
            Ok(Action::DevBoot {
                check: true,
                smp: false,
                deep_repository: None,
                sdk: None
            })
        );
        assert_eq!(
            dispatch(&arguments(&[
                "dev-boot",
                "--sdk",
                "../wyrmroot-sdk/out",
                "--check"
            ])),
            Ok(Action::DevBoot {
                check: true,
                smp: false,
                deep_repository: None,
                sdk: Some("../wyrmroot-sdk/out".into())
            })
        );
        assert_eq!(
            dispatch(&arguments(&["product", "--output", "out"])),
            Ok(Action::Product {
                output: "out".into(),
                deep_repository: None
            })
        );
        assert_eq!(
            dispatch(&arguments(&["test"])),
            Ok(Action::Test(Scope::All))
        );
        assert_eq!(
            dispatch(&arguments(&["test", "clippy"])),
            Ok(Action::Test(Scope::Clippy))
        );
    }

    #[test]
    fn malformed_commands_are_refused() {
        for bad in [
            &["product"][..],
            &["product", "--output"],
            &["dev-boot", "--check", "--check"],
            &["dev-boot", "--sdk"],
            &["dev-boot", "--sdk", "a", "--sdk", "b"],
            &["test", "native"],
            &["wyr1f", "prepare"],
        ] {
            assert!(dispatch(&arguments(bad)).is_err(), "{bad:?}");
        }
    }
}
