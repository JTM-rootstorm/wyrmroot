use crate::{dev_boot::Clock, error::Failure, gate::Scope};

pub(crate) const USAGE: &str = r#"Wyrmroot development task dispatcher

Usage:
    tools/pinned-cargo xtask dev-boot [--smp] [--check] [--icount|--kvm] [--deep-repository <path>] [--sdk <path>]
    tools/pinned-cargo xtask product --output <fresh-directory> [--deep-repository <path>]
    tools/pinned-cargo xtask test [all|fmt|clippy|unit|root]

dev-boot builds the current product from both working trees and boots it in
local QEMU; COM2 is the `wyrmsh` console. --check drives the prompt, sends
Ctrl-D and requires the kernel's power-off line instead. --sdk names a built
Wyrmroot SDK (`wyrmroot-sdk/out`): its test programs (hello, zlib, Lua) go
on the ESP, and --check runs them. --icount runs QEMU with `-icount shift=0`,
so guest time counts instructions (one per nanosecond) and the kernel's step
report reads as guest instructions; --check then waits four times as long.
--kvm is the timing mode: QEMU runs the guest under KVM on the host CPU, so
the step report is real time under virtualization and --check prints step
means in nanoseconds. It needs /dev/kvm read-write and is refused with
--icount, which is a different clock.

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
        clock: Clock,
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
    let mut icount = false;
    let mut kvm = false;
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
            "--icount" if !icount => {
                icount = true;
                continue;
            }
            "--kvm" if !kvm => {
                kvm = true;
                continue;
            }
            "--deep-repository" if deep_repository.is_none() => &mut deep_repository,
            "--sdk" if sdk.is_none() => &mut sdk,
            _ => {
                return Err(Failure::usage(
                    "dev-boot accepts [--smp] [--check] [--icount|--kvm] [--deep-repository <path>] [--sdk <path>]",
                ));
            }
        };
        *slot = Some(
            rest.next()
                .cloned()
                .ok_or_else(|| Failure::usage(format!("dev-boot {argument} requires a path")))?,
        );
    }
    let clock = match (icount, kvm) {
        (false, false) => Clock::Emulated,
        (true, false) => Clock::Icount,
        (false, true) => Clock::Kvm,
        (true, true) => {
            return Err(Failure::usage(
                "dev-boot --icount and --kvm are different clocks; pass one of them",
            ));
        }
    };
    Ok(Action::DevBoot {
        check,
        smp,
        clock,
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
                clock: Clock::Emulated,
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
                clock: Clock::Emulated,
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
    fn icount_parses_alone_and_with_every_other_flag_in_any_order() {
        let boot = |icount, check, smp, deep: Option<&str>, sdk: Option<&str>| Action::DevBoot {
            check,
            smp,
            clock: if icount {
                Clock::Icount
            } else {
                Clock::Emulated
            },
            deep_repository: deep.map(Into::into),
            sdk: sdk.map(Into::into),
        };
        assert_eq!(
            dispatch(&arguments(&["dev-boot", "--icount"])),
            Ok(boot(true, false, false, None, None))
        );
        for order in [
            &[
                "--icount",
                "--check",
                "--smp",
                "--sdk",
                "s",
                "--deep-repository",
                "d",
            ][..],
            &[
                "--check",
                "--icount",
                "--smp",
                "--deep-repository",
                "d",
                "--sdk",
                "s",
            ],
            &[
                "--sdk",
                "s",
                "--deep-repository",
                "d",
                "--smp",
                "--check",
                "--icount",
            ],
            &[
                "--smp",
                "--sdk",
                "s",
                "--icount",
                "--deep-repository",
                "d",
                "--check",
            ],
        ] {
            let mut command = vec!["dev-boot"];
            command.extend_from_slice(order);
            assert_eq!(
                dispatch(&arguments(&command)),
                Ok(boot(true, true, true, Some("d"), Some("s"))),
                "{order:?}"
            );
        }
        assert_eq!(
            dispatch(&arguments(&["dev-boot", "--check", "--icount"])),
            Ok(boot(true, true, false, None, None))
        );
    }

    #[test]
    fn kvm_parses_alone_and_with_every_other_flag_in_any_order() {
        let boot = |check, smp, deep: Option<&str>, sdk: Option<&str>| Action::DevBoot {
            check,
            smp,
            clock: Clock::Kvm,
            deep_repository: deep.map(Into::into),
            sdk: sdk.map(Into::into),
        };
        assert_eq!(
            dispatch(&arguments(&["dev-boot", "--kvm"])),
            Ok(boot(false, false, None, None))
        );
        let flags = [
            "--kvm",
            "--check",
            "--smp",
            "--sdk s",
            "--deep-repository d",
        ];
        // Every order of the five flags.
        let mut orders = vec![Vec::new()];
        for _ in 0..flags.len() {
            orders = orders
                .into_iter()
                .flat_map(|order: Vec<&str>| {
                    flags
                        .iter()
                        .filter(|flag| !order.contains(*flag))
                        .map(|flag| {
                            let mut next = order.clone();
                            next.push(*flag);
                            next
                        })
                        .collect::<Vec<_>>()
                })
                .collect();
        }
        assert_eq!(orders.len(), 120);
        for order in orders {
            let mut command = vec!["dev-boot"];
            command.extend(order.iter().flat_map(|flag| flag.split(' ')));
            assert_eq!(
                dispatch(&arguments(&command)),
                Ok(boot(true, true, Some("d"), Some("s"))),
                "{order:?}"
            );
        }
        for (with, check, smp, deep, sdk) in [
            ("--check", true, false, None, None),
            ("--smp", false, true, None, None),
            ("--sdk", false, false, None, Some("s")),
            ("--deep-repository", false, false, Some("d"), None),
        ] {
            let mut alone = vec![with];
            if let Some(path) = deep.or(sdk) {
                alone.push(path);
            }
            for kvm_first in [true, false] {
                let mut command = vec!["dev-boot"];
                if kvm_first {
                    command.push("--kvm");
                    command.extend(&alone);
                } else {
                    command.extend(&alone);
                    command.push("--kvm");
                }
                assert_eq!(
                    dispatch(&arguments(&command)),
                    Ok(boot(check, smp, deep, sdk)),
                    "{command:?}"
                );
            }
        }
    }

    #[test]
    fn kvm_is_refused_with_icount_in_either_order() {
        for bad in [
            &["dev-boot", "--kvm", "--icount"][..],
            &["dev-boot", "--icount", "--kvm"],
            &["dev-boot", "--check", "--icount", "--smp", "--kvm"],
        ] {
            let failure = dispatch(&arguments(bad)).unwrap_err();
            assert!(failure.message.contains("--icount"), "{bad:?}");
            assert!(failure.message.contains("--kvm"), "{bad:?}");
            assert!(failure.message.contains("different clocks"), "{bad:?}");
        }
    }

    #[test]
    fn malformed_commands_are_refused() {
        for bad in [
            &["product"][..],
            &["product", "--output"],
            &["dev-boot", "--check", "--check"],
            &["dev-boot", "--sdk"],
            &["dev-boot", "--sdk", "a", "--sdk", "b"],
            &["dev-boot", "--icount", "--icount"],
            &["dev-boot", "--icount", "--check", "--icount"],
            &["dev-boot", "--kvm", "--kvm"],
            &["dev-boot", "--kvm", "--check", "--kvm"],
            &["test", "native"],
            &["wyr1f", "prepare"],
        ] {
            assert!(dispatch(&arguments(bad)).is_err(), "{bad:?}");
        }
    }
}
