use crate::error::Failure;

pub(crate) const USAGE: &str = r#"Wyrmroot development task dispatcher

Usage:
    cargo xtask build [host|loader|bootfs]
    cargo xtask image <loader.efi> <deepwyrm.elf> <bootstrap.elf> <bootfs.img> <esp.img>
    cargo xtask run
    cargo xtask inspect-image <esp.img> <loader.efi> <deepwyrm.elf> <bootstrap.elf> <bootfs.img>
    cargo xtask gdb
    cargo xtask test host [filter]
    cargo xtask test <guest|integration> [filter]

Host filters may name a component (bootfs, protocol, elf, runtime, bootstrap,
efi, init0, hello, or xtask), package:<workspace-package>, or test:<substring>.

WYR0-G3 adds only the exact paired deterministic ESP build and inspection
surface above. Run, GDB, guest-test, integration-test, and general image-builder
work remain unavailable until their assigned later phases.
"#;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct G3ImageArguments {
    pub(crate) image: String,
    pub(crate) loader: String,
    pub(crate) kernel: String,
    pub(crate) bootstrap: String,
    pub(crate) bootfs: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum BuildScope {
    All,
    Host,
    Loader,
    Bootfs,
}

impl BuildScope {
    pub(crate) const fn runs_workspace(self) -> bool {
        matches!(self, Self::All | Self::Host)
    }

    pub(crate) const fn runs_loader(self) -> bool {
        matches!(self, Self::All | Self::Loader)
    }

    pub(crate) const fn runs_bootfs_package(self) -> bool {
        matches!(self, Self::All | Self::Bootfs)
    }
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) enum Action {
    Help,
    Build(BuildScope),
    HostTests(Option<String>),
    BuildG3Image(G3ImageArguments),
    InspectG3Image(G3ImageArguments),
    Unavailable(&'static str),
}

pub(crate) fn dispatch(arguments: &[String]) -> Result<Action, Failure> {
    let Some(command) = arguments.first().map(String::as_str) else {
        return Err(Failure::usage(format!("a command is required\n\n{USAGE}")));
    };

    match command {
        "--help" | "-h" | "help" => {
            expect_arity(arguments, 1, "help does not accept arguments")?;
            Ok(Action::Help)
        }
        "build" => dispatch_build(&arguments[1..]),
        "image" => dispatch_image(&arguments[1..]),
        "run" => unavailable_without_arguments(arguments, "run"),
        "inspect-image" => dispatch_inspect_image(&arguments[1..]),
        "gdb" => unavailable_without_arguments(arguments, "gdb"),
        "test" => dispatch_test(&arguments[1..]),
        unknown => Err(Failure::usage(format!(
            "unknown command '{unknown}'\n\n{USAGE}"
        ))),
    }
}

fn dispatch_image(arguments: &[String]) -> Result<Action, Failure> {
    let [loader, kernel, bootstrap, bootfs, image] = arguments else {
        return Err(Failure::usage(
            "image requires loader, kernel, bootstrap, bootfs, and output ESP paths",
        ));
    };
    Ok(Action::BuildG3Image(G3ImageArguments {
        image: image.clone(),
        loader: loader.clone(),
        kernel: kernel.clone(),
        bootstrap: bootstrap.clone(),
        bootfs: bootfs.clone(),
    }))
}

fn dispatch_inspect_image(arguments: &[String]) -> Result<Action, Failure> {
    let [image, loader, kernel, bootstrap, bootfs] = arguments else {
        return Err(Failure::usage(
            "inspect-image requires ESP, loader, kernel, bootstrap, and bootfs paths",
        ));
    };
    Ok(Action::InspectG3Image(G3ImageArguments {
        image: image.clone(),
        loader: loader.clone(),
        kernel: kernel.clone(),
        bootstrap: bootstrap.clone(),
        bootfs: bootfs.clone(),
    }))
}

fn dispatch_build(arguments: &[String]) -> Result<Action, Failure> {
    match arguments {
        [] => Ok(Action::Build(BuildScope::All)),
        [selector] if selector == "host" => Ok(Action::Build(BuildScope::Host)),
        [selector] if selector == "loader" => Ok(Action::Build(BuildScope::Loader)),
        [selector] if selector == "bootfs" => Ok(Action::Build(BuildScope::Bootfs)),
        [unknown] => Err(Failure::usage(format!(
            "unknown build selector '{unknown}'; expected host, loader, or bootfs"
        ))),
        _ => Err(Failure::usage(
            "build accepts at most one selector (host, loader, or bootfs)",
        )),
    }
}

fn unavailable_without_arguments(
    arguments: &[String],
    command: &'static str,
) -> Result<Action, Failure> {
    expect_arity(
        arguments,
        1,
        format!("{command} does not accept arguments in WYR0-C"),
    )?;
    Ok(Action::Unavailable(command))
}

fn dispatch_test(arguments: &[String]) -> Result<Action, Failure> {
    let Some(suite) = arguments.first().map(String::as_str) else {
        return Err(Failure::usage(format!(
            "a test suite is required (host, guest, or integration)\n\n{USAGE}"
        )));
    };

    if arguments.len() > 2 {
        return Err(Failure::usage(
            "test accepts at most one focused filter argument",
        ));
    }
    let filter = arguments.get(1).cloned();
    if let Some(filter) = &filter {
        validate_filter(filter)?;
    }

    match suite {
        "host" => Ok(Action::HostTests(filter)),
        "guest" => Ok(Action::Unavailable("test guest")),
        "integration" => Ok(Action::Unavailable("test integration")),
        unknown => Err(Failure::usage(format!(
            "unknown test suite '{unknown}'; expected host, guest, or integration"
        ))),
    }
}

fn expect_arity(
    arguments: &[String],
    expected: usize,
    message: impl Into<String>,
) -> Result<(), Failure> {
    if arguments.len() == expected {
        Ok(())
    } else {
        Err(Failure::usage(message))
    }
}

pub(crate) fn validate_filter(filter: &str) -> Result<(), Failure> {
    if filter.is_empty() {
        return Err(Failure::usage("host test filter must not be empty"));
    }
    if filter.starts_with('-') {
        return Err(Failure::usage(
            "host test filter must not be a Cargo or test-harness option",
        ));
    }
    if filter.chars().any(char::is_control) {
        return Err(Failure::usage(
            "host test filter must not contain control characters",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{Action, BuildScope, USAGE, dispatch};
    use crate::error::{Failure, FailureKind};

    fn arguments(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| String::from(*value)).collect()
    }

    #[test]
    fn help_and_available_actions_dispatch() {
        for command in ["help", "--help", "-h"] {
            assert_eq!(dispatch(&arguments(&[command])), Ok(Action::Help));
        }
        assert_eq!(
            dispatch(&arguments(&["build"])),
            Ok(Action::Build(BuildScope::All))
        );
        assert_eq!(
            dispatch(&arguments(&["build", "host"])),
            Ok(Action::Build(BuildScope::Host))
        );
        assert_eq!(
            dispatch(&arguments(&["build", "loader"])),
            Ok(Action::Build(BuildScope::Loader))
        );
        assert_eq!(
            dispatch(&arguments(&["build", "bootfs"])),
            Ok(Action::Build(BuildScope::Bootfs))
        );
        assert_eq!(
            dispatch(&arguments(&["test", "host", "bootfs"])),
            Ok(Action::HostTests(Some("bootfs".to_owned())))
        );
        assert!(BuildScope::All.runs_workspace());
        assert!(BuildScope::All.runs_loader());
        assert!(BuildScope::All.runs_bootfs_package());
        assert!(!BuildScope::Bootfs.runs_workspace());
        assert!(!BuildScope::Bootfs.runs_loader());
        assert!(BuildScope::Bootfs.runs_bootfs_package());
        assert!(USAGE.contains("WYR0-G3 adds only the exact paired deterministic ESP"));
    }

    #[test]
    fn later_phase_tasks_are_stable_unavailable_failures() {
        for values in [
            &["run"][..],
            &["gdb"],
            &["test", "guest"],
            &["test", "integration", "wyr0"],
        ] {
            let Action::Unavailable(command) =
                dispatch(&arguments(values)).expect("recognized command should dispatch")
            else {
                panic!("later phase operation did not remain unavailable");
            };
            let failure = Failure::unavailable(command);
            assert_eq!(failure.kind, FailureKind::Unavailable);
            assert_eq!(failure.exit_code(), 1);
            assert!(
                failure
                    .message
                    .contains("unavailable in the current WYR0-G3 surface")
            );
        }

        assert_eq!(
            dispatch(&arguments(&[
                "image",
                "loader.efi",
                "deepwyrm.elf",
                "bootstrap.elf",
                "bootfs.img",
                "esp.img",
            ])),
            Ok(Action::BuildG3Image(super::G3ImageArguments {
                image: "esp.img".to_owned(),
                loader: "loader.efi".to_owned(),
                kernel: "deepwyrm.elf".to_owned(),
                bootstrap: "bootstrap.elf".to_owned(),
                bootfs: "bootfs.img".to_owned(),
            }))
        );
    }

    #[test]
    fn invalid_or_missing_syntax_is_a_usage_failure() {
        for values in [
            &[][..],
            &["unknown"],
            &["build", "extra"],
            &["build", "host", "extra"],
            &["build", "bootfs", "extra"],
            &["image", "extra"],
            &["inspect-image"],
            &["inspect-image", "one", "two"],
            &["test"],
            &["test", "unknown"],
            &["test", "host", "one", "two"],
            &["test", "host", "--nocapture"],
        ] {
            let failure = dispatch(&arguments(values)).expect_err("invalid syntax was accepted");
            assert_eq!(failure.kind, FailureKind::Usage);
            assert_eq!(failure.exit_code(), 2);
        }
    }
}
