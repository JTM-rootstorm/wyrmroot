use crate::error::Failure;

pub(crate) const USAGE: &str = r#"Wyrmroot development task dispatcher

Usage:
    cargo xtask build [host|loader]
    cargo xtask image
    cargo xtask run
    cargo xtask inspect-image
    cargo xtask gdb
    cargo xtask test host [filter]
    cargo xtask test <guest|integration> [filter]

Host filters may name a component (bootfs, protocol, elf, runtime, bootstrap,
efi, init0, hello, or xtask), package:<workspace-package>, or test:<substring>.

WYR0-B implements host and UEFI-loader build orchestration. Image, run, image
inspection, GDB, guest-test, integration-test, and external kernel-artifact
collection remain unavailable until their assigned later phases.
"#;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum BuildScope {
    All,
    Host,
    Loader,
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) enum Action {
    Help,
    Build(BuildScope),
    HostTests(Option<String>),
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
        "image" => unavailable_without_arguments(arguments, "image"),
        "run" => unavailable_without_arguments(arguments, "run"),
        "inspect-image" => unavailable_without_arguments(arguments, "inspect-image"),
        "gdb" => unavailable_without_arguments(arguments, "gdb"),
        "test" => dispatch_test(&arguments[1..]),
        unknown => Err(Failure::usage(format!(
            "unknown command '{unknown}'\n\n{USAGE}"
        ))),
    }
}

fn dispatch_build(arguments: &[String]) -> Result<Action, Failure> {
    match arguments {
        [] => Ok(Action::Build(BuildScope::All)),
        [selector] if selector == "host" => Ok(Action::Build(BuildScope::Host)),
        [selector] if selector == "loader" => Ok(Action::Build(BuildScope::Loader)),
        [unknown] => Err(Failure::usage(format!(
            "unknown build selector '{unknown}'; expected host or loader"
        ))),
        _ => Err(Failure::usage(
            "build accepts at most one selector (host or loader)",
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
        format!("{command} does not accept arguments in WYR0-B"),
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
    fn help_and_wyr0_b_actions_dispatch() {
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
            dispatch(&arguments(&["test", "host", "bootfs"])),
            Ok(Action::HostTests(Some("bootfs".to_owned())))
        );
        assert!(USAGE.contains("WYR0-B implements host and UEFI-loader"));
    }

    #[test]
    fn later_phase_tasks_are_stable_unavailable_failures() {
        for values in [
            &["image"][..],
            &["run"],
            &["inspect-image"],
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
            assert!(failure.message.contains("unavailable in WYR0-B"));
        }
    }

    #[test]
    fn invalid_or_missing_syntax_is_a_usage_failure() {
        for values in [
            &[][..],
            &["unknown"],
            &["build", "extra"],
            &["build", "host", "extra"],
            &["image", "extra"],
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
