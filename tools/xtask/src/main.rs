use std::env;
use std::process::ExitCode;

const USAGE: &str = "\
Wyrmroot development task dispatcher (bootstrap scaffold)\n\
\n\
Usage:\n\
    cargo xtask build\n\
    cargo xtask image\n\
    cargo xtask run\n\
    cargo xtask inspect-image\n\
    cargo xtask gdb\n\
    cargo xtask test <host|guest|integration> [filter]\n\
\n\
All task commands are placeholders and currently fail without performing work.\n";

fn main() -> ExitCode {
    let arguments: Vec<String> = env::args().skip(1).collect();

    match dispatch(&arguments) {
        Ok(output) => {
            print!("{output}");
            ExitCode::SUCCESS
        }
        Err(failure) => {
            eprintln!("xtask: {}", failure.message);
            ExitCode::from(failure.exit_code())
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
enum FailureKind {
    NotImplemented,
    Usage,
}

#[derive(Debug, Eq, PartialEq)]
struct Failure {
    kind: FailureKind,
    message: String,
}

impl Failure {
    fn not_implemented(command: &str) -> Self {
        Self {
            kind: FailureKind::NotImplemented,
            message: format!(
                "'{command}' is not implemented; this command surface is bootstrap scaffolding only"
            ),
        }
    }

    fn usage(message: String) -> Self {
        Self {
            kind: FailureKind::Usage,
            message,
        }
    }

    const fn exit_code(&self) -> u8 {
        match self.kind {
            FailureKind::NotImplemented => 1,
            FailureKind::Usage => 2,
        }
    }
}

fn dispatch(arguments: &[String]) -> Result<&'static str, Failure> {
    let Some(command) = arguments.first().map(String::as_str) else {
        return Err(Failure::usage(format!("a command is required\n\n{USAGE}")));
    };

    match command {
        "--help" | "-h" | "help" => Ok(USAGE),
        "build" | "image" | "run" | "inspect-image" | "gdb" => {
            Err(Failure::not_implemented(command))
        }
        "test" => dispatch_test(&arguments[1..]),
        unknown => Err(Failure::usage(format!(
            "unknown command '{unknown}'\n\n{USAGE}"
        ))),
    }
}

fn dispatch_test(arguments: &[String]) -> Result<&'static str, Failure> {
    let Some(suite) = arguments.first().map(String::as_str) else {
        return Err(Failure::usage(format!(
            "a test suite is required (host, guest, or integration)\n\n{USAGE}"
        )));
    };

    match suite {
        "host" | "guest" | "integration" => Err(Failure::not_implemented(&format!("test {suite}"))),
        unknown => Err(Failure::usage(format!(
            "unknown test suite '{unknown}'; expected host, guest, or integration"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::{FailureKind, USAGE, dispatch};

    fn arguments(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| String::from(*value)).collect()
    }

    #[test]
    fn help_is_successful() {
        for command in ["help", "--help", "-h"] {
            assert_eq!(dispatch(&arguments(&[command])), Ok(USAGE));
        }
    }

    #[test]
    fn planned_tasks_are_not_implemented_failures() {
        for values in [
            &["build"][..],
            &["image"],
            &["run"],
            &["inspect-image"],
            &["gdb"],
            &["test", "host"],
            &["test", "guest"],
            &["test", "integration"],
            &["test", "host", "bootfs"],
        ] {
            let failure = dispatch(&arguments(values)).expect_err("planned task unexpectedly ran");
            assert_eq!(failure.kind, FailureKind::NotImplemented);
            assert_eq!(failure.exit_code(), 1);
            assert!(failure.message.contains("not implemented"));
        }
    }

    #[test]
    fn invalid_or_missing_syntax_is_a_usage_failure() {
        for values in [&[][..], &["unknown"], &["test"], &["test", "unknown"]] {
            let failure = dispatch(&arguments(values)).expect_err("invalid syntax was accepted");
            assert_eq!(failure.kind, FailureKind::Usage);
            assert_eq!(failure.exit_code(), 2);
        }
    }
}
