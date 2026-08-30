use crate::error::Failure;

pub(crate) const USAGE: &str = r#"Wyrmroot development task dispatcher

Usage:
    cargo xtask build [host|loader|bootfs]
    cargo xtask image <loader.efi> <deepwyrm.elf> <bootstrap.elf> <bootfs.img> <esp.img>
    cargo xtask image --request <wyr0-h-request.toml>
    cargo xtask run <default|smp> --request <wyr0-h-request.toml>
    cargo xtask inspect-image <esp.img> <loader.efi> <deepwyrm.elf> <bootstrap.elf> <bootfs.img>
    cargo xtask inspect-image --request <wyr0-h-request.toml>
    cargo xtask audit-i-b <first-request.toml> <second-request.toml>
    cargo xtask gdb <default|smp> --request <wyr0-h-request.toml>
    cargo xtask test host [filter]
    cargo xtask test guest [filter]
    cargo xtask test integration wyr0 [default|smp] --request <wyr0-h-request.toml>
    tools/pinned-cargo xtask wyr1 image --request <wyr1-a-request.toml>
    tools/pinned-cargo xtask wyr1 inspect --request <wyr1-a-request.toml>
    tools/pinned-cargo xtask wyr1 prepare --request <wyr1-a-request.toml>
    tools/pinned-cargo xtask wyr1 evidence --request <wyr1-a-request.toml> --default <log> --smp <log>
    tools/pinned-cargo xtask wyr1b freeze --output <fresh-directory>
    tools/pinned-cargo xtask wyr1b image --request <wyr1-b-request.toml>
    tools/pinned-cargo xtask wyr1b inspect --request <wyr1-b-request.toml>
    tools/pinned-cargo xtask wyr1b run --request <wyr1-b-request.toml>
    tools/pinned-cargo xtask wyr1b evidence --request <wyr1-b-request.toml>
    tools/pinned-cargo xtask wyr1c1 product --output <fresh-directory>
    tools/pinned-cargo xtask wyr1c2 freeze --output <fresh-directory>
    tools/pinned-cargo xtask wyr1c2 image --request <wyr1-c2-request.toml>
    tools/pinned-cargo xtask wyr1c2 inspect --request <wyr1-c2-request.toml>
    cargo xtask dw1b image --request <dw1-b-request.toml>
    cargo xtask dw1b image-rebuild --request <dw1-b-request.toml>
    cargo xtask dw1b freeze --output <directory>
    cargo xtask dw1b inspect --request <dw1-b-request.toml>
    cargo xtask dw1b run --request <dw1-b-request.toml>
    cargo xtask dw1b measure --init <elf> --hello <elf> --cpu-hog <elf> --progress <elf>
    cargo xtask dw1b evidence --request <dw1-b-request.toml>
    cargo xtask dw1c preflight --output <fresh-directory> --progress-digest <16-hex>
    cargo xtask dw1c prepare --request <dw1-c-request.toml>
    cargo xtask dw1c freeze --output <directory>
    cargo xtask dw1c image --request <dw1-c-request.toml>
    cargo xtask dw1c image-rebuild --request <dw1-c-request.toml>
    cargo xtask dw1c inspect --request <dw1-c-request.toml>
    tools/pinned-cargo xtask dw1d6 freeze --output <fresh-directory> --deep-repository <path> --deep-revision <40-hex> --evidence-nonce <16-hex> --evidence-challenge <16-hex>

Host filters may name a component (bootfs, protocol, elf, runtime, bootstrap,
efi, init0, hello, xtask, dw1c-init0, or dw1d6), package:<workspace-package>,
or test:<substring>. The dw1c-init0 and dw1d6 filters are explicit
feature-specific controller gates.

The WYR0-H request path builds and inspects the exact init0/hello bootfs and
paired ESP, records revision/hash provenance, and uses one q35/OVMF path for
the 1-vCPU default and 4-vCPU smp profiles. Guest-test remains unavailable;
the integration command owns the complete paired profile assertion.
Each request requires a sibling build-receipt.toml produced by its isolated
canonical build lane; see toolchain/templates/wyr0-h-build-receipt.toml.

The WYR0-I-B artifact audit consumes two already-built requests in distinct
output roots. It requires separately recorded clean-build process evidence;
the command does not perform or prove the two clean builds.

When the exact Deepwyrm commit is absent from the remote ref closure, run Cargo
through the project-local transport after independently obtaining the sibling
Git repository:
    sh toolchain/cargo-with-local-deepwyrm.sh <deepwyrm-repository> -- <cargo-arguments...>
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
    BuildHImage(String),
    InspectHImage(String),
    AuditIB {
        first_request: String,
        second_request: String,
    },
    RunH {
        profile: HProfile,
        request: String,
    },
    GdbH {
        profile: HProfile,
        request: String,
    },
    IntegrationH {
        profile: Option<HProfile>,
        request: String,
    },
    Wyr1Image(String),
    Wyr1Inspect(String),
    Wyr1Prepare(String),
    Wyr1Evidence {
        request: String,
        default: String,
        smp: String,
    },
    Wyr1BImage(String),
    Wyr1BFreeze(String),
    Wyr1BInspect(String),
    Wyr1BRun(String),
    Wyr1BEvidence(String),
    Wyr1C1Product(String),
    Wyr1C2Freeze(String),
    Wyr1C2Image(String),
    Wyr1C2Inspect(String),
    Dw1BImage(String),
    Dw1BImageRebuild(String),
    Dw1BFreeze(String),
    Dw1BInspect(String),
    Dw1BRun(String),
    Dw1BMeasure {
        init: String,
        hello: String,
        cpu_hog: String,
        progress: String,
    },
    Dw1BEvidence(String),
    Dw1CPreflight {
        output: String,
        progress_digest: String,
    },
    Dw1CPrepare(String),
    Dw1CFreeze {
        output: String,
        deep_repository: String,
        deep_revision: String,
        evidence_nonce: String,
        progress_digest: String,
    },
    Dw1CImage(String),
    Dw1CImageRebuild(String),
    Dw1CInspect(String),
    Dw1D6Freeze {
        output: String,
        deep_repository: String,
        deep_revision: String,
        evidence_nonce: String,
        evidence_challenge: String,
    },
    Unavailable(&'static str),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum HProfile {
    Default,
    Smp,
}

impl HProfile {
    pub(crate) const fn name(self) -> &'static str {
        match self {
            Self::Default => "default",
            Self::Smp => "smp",
        }
    }

    fn parse(value: &str) -> Result<Self, Failure> {
        match value {
            "default" => Ok(Self::Default),
            "smp" => Ok(Self::Smp),
            _ => Err(Failure::usage(
                "WYR0-H profile must be either 'default' or 'smp'",
            )),
        }
    }
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
        "run" => dispatch_profile_request(&arguments[1..], false),
        "inspect-image" => dispatch_inspect_image(&arguments[1..]),
        "audit-i-b" => dispatch_i_b_audit(&arguments[1..]),
        "gdb" => dispatch_profile_request(&arguments[1..], true),
        "test" => dispatch_test(&arguments[1..]),
        "wyr1" => dispatch_wyr1(&arguments[1..]),
        "wyr1b" => dispatch_wyr1b(&arguments[1..]),
        "wyr1c1" => dispatch_wyr1c1(&arguments[1..]),
        "wyr1c2" => dispatch_wyr1c2(&arguments[1..]),
        "dw1b" => dispatch_dw1b(&arguments[1..]),
        "dw1c" => dispatch_dw1c(&arguments[1..]),
        "dw1d6" => dispatch_dw1d6(&arguments[1..]),
        unknown => Err(Failure::usage(format!(
            "unknown command '{unknown}'\n\n{USAGE}"
        ))),
    }
}

fn dispatch_dw1d6(arguments: &[String]) -> Result<Action, Failure> {
    match arguments {
        [
            command,
            output_flag,
            output,
            deep_flag,
            deep_repository,
            revision_flag,
            deep_revision,
            nonce_flag,
            evidence_nonce,
            challenge_flag,
            evidence_challenge,
        ] if command == "freeze"
            && output_flag == "--output"
            && deep_flag == "--deep-repository"
            && revision_flag == "--deep-revision"
            && nonce_flag == "--evidence-nonce"
            && challenge_flag == "--evidence-challenge" =>
        {
            Ok(Action::Dw1D6Freeze {
                output: output.clone(),
                deep_repository: deep_repository.clone(),
                deep_revision: deep_revision.clone(),
                evidence_nonce: evidence_nonce.clone(),
                evidence_challenge: evidence_challenge.clone(),
            })
        }
        _ => Err(Failure::usage(
            "dw1d6 requires freeze --output <fresh-directory> --deep-repository <path> --deep-revision <40-hex> --evidence-nonce <16-hex> --evidence-challenge <16-hex>",
        )),
    }
}

fn dispatch_wyr1c2(arguments: &[String]) -> Result<Action, Failure> {
    match arguments {
        [command, flag, value] if command == "freeze" && flag == "--output" => {
            Ok(Action::Wyr1C2Freeze(value.clone()))
        }
        [command, flag, value] if command == "image" && flag == "--request" => {
            Ok(Action::Wyr1C2Image(value.clone()))
        }
        [command, flag, value] if command == "inspect" && flag == "--request" => {
            Ok(Action::Wyr1C2Inspect(value.clone()))
        }
        _ => Err(Failure::usage(
            "wyr1c2 requires freeze --output <fresh-directory>, image --request <request>, or inspect --request <request>; it has selector=none and no run or evidence command",
        )),
    }
}

fn dispatch_wyr1c1(arguments: &[String]) -> Result<Action, Failure> {
    match arguments {
        [command, flag, output] if command == "product" && flag == "--output" => {
            Ok(Action::Wyr1C1Product(output.clone()))
        }
        _ => Err(Failure::usage(
            "wyr1c1 requires product --output <fresh-directory>; it has no selector, run, or evidence command",
        )),
    }
}

fn dispatch_dw1c(arguments: &[String]) -> Result<Action, Failure> {
    match arguments {
        [command, output_flag, output, digest_flag, progress_digest]
            if command == "preflight"
                && output_flag == "--output"
                && digest_flag == "--progress-digest" =>
        {
            Ok(Action::Dw1CPreflight {
                output: output.clone(),
                progress_digest: progress_digest.clone(),
            })
        }
        [
            command,
            output_flag,
            output,
            deep_flag,
            deep_repository,
            revision_flag,
            deep_revision,
            nonce_flag,
            evidence_nonce,
            digest_flag,
            progress_digest,
        ] if command == "freeze"
            && output_flag == "--output"
            && deep_flag == "--deep-repository"
            && revision_flag == "--deep-revision"
            && nonce_flag == "--evidence-nonce"
            && digest_flag == "--progress-digest" =>
        {
            Ok(Action::Dw1CFreeze {
                output: output.clone(),
                deep_repository: deep_repository.clone(),
                deep_revision: deep_revision.clone(),
                evidence_nonce: evidence_nonce.clone(),
                progress_digest: progress_digest.clone(),
            })
        }
        [command, flag, request] if command == "image" && flag == "--request" => {
            Ok(Action::Dw1CImage(request.clone()))
        }
        [command, flag, request] if command == "image-rebuild" && flag == "--request" => {
            Ok(Action::Dw1CImageRebuild(request.clone()))
        }
        [command, flag, request] if command == "inspect" && flag == "--request" => {
            Ok(Action::Dw1CInspect(request.clone()))
        }
        [command, flag, request] if command == "prepare" && flag == "--request" => {
            Ok(Action::Dw1CPrepare(request.clone()))
        }
        _ => Err(Failure::usage(
            "dw1c requires preflight --output <fresh-dir> --progress-digest <16-hex>, freeze --output <fresh-dir> --deep-repository <path> --deep-revision <40-hex> --evidence-nonce <16-hex> --progress-digest <16-hex>, or image|image-rebuild|inspect|prepare --request <dw1-c-request.toml>",
        )),
    }
}

fn dispatch_dw1b(arguments: &[String]) -> Result<Action, Failure> {
    match arguments {
        [command, flag, output] if command == "freeze" && flag == "--output" => {
            Ok(Action::Dw1BFreeze(output.clone()))
        }
        [command, flag, request] if command == "image" && flag == "--request" => {
            Ok(Action::Dw1BImage(request.clone()))
        }
        [command, flag, request] if command == "image-rebuild" && flag == "--request" => {
            Ok(Action::Dw1BImageRebuild(request.clone()))
        }
        [command, flag, request] if command == "inspect" && flag == "--request" => {
            Ok(Action::Dw1BInspect(request.clone()))
        }
        [command, flag, request] if command == "run" && flag == "--request" => {
            Ok(Action::Dw1BRun(request.clone()))
        }
        [
            command,
            init_flag,
            init,
            hello_flag,
            hello,
            hog_flag,
            cpu_hog,
            progress_flag,
            progress,
        ] if command == "measure"
            && init_flag == "--init"
            && hello_flag == "--hello"
            && hog_flag == "--cpu-hog"
            && progress_flag == "--progress" =>
        {
            Ok(Action::Dw1BMeasure {
                init: init.clone(),
                hello: hello.clone(),
                cpu_hog: cpu_hog.clone(),
                progress: progress.clone(),
            })
        }
        [command, flag, request] if command == "evidence" && flag == "--request" => {
            Ok(Action::Dw1BEvidence(request.clone()))
        }
        _ => Err(Failure::usage(
            "dw1b requires freeze --output <directory>, image|image-rebuild|inspect|run|evidence --request <path>, or measure with four exact artifacts",
        )),
    }
}

fn dispatch_wyr1b(arguments: &[String]) -> Result<Action, Failure> {
    match arguments {
        [command, flag, output] if command == "freeze" && flag == "--output" => {
            Ok(Action::Wyr1BFreeze(output.clone()))
        }
        [command, flag, request] if command == "image" && flag == "--request" => {
            Ok(Action::Wyr1BImage(request.clone()))
        }
        [command, flag, request] if command == "inspect" && flag == "--request" => {
            Ok(Action::Wyr1BInspect(request.clone()))
        }
        [command, flag, request] if command == "run" && flag == "--request" => {
            Ok(Action::Wyr1BRun(request.clone()))
        }
        [command, flag, request] if command == "evidence" && flag == "--request" => {
            Ok(Action::Wyr1BEvidence(request.clone()))
        }
        _ => Err(Failure::usage(
            "wyr1b requires freeze --output <fresh-directory> or image|inspect|run|evidence --request <path>",
        )),
    }
}

fn dispatch_wyr1(arguments: &[String]) -> Result<Action, Failure> {
    match arguments {
        [command, flag, request] if command == "image" && flag == "--request" => {
            Ok(Action::Wyr1Image(request.clone()))
        }
        [command, flag, request] if command == "inspect" && flag == "--request" => {
            Ok(Action::Wyr1Inspect(request.clone()))
        }
        [command, flag, request] if command == "prepare" && flag == "--request" => {
            Ok(Action::Wyr1Prepare(request.clone()))
        }
        [command, flag, request, default_flag, default, smp_flag, smp]
            if command == "evidence"
                && flag == "--request"
                && default_flag == "--default"
                && smp_flag == "--smp" =>
        {
            Ok(Action::Wyr1Evidence {
                request: request.clone(),
                default: default.clone(),
                smp: smp.clone(),
            })
        }
        _ => Err(Failure::usage(
            "wyr1 requires image|inspect|prepare --request <path>, or evidence --request <path> --default <log> --smp <log>",
        )),
    }
}

fn dispatch_i_b_audit(arguments: &[String]) -> Result<Action, Failure> {
    let [first_request, second_request] = arguments else {
        return Err(Failure::usage(
            "audit-i-b requires exactly two WYR0-H candidate request paths",
        ));
    };
    Ok(Action::AuditIB {
        first_request: first_request.clone(),
        second_request: second_request.clone(),
    })
}

fn dispatch_image(arguments: &[String]) -> Result<Action, Failure> {
    if let [flag, request] = arguments
        && flag == "--request"
    {
        return Ok(Action::BuildHImage(request.clone()));
    }
    let [loader, kernel, bootstrap, bootfs, image] = arguments else {
        return Err(Failure::usage(
            "image requires either --request <path> or loader, kernel, bootstrap, bootfs, and output ESP paths",
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
    if let [flag, request] = arguments
        && flag == "--request"
    {
        return Ok(Action::InspectHImage(request.clone()));
    }
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

fn dispatch_profile_request(arguments: &[String], gdb: bool) -> Result<Action, Failure> {
    let [profile, flag, request] = arguments else {
        return Err(Failure::usage(
            "WYR0-H run/gdb requires <default|smp> --request <path>",
        ));
    };
    if flag != "--request" {
        return Err(Failure::usage("WYR0-H run/gdb requires the --request flag"));
    }
    let profile = HProfile::parse(profile)?;
    if gdb {
        Ok(Action::GdbH {
            profile,
            request: request.clone(),
        })
    } else {
        Ok(Action::RunH {
            profile,
            request: request.clone(),
        })
    }
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

fn dispatch_test(arguments: &[String]) -> Result<Action, Failure> {
    let Some(suite) = arguments.first().map(String::as_str) else {
        return Err(Failure::usage(format!(
            "a test suite is required (host, guest, or integration)\n\n{USAGE}"
        )));
    };

    match suite {
        "host" => {
            if arguments.len() > 2 {
                return Err(Failure::usage(
                    "test host accepts at most one focused filter argument",
                ));
            }
            let filter = arguments.get(1).cloned();
            if let Some(filter) = &filter {
                validate_filter(filter)?;
            }
            Ok(Action::HostTests(filter))
        }
        "guest" if arguments.len() <= 2 => Ok(Action::Unavailable("test guest")),
        "guest" => Err(Failure::usage(
            "test guest accepts at most one focused filter argument",
        )),
        "integration" => dispatch_integration(&arguments[1..]),
        unknown => Err(Failure::usage(format!(
            "unknown test suite '{unknown}'; expected host, guest, or integration"
        ))),
    }
}

fn dispatch_integration(arguments: &[String]) -> Result<Action, Failure> {
    match arguments {
        [wyr0, flag, request] if wyr0 == "wyr0" && flag == "--request" => {
            Ok(Action::IntegrationH {
                profile: None,
                request: request.clone(),
            })
        }
        [wyr0, profile, flag, request] if wyr0 == "wyr0" && flag == "--request" => {
            Ok(Action::IntegrationH {
                profile: Some(HProfile::parse(profile)?),
                request: request.clone(),
            })
        }
        _ => Err(Failure::usage(
            "test integration requires wyr0 [default|smp] --request <path>",
        )),
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
    use super::{Action, BuildScope, HProfile, USAGE, dispatch};
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
        assert!(USAGE.contains("WYR0-H request path"));
        assert!(USAGE.contains("build-receipt.toml"));
        assert!(USAGE.contains("requires separately recorded clean-build process evidence"));
    }

    #[test]
    fn h_actions_dispatch_and_guest_test_remains_unavailable() {
        assert_eq!(
            dispatch(&arguments(&["image", "--request", "request.toml"])),
            Ok(Action::BuildHImage("request.toml".into()))
        );
        assert_eq!(
            dispatch(&arguments(&["inspect-image", "--request", "request.toml"])),
            Ok(Action::InspectHImage("request.toml".into()))
        );
        assert_eq!(
            dispatch(&arguments(&["audit-i-b", "first.toml", "second.toml"])),
            Ok(Action::AuditIB {
                first_request: "first.toml".into(),
                second_request: "second.toml".into(),
            })
        );
        assert_eq!(
            dispatch(&arguments(&["run", "default", "--request", "request.toml"])),
            Ok(Action::RunH {
                profile: HProfile::Default,
                request: "request.toml".into(),
            })
        );
        assert_eq!(
            dispatch(&arguments(&["gdb", "smp", "--request", "request.toml"])),
            Ok(Action::GdbH {
                profile: HProfile::Smp,
                request: "request.toml".into(),
            })
        );
        assert_eq!(
            dispatch(&arguments(&[
                "test",
                "integration",
                "wyr0",
                "--request",
                "request.toml"
            ])),
            Ok(Action::IntegrationH {
                profile: None,
                request: "request.toml".into(),
            })
        );
        assert_eq!(
            dispatch(&arguments(&[
                "test",
                "integration",
                "wyr0",
                "smp",
                "--request",
                "request.toml"
            ])),
            Ok(Action::IntegrationH {
                profile: Some(HProfile::Smp),
                request: "request.toml".into(),
            })
        );

        let Action::Unavailable(command) =
            dispatch(&arguments(&["test", "guest"])).expect("guest dispatch")
        else {
            panic!("guest test unexpectedly became available");
        };
        let failure = Failure::unavailable(command);
        assert_eq!(failure.kind, FailureKind::Unavailable);
        assert_eq!(failure.exit_code(), 1);
        assert!(
            failure
                .message
                .contains("unavailable in the current WYR0-H surface")
        );

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
    fn wyr1_vm_preparation_dispatches_separately_from_execution() {
        assert_eq!(
            dispatch(&arguments(&[
                "wyr1",
                "prepare",
                "--request",
                "request.toml",
            ])),
            Ok(Action::Wyr1Prepare("request.toml".into()))
        );
        assert!(USAGE.contains("tools/pinned-cargo xtask wyr1 prepare --request"));
        assert!(!USAGE.contains("\n    cargo xtask wyr1 "));
    }

    #[test]
    fn dw1b_run_dispatches_to_the_observed_execution_path() {
        assert_eq!(
            dispatch(&arguments(&["dw1b", "run", "--request", "request.toml",])),
            Ok(Action::Dw1BRun("request.toml".into()))
        );
        assert!(USAGE.contains("dw1b run --request"));
        assert_eq!(
            dispatch(&arguments(&["dw1b", "freeze", "--output", "freeze"])),
            Ok(Action::Dw1BFreeze("freeze".into()))
        );
        assert!(USAGE.contains("dw1b freeze --output"));
        assert_eq!(
            dispatch(&arguments(&[
                "dw1b",
                "image-rebuild",
                "--request",
                "request.toml",
            ])),
            Ok(Action::Dw1BImageRebuild("request.toml".into()))
        );
    }

    #[test]
    fn dw1c_product_commands_dispatch_to_request_bound_actions() {
        assert_eq!(
            dispatch(&arguments(&[
                "dw1c",
                "preflight",
                "--output",
                "preflight",
                "--progress-digest",
                &"B".repeat(16),
            ])),
            Ok(Action::Dw1CPreflight {
                output: "preflight".into(),
                progress_digest: "B".repeat(16),
            })
        );
        assert_eq!(
            dispatch(&arguments(&[
                "dw1c",
                "freeze",
                "--output",
                "freeze",
                "--deep-repository",
                "/deep",
                "--deep-revision",
                &"a".repeat(40),
                "--evidence-nonce",
                &"A".repeat(16),
                "--progress-digest",
                &"B".repeat(16),
            ])),
            Ok(Action::Dw1CFreeze {
                output: "freeze".into(),
                deep_repository: "/deep".into(),
                deep_revision: "a".repeat(40),
                evidence_nonce: "A".repeat(16),
                progress_digest: "B".repeat(16)
            })
        );
        assert_eq!(
            dispatch(&arguments(&["dw1c", "image", "--request", "request.toml"])),
            Ok(Action::Dw1CImage("request.toml".into()))
        );
        assert_eq!(
            dispatch(&arguments(&[
                "dw1c",
                "image-rebuild",
                "--request",
                "request.toml"
            ])),
            Ok(Action::Dw1CImageRebuild("request.toml".into()))
        );
        assert_eq!(
            dispatch(&arguments(&[
                "dw1c",
                "inspect",
                "--request",
                "request.toml"
            ])),
            Ok(Action::Dw1CInspect("request.toml".into()))
        );
    }

    #[test]
    fn dw1d6_freeze_requires_the_explicit_candidate_and_evidence_pair() {
        assert_eq!(
            dispatch(&arguments(&[
                "dw1d6",
                "freeze",
                "--output",
                "freeze",
                "--deep-repository",
                "/home/mike/Documents/Programming/OS-Project/deepwyrm",
                "--deep-revision",
                &"a".repeat(40),
                "--evidence-nonce",
                &"A".repeat(16),
                "--evidence-challenge",
                &"B".repeat(16),
            ])),
            Ok(Action::Dw1D6Freeze {
                output: "freeze".into(),
                deep_repository: "/home/mike/Documents/Programming/OS-Project/deepwyrm".into(),
                deep_revision: "a".repeat(40),
                evidence_nonce: "A".repeat(16),
                evidence_challenge: "B".repeat(16),
            })
        );
        assert!(USAGE.contains("tools/pinned-cargo xtask dw1d6 freeze --output"));
    }

    #[test]
    fn wyr1b_freeze_run_and_request_bound_evidence_dispatch() {
        assert_eq!(
            dispatch(&arguments(&["wyr1b", "freeze", "--output", "freeze"])),
            Ok(Action::Wyr1BFreeze("freeze".into()))
        );
        assert_eq!(
            dispatch(&arguments(&["wyr1b", "run", "--request", "request.toml"])),
            Ok(Action::Wyr1BRun("request.toml".into()))
        );
        assert_eq!(
            dispatch(&arguments(&[
                "wyr1b",
                "evidence",
                "--request",
                "request.toml"
            ])),
            Ok(Action::Wyr1BEvidence("request.toml".into()))
        );
        for command in [
            "freeze --output",
            "image --request",
            "inspect --request",
            "run --request",
            "evidence --request",
        ] {
            assert!(USAGE.contains(&format!("tools/pinned-cargo xtask wyr1b {command}")));
        }
        assert!(!USAGE.contains("\n    cargo xtask wyr1b"));
    }

    #[test]
    fn wyr1c1_dispatch_is_product_only_and_unnumbered() {
        assert_eq!(
            dispatch(&arguments(&["wyr1c1", "product", "--output", "product",])),
            Ok(Action::Wyr1C1Product("product".into()))
        );
        assert!(dispatch(&arguments(&["wyr1c1", "run", "--output", "product"])).is_err());
        assert!(dispatch(&arguments(&["wyr1c1", "evidence", "--output", "product"])).is_err());
        assert!(USAGE.contains("tools/pinned-cargo xtask wyr1c1 product --output"));
        assert!(!USAGE.contains("wyr1c1 run"));
        assert!(!USAGE.contains("wyr1c1 evidence"));
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
            &["image", "--request"],
            &["run"],
            &["run", "debug", "--request", "request.toml"],
            &["gdb", "default", "request.toml"],
            &["inspect-image"],
            &["inspect-image", "one", "two"],
            &["audit-i-b"],
            &["audit-i-b", "one"],
            &["audit-i-b", "one", "two", "three"],
            &["test"],
            &["test", "unknown"],
            &["test", "host", "one", "two"],
            &["test", "host", "--nocapture"],
            &["test", "integration", "wyr0"],
            &[
                "test",
                "integration",
                "wyr0",
                "debug",
                "--request",
                "request.toml",
            ],
        ] {
            let failure = dispatch(&arguments(values)).expect_err("invalid syntax was accepted");
            assert_eq!(failure.kind, FailureKind::Usage);
            assert_eq!(failure.exit_code(), 2);
        }
    }
}
