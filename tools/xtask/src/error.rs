const FUTURE_PHASE_MESSAGE: &str =
    "is unavailable in the current WYR0-G3 surface; it requires a later phase";

#[derive(Debug, Eq, PartialEq)]
pub(crate) enum FailureKind {
    Unavailable,
    TaskFailed,
    Usage,
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct Failure {
    pub(crate) kind: FailureKind,
    pub(crate) message: String,
}

impl Failure {
    pub(crate) fn unavailable(command: &str) -> Self {
        Self {
            kind: FailureKind::Unavailable,
            message: format!("'{command}' {FUTURE_PHASE_MESSAGE}"),
        }
    }

    pub(crate) fn task(message: impl Into<String>) -> Self {
        Self {
            kind: FailureKind::TaskFailed,
            message: message.into(),
        }
    }

    pub(crate) fn usage(message: impl Into<String>) -> Self {
        Self {
            kind: FailureKind::Usage,
            message: message.into(),
        }
    }

    pub(crate) const fn exit_code(&self) -> u8 {
        match self.kind {
            FailureKind::Unavailable | FailureKind::TaskFailed => 1,
            FailureKind::Usage => 2,
        }
    }
}
