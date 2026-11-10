#[derive(Debug, Eq, PartialEq)]
pub(crate) enum FailureKind {
    TaskFailed,
    Usage,
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct Failure {
    pub(crate) kind: FailureKind,
    pub(crate) message: String,
}

impl Failure {
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
            FailureKind::TaskFailed => 1,
            FailureKind::Usage => 2,
        }
    }
}
