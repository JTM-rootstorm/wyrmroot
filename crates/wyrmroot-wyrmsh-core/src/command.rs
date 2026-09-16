// SPDX-License-Identifier: GPL-3.0-or-later

use core::num::NonZeroU64;

use crate::Arguments;

/// Current WRLJ launch-path bound, also within the bootfs archive name bound.
pub const MAX_PATH_BYTES: usize = 256;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CommandName {
    Help,
    Echo,
    Clear,
    Exit,
    Services,
    Tasks,
    Status,
    Run,
    Spawn,
    Wait,
    Terminate,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Arity {
    Exact(usize),
    AtLeast(usize),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CommandSpec {
    pub name: CommandName,
    pub spelling: &'static str,
    pub usage: &'static str,
    /// Operand count, excluding the command name.
    pub arity: Arity,
}

/// The same fixed metadata supports classification and the future help builtin.
pub const COMMANDS: [CommandSpec; 11] = [
    CommandSpec {
        name: CommandName::Help,
        spelling: "help",
        usage: "help",
        arity: Arity::Exact(0),
    },
    CommandSpec {
        name: CommandName::Echo,
        spelling: "echo",
        usage: "echo [args...]",
        arity: Arity::AtLeast(0),
    },
    CommandSpec {
        name: CommandName::Clear,
        spelling: "clear",
        usage: "clear",
        arity: Arity::Exact(0),
    },
    CommandSpec {
        name: CommandName::Exit,
        spelling: "exit",
        usage: "exit",
        arity: Arity::Exact(0),
    },
    CommandSpec {
        name: CommandName::Services,
        spelling: "services",
        usage: "services",
        arity: Arity::Exact(0),
    },
    CommandSpec {
        name: CommandName::Tasks,
        spelling: "tasks",
        usage: "tasks",
        arity: Arity::Exact(0),
    },
    CommandSpec {
        name: CommandName::Status,
        spelling: "status",
        usage: "status",
        arity: Arity::Exact(0),
    },
    CommandSpec {
        name: CommandName::Run,
        spelling: "run",
        usage: "run <bootfs-path> [args...]",
        arity: Arity::AtLeast(1),
    },
    CommandSpec {
        name: CommandName::Spawn,
        spelling: "spawn",
        usage: "spawn <bootfs-path> [args...]",
        arity: Arity::AtLeast(1),
    },
    CommandSpec {
        name: CommandName::Wait,
        spelling: "wait",
        usage: "wait <job-id>",
        arity: Arity::Exact(1),
    },
    CommandSpec {
        name: CommandName::Terminate,
        spelling: "terminate",
        usage: "terminate <job-id>",
        arity: Arity::Exact(1),
    },
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum JobIdError {
    Noncanonical,
    Overflow,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UsageError {
    UnknownCommand,
    ArgumentCount { command: CommandName, actual: usize },
    InvalidPath,
    InvalidJobId(JobIdError),
}

/// Data for the future runtime adapter. No variant contains handles or executes I/O.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Command<'a> {
    Empty,
    Help,
    Echo(Arguments<'a>),
    Clear,
    Exit,
    Services,
    Tasks,
    Status,
    /// `argv` includes the path as child `argv[0]`, without the shell command name.
    Run {
        path: &'a str,
        argv: Arguments<'a>,
    },
    /// Background transport uses zero streams; that policy belongs to the adapter.
    Spawn {
        path: &'a str,
        argv: Arguments<'a>,
    },
    Wait(NonZeroU64),
    Terminate(NonZeroU64),
}

impl<'a> Arguments<'a> {
    pub fn command(self) -> Result<Command<'a>, UsageError> {
        let Some(name) = self.get(0) else {
            return Ok(Command::Empty);
        };
        let spec = COMMANDS
            .iter()
            .find(|spec| spec.spelling == name)
            .ok_or(UsageError::UnknownCommand)?;
        let operands = self.tail();
        let valid = match spec.arity {
            Arity::Exact(n) => operands.len() == n,
            Arity::AtLeast(n) => operands.len() >= n,
        };
        if !valid {
            return Err(UsageError::ArgumentCount {
                command: spec.name,
                actual: operands.len(),
            });
        }
        Ok(match spec.name {
            CommandName::Help => Command::Help,
            CommandName::Echo => Command::Echo(operands),
            CommandName::Clear => Command::Clear,
            CommandName::Exit => Command::Exit,
            CommandName::Services => Command::Services,
            CommandName::Tasks => Command::Tasks,
            CommandName::Status => Command::Status,
            CommandName::Run | CommandName::Spawn => {
                let path = operands.get(0).ok_or(UsageError::InvalidPath)?;
                validate_path(path)?;
                if spec.name == CommandName::Run {
                    Command::Run {
                        path,
                        argv: operands,
                    }
                } else {
                    Command::Spawn {
                        path,
                        argv: operands,
                    }
                }
            }
            CommandName::Wait | CommandName::Terminate => {
                let value = operands
                    .get(0)
                    .ok_or(UsageError::InvalidJobId(JobIdError::Noncanonical))?;
                let id = parse_job_id(value).map_err(UsageError::InvalidJobId)?;
                if spec.name == CommandName::Wait {
                    Command::Wait(id)
                } else {
                    Command::Terminate(id)
                }
            }
        })
    }
}

/// Canonical syntax compatible with both current WRLJ and bootfs names.
/// This does not establish existence, executable identity, or launch authority.
pub fn validate_path(path: &str) -> Result<(), UsageError> {
    let bytes = path.as_bytes();
    if bytes.is_empty()
        || bytes.len() > MAX_PATH_BYTES
        || !bytes.is_ascii()
        || bytes.contains(&0)
        || bytes.contains(&b'\\')
        || path == "TRAILER!!!"
        || path.split('/').any(|part| matches!(part, "" | "." | ".."))
    {
        return Err(UsageError::InvalidPath);
    }
    Ok(())
}

pub fn parse_job_id(value: &str) -> Result<NonZeroU64, JobIdError> {
    let bytes = value.as_bytes();
    if !matches!(bytes.first(), Some(b'1'..=b'9')) || !bytes.iter().all(u8::is_ascii_digit) {
        return Err(JobIdError::Noncanonical);
    }
    let mut id = 0u64;
    for byte in bytes {
        id = id
            .checked_mul(10)
            .and_then(|n| n.checked_add(u64::from(byte - b'0')))
            .ok_or(JobIdError::Overflow)?;
    }
    NonZeroU64::new(id).ok_or(JobIdError::Noncanonical)
}
