// SPDX-License-Identifier: GPL-3.0-or-later
//! Bounded WYR1 shell grammar. Parsing produces data; it performs no commands.
//!
//! The caller owns one reusable [`Parser`]. Returned arguments borrow its single
//! scratch buffer, so another parse cannot invalidate arguments still in use.

#![no_std]
#![forbid(unsafe_code)]

mod command;
mod editor;
mod history;
mod input;
mod parser;
mod redraw;

pub use command::{
    Arity, COMMANDS, Command, CommandName, CommandSpec, JobIdError, MAX_PATH_BYTES, UsageError,
    parse_job_id, validate_path,
};
pub use editor::{EditError, EditOutcome, Editor};
pub use input::{InputDecoder, InputError, InputEvent};
pub use parser::{ArgRange, Arguments, MAX_ARGUMENTS, MAX_LINE_BYTES, ParseError, Parser};
pub use redraw::Redraw;
