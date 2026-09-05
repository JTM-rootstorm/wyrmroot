// SPDX-License-Identifier: GPL-3.0-or-later

use crate::history::History;
use crate::input::{InputError, InputEvent, is_printable_scalar};
use crate::parser::MAX_LINE_BYTES;
use crate::redraw::Redraw;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EditError {
    Input(InputError),
    LineTooLong,
    UnsupportedCharacter,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EditOutcome {
    Unchanged,
    Changed,
    Submitted,
    Cancelled,
    Eof,
    Rejected(EditError),
    Busy,
}

/// Allocation-free WYR1 line editor with immutable committed history.
pub struct Editor {
    line: [u8; MAX_LINE_BYTES],
    len: usize,
    cursor: usize,
    history: History,
    draft: [u8; MAX_LINE_BYTES],
    draft_len: usize,
    draft_cursor: usize,
    browsing: Option<usize>,
    submission_pending: bool,
}

impl Default for Editor {
    fn default() -> Self {
        Self::new()
    }
}

impl Editor {
    pub const fn new() -> Self {
        Self {
            line: [0; MAX_LINE_BYTES],
            len: 0,
            cursor: 0,
            history: History::new(),
            draft: [0; MAX_LINE_BYTES],
            draft_len: 0,
            draft_cursor: 0,
            browsing: None,
            submission_pending: false,
        }
    }

    pub fn apply(&mut self, event: InputEvent) -> EditOutcome {
        if self.submission_pending {
            return EditOutcome::Busy;
        }
        match event {
            InputEvent::None => EditOutcome::Unchanged,
            InputEvent::Insert(ch) => self.insert(ch),
            InputEvent::Left => self.left(),
            InputEvent::Right => self.right(),
            InputEvent::Home => self.set_cursor(0),
            InputEvent::End => self.set_cursor(self.len),
            InputEvent::Delete => self.delete(),
            InputEvent::Backspace => self.backspace(),
            InputEvent::Up => self.up(),
            InputEvent::Down => self.down(),
            InputEvent::Submit => {
                self.submission_pending = true;
                EditOutcome::Submitted
            }
            InputEvent::Cancel => {
                self.clear_draft();
                EditOutcome::Cancelled
            }
            InputEvent::Eof if self.len == 0 => EditOutcome::Eof,
            InputEvent::Eof => EditOutcome::Unchanged,
            InputEvent::Rejected(error) => EditOutcome::Rejected(EditError::Input(error)),
        }
    }

    pub fn line(&self) -> &str {
        // All mutation paths insert complete Rust chars or copy valid editor lines.
        core::str::from_utf8(&self.line[..self.len]).unwrap_or("")
    }

    pub const fn cursor(&self) -> usize {
        self.cursor
    }

    /// Commits and clears the line currently frozen by `Submitted`.
    pub fn accept_submission(&mut self) {
        if !self.submission_pending {
            return;
        }
        self.history.push(&self.line[..self.len]);
        self.submission_pending = false;
        self.clear_draft();
    }

    pub const fn history_len(&self) -> usize {
        self.history.len()
    }

    pub const fn history_bytes(&self) -> usize {
        self.history.bytes()
    }

    pub fn redraw(&self) -> Redraw<'_> {
        Redraw::new(self.line(), self.cursor)
    }

    fn insert(&mut self, ch: char) -> EditOutcome {
        if !is_printable_scalar(ch) {
            return EditOutcome::Rejected(EditError::UnsupportedCharacter);
        }
        let mut encoded = [0; 4];
        let bytes = ch.encode_utf8(&mut encoded).as_bytes();
        if bytes.len() > MAX_LINE_BYTES - self.len {
            return EditOutcome::Rejected(EditError::LineTooLong);
        }
        self.line
            .copy_within(self.cursor..self.len, self.cursor + bytes.len());
        self.line[self.cursor..self.cursor + bytes.len()].copy_from_slice(bytes);
        self.cursor += bytes.len();
        self.len += bytes.len();
        EditOutcome::Changed
    }

    fn left(&mut self) -> EditOutcome {
        let Some(ch) = self
            .line()
            .get(..self.cursor)
            .expect("editor cursor is a valid character boundary")
            .chars()
            .next_back()
        else {
            return EditOutcome::Unchanged;
        };
        self.cursor -= ch.len_utf8();
        EditOutcome::Changed
    }

    fn right(&mut self) -> EditOutcome {
        let Some(ch) = self
            .line()
            .get(self.cursor..)
            .expect("editor cursor is a valid character boundary")
            .chars()
            .next()
        else {
            return EditOutcome::Unchanged;
        };
        self.cursor += ch.len_utf8();
        EditOutcome::Changed
    }

    fn set_cursor(&mut self, cursor: usize) -> EditOutcome {
        if self.cursor == cursor {
            EditOutcome::Unchanged
        } else {
            self.cursor = cursor;
            EditOutcome::Changed
        }
    }

    fn delete(&mut self) -> EditOutcome {
        let Some(ch) = self
            .line()
            .get(self.cursor..)
            .expect("editor cursor is a valid character boundary")
            .chars()
            .next()
        else {
            return EditOutcome::Unchanged;
        };
        let end = self.cursor + ch.len_utf8();
        self.line.copy_within(end..self.len, self.cursor);
        self.len -= ch.len_utf8();
        EditOutcome::Changed
    }

    fn backspace(&mut self) -> EditOutcome {
        let Some(ch) = self
            .line()
            .get(..self.cursor)
            .expect("editor cursor is a valid character boundary")
            .chars()
            .next_back()
        else {
            return EditOutcome::Unchanged;
        };
        let start = self.cursor - ch.len_utf8();
        self.line.copy_within(self.cursor..self.len, start);
        self.cursor = start;
        self.len -= ch.len_utf8();
        EditOutcome::Changed
    }

    fn up(&mut self) -> EditOutcome {
        if self.history.len() == 0 {
            return EditOutcome::Unchanged;
        }
        let age = match self.browsing {
            None => {
                self.draft[..self.len].copy_from_slice(&self.line[..self.len]);
                self.draft_len = self.len;
                self.draft_cursor = self.cursor;
                0
            }
            Some(age) if age + 1 < self.history.len() => age + 1,
            Some(_) => return EditOutcome::Unchanged,
        };
        self.browsing = Some(age);
        let index = self.history.len() - 1 - age;
        self.len = self.history.copy_entry(index, &mut self.line);
        self.cursor = self.len;
        EditOutcome::Changed
    }

    fn down(&mut self) -> EditOutcome {
        match self.browsing {
            None => EditOutcome::Unchanged,
            Some(age) if age != 0 => {
                let next_age = age - 1;
                self.browsing = Some(next_age);
                let index = self.history.len() - 1 - next_age;
                self.len = self.history.copy_entry(index, &mut self.line);
                self.cursor = self.len;
                EditOutcome::Changed
            }
            Some(_) => {
                self.line[..self.draft_len].copy_from_slice(&self.draft[..self.draft_len]);
                self.len = self.draft_len;
                self.cursor = self.draft_cursor;
                self.browsing = None;
                EditOutcome::Changed
            }
        }
    }

    fn clear_draft(&mut self) {
        self.len = 0;
        self.cursor = 0;
        self.draft_len = 0;
        self.draft_cursor = 0;
        self.browsing = None;
    }
}
