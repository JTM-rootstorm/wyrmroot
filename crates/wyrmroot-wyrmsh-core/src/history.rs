// SPDX-License-Identifier: GPL-3.0-or-later

use crate::parser::MAX_LINE_BYTES;

pub(crate) const MAX_HISTORY_ENTRIES: usize = 32;
pub(crate) const HISTORY_ARENA_BYTES: usize = 16 * 1024;

#[derive(Clone, Copy, Default)]
struct Entry {
    start: u16,
    len: u16,
}

pub(crate) struct History {
    arena: [u8; HISTORY_ARENA_BYTES],
    entries: [Entry; MAX_HISTORY_ENTRIES],
    head: usize,
    len: usize,
    bytes: usize,
    write: usize,
}

impl History {
    pub(crate) const fn new() -> Self {
        Self {
            arena: [0; HISTORY_ARENA_BYTES],
            entries: [Entry { start: 0, len: 0 }; MAX_HISTORY_ENTRIES],
            head: 0,
            len: 0,
            bytes: 0,
            write: 0,
        }
    }

    pub(crate) const fn len(&self) -> usize {
        self.len
    }

    pub(crate) const fn bytes(&self) -> usize {
        self.bytes
    }

    pub(crate) fn push(&mut self, line: &[u8]) {
        if line.is_empty() || line.len() > HISTORY_ARENA_BYTES {
            return;
        }
        if self.len != 0 && self.entry_equals(self.len - 1, line) {
            return;
        }
        while self.len == MAX_HISTORY_ENTRIES || self.bytes + line.len() > HISTORY_ARENA_BYTES {
            self.evict_oldest();
        }

        let start = self.write;
        for &byte in line {
            self.arena[self.write] = byte;
            self.write = (self.write + 1) % HISTORY_ARENA_BYTES;
        }
        let slot = (self.head + self.len) % MAX_HISTORY_ENTRIES;
        self.entries[slot] = Entry {
            start: start as u16,
            len: line.len() as u16,
        };
        self.len += 1;
        self.bytes += line.len();
    }

    /// Copies the entry indexed from the oldest end into the editor line.
    pub(crate) fn copy_entry(&self, index: usize, output: &mut [u8; MAX_LINE_BYTES]) -> usize {
        let entry = self.entries[(self.head + index) % MAX_HISTORY_ENTRIES];
        let len = usize::from(entry.len);
        let start = usize::from(entry.start);
        for (offset, byte) in output[..len].iter_mut().enumerate() {
            *byte = self.arena[(start + offset) % HISTORY_ARENA_BYTES];
        }
        len
    }

    fn entry_equals(&self, index: usize, line: &[u8]) -> bool {
        let entry = self.entries[(self.head + index) % MAX_HISTORY_ENTRIES];
        if usize::from(entry.len) != line.len() {
            return false;
        }
        let start = usize::from(entry.start);
        line.iter()
            .enumerate()
            .all(|(offset, byte)| self.arena[(start + offset) % HISTORY_ARENA_BYTES] == *byte)
    }

    fn evict_oldest(&mut self) {
        let entry = self.entries[self.head];
        self.bytes -= usize::from(entry.len);
        self.head = (self.head + 1) % MAX_HISTORY_ENTRIES;
        self.len -= 1;
    }
}
