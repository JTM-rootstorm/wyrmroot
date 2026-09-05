// SPDX-License-Identifier: GPL-3.0-or-later

mod unicode_format;

/// Returns whether WYR1-E admits a scalar as printable command text.
///
/// This excludes Unicode general categories Cc, Cf, Zl, and Zp. The complete
/// Unicode 17.0.0 Cf/Zl/Zp ranges live in the separately licensed data module.
pub fn is_printable_scalar(ch: char) -> bool {
    !ch.is_control() && !unicode_format::is_format_or_line_separator(ch)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InputError {
    InvalidUtf8,
    IncompleteUtf8,
    IncompleteEscape,
    UnsupportedControl,
    UnsupportedEscape,
    EscapeTooLong,
}

/// One byte produces at most one event. `None` means consumed pending input.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InputEvent {
    None,
    Insert(char),
    Left,
    Right,
    Home,
    End,
    Delete,
    Backspace,
    Up,
    Down,
    Submit,
    Cancel,
    Eof,
    Rejected(InputError),
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum Escape {
    None,
    Start,
    Intermediate,
    Csi,
    DiscardStart,
    DiscardIntermediate,
    DiscardCsi,
    DiscardNestedCsi { paste_matched: u8 },
    DiscardSs3,
    String { osc: bool, escaped: bool },
    Paste { matched: usize },
}

/// Incremental decoder with four UTF-8 and twelve ESC/CSI storage bytes.
/// Unsupported control strings and bracketed paste are discarded, never replayed.
pub struct InputDecoder {
    utf8: [u8; 4],
    utf8_len: usize,
    utf8_need: usize,
    escape_bytes: [u8; 12],
    escape_len: usize,
    escape: Escape,
    suppress_lf: bool,
}

impl Default for InputDecoder {
    fn default() -> Self {
        Self::new()
    }
}

impl InputDecoder {
    pub const fn new() -> Self {
        Self {
            utf8: [0; 4],
            utf8_len: 0,
            utf8_need: 0,
            escape_bytes: [0; 12],
            escape_len: 0,
            escape: Escape::None,
            suppress_lf: false,
        }
    }

    pub fn is_pending(&self) -> bool {
        self.utf8_len != 0 || self.escape != Escape::None
    }

    /// Stored pending bytes, excluding finite state/counters for discard modes.
    pub fn pending_bytes(&self) -> usize {
        self.utf8_len + self.escape_len
    }

    pub fn reset(&mut self) {
        self.utf8_len = 0;
        self.utf8_need = 0;
        self.escape_len = 0;
        self.escape = Escape::None;
        self.suppress_lf = false;
    }

    /// End-of-stream is not Enter. Incomplete input is rejected and discarded.
    pub fn finish(&mut self) -> InputEvent {
        let result = if self.utf8_len != 0 {
            InputEvent::Rejected(InputError::IncompleteUtf8)
        } else if self.escape != Escape::None {
            InputEvent::Rejected(InputError::IncompleteEscape)
        } else {
            InputEvent::None
        };
        self.reset();
        result
    }

    pub fn feed(&mut self, byte: u8) -> InputEvent {
        if byte == 3 {
            self.reset();
            return InputEvent::Cancel;
        }
        if self.suppress_lf && byte == b'\n' {
            self.suppress_lf = false;
            return InputEvent::None;
        }
        self.suppress_lf = byte == b'\r';

        // Discard modes consume even Enter; Ctrl-C above is the explicit abort.
        if let Escape::String { osc, escaped } = self.escape {
            if (osc && byte == 7) || (escaped && byte == b'\\') {
                self.end_escape();
            } else {
                self.escape = Escape::String {
                    osc,
                    escaped: byte == 27,
                };
            }
            return InputEvent::None;
        }
        if let Escape::Paste { matched } = self.escape {
            const END: &[u8] = b"\x1b[201~";
            let next = if byte == END[matched] {
                matched + 1
            } else {
                usize::from(byte == END[0])
            };
            if next == END.len() {
                self.end_escape();
            } else {
                self.escape = Escape::Paste { matched: next };
            }
            return InputEvent::None;
        }

        if matches!(byte, b'\r' | b'\n') && self.is_pending() {
            let error = if self.utf8_len != 0 {
                InputError::IncompleteUtf8
            } else {
                InputError::IncompleteEscape
            };
            self.utf8_len = 0;
            self.utf8_need = 0;
            self.end_escape();
            return InputEvent::Rejected(error);
        }
        if self.escape != Escape::None {
            return self.escape_byte(byte);
        }

        if self.utf8_len != 0 {
            if !(0x80..=0xbf).contains(&byte) {
                self.utf8_len = 0;
                self.utf8_need = 0;
                // Keep an ESC introducer quarantined even after malformed UTF-8.
                if byte == 27 {
                    self.begin_escape();
                }
                return InputEvent::Rejected(InputError::InvalidUtf8);
            }
            self.utf8[self.utf8_len] = byte;
            self.utf8_len += 1;
            if self.utf8_len != self.utf8_need {
                return InputEvent::None;
            }
            let scalar = core::str::from_utf8(&self.utf8[..self.utf8_len])
                .ok()
                .and_then(|text| text.chars().next());
            self.utf8_len = 0;
            self.utf8_need = 0;
            return match scalar {
                Some(ch) if is_printable_scalar(ch) => InputEvent::Insert(ch),
                Some(_) => InputEvent::Rejected(InputError::UnsupportedControl),
                None => InputEvent::Rejected(InputError::InvalidUtf8),
            };
        }

        match byte {
            27 => {
                self.begin_escape();
                InputEvent::None
            }
            8 | 127 => InputEvent::Backspace,
            4 => InputEvent::Eof,
            b'\r' | b'\n' => InputEvent::Submit,
            b'\t' => InputEvent::Insert(' '),
            0x20..=0x7e => InputEvent::Insert(char::from(byte)),
            0xc2..=0xf4 => {
                self.utf8[0] = byte;
                self.utf8_len = 1;
                self.utf8_need = if byte < 0xe0 {
                    2
                } else if byte < 0xf0 {
                    3
                } else {
                    4
                };
                InputEvent::None
            }
            0..=0x1f => InputEvent::Rejected(InputError::UnsupportedControl),
            _ => InputEvent::Rejected(InputError::InvalidUtf8),
        }
    }

    fn begin_escape(&mut self) {
        self.escape = Escape::Start;
        self.escape_bytes[0] = 27;
        self.escape_len = 1;
    }

    fn end_escape(&mut self) {
        self.escape = Escape::None;
        self.escape_len = 0;
    }

    fn escape_byte(&mut self, byte: u8) -> InputEvent {
        if self.escape == Escape::DiscardStart {
            match byte {
                27 => {}
                b'[' => self.escape = Escape::DiscardNestedCsi { paste_matched: 0 },
                b'O' => self.escape = Escape::DiscardSs3,
                b']' | b'P' | b'X' | b'^' | b'_' => {
                    self.escape = Escape::String {
                        osc: byte == b']',
                        escaped: false,
                    };
                }
                0x20..=0x2f => self.escape = Escape::DiscardIntermediate,
                0x30..=0x7e => self.end_escape(),
                _ => {}
            }
            return InputEvent::None;
        }
        if let Escape::DiscardNestedCsi { paste_matched } = self.escape {
            if byte == 27 {
                self.escape = Escape::DiscardStart;
                return InputEvent::None;
            }

            const PASTE_START: &[u8] = b"200~";
            let matched = usize::from(paste_matched);
            let next = if matched < PASTE_START.len() && byte == PASTE_START[matched] {
                paste_matched + 1
            } else {
                u8::MAX
            };
            if (0x40..=0x7e).contains(&byte) {
                self.end_escape();
                if usize::from(next) == PASTE_START.len() {
                    self.escape = Escape::Paste { matched: 0 };
                }
            } else {
                self.escape = Escape::DiscardNestedCsi {
                    paste_matched: next,
                };
            }
            return InputEvent::None;
        }
        if self.escape == Escape::DiscardIntermediate {
            if byte == 27 {
                self.escape = Escape::DiscardStart;
            } else if (0x30..=0x7e).contains(&byte) {
                self.end_escape();
            }
            return InputEvent::None;
        }
        if matches!(self.escape, Escape::DiscardCsi | Escape::DiscardSs3) {
            if byte == 27 {
                self.escape = Escape::DiscardStart;
            } else if (0x40..=0x7e).contains(&byte) {
                self.end_escape();
            }
            return InputEvent::None;
        }
        if byte == 27 {
            self.begin_escape();
            return InputEvent::Rejected(InputError::IncompleteEscape);
        }
        if self.escape_len == self.escape_bytes.len() {
            self.escape = if self.escape == Escape::Intermediate {
                Escape::DiscardIntermediate
            } else {
                Escape::DiscardCsi
            };
            self.escape_len = 0;
            let final_byte = if self.escape == Escape::DiscardIntermediate {
                (0x30..=0x7e).contains(&byte)
            } else {
                (0x40..=0x7e).contains(&byte)
            };
            if final_byte {
                self.end_escape();
            }
            return InputEvent::Rejected(InputError::EscapeTooLong);
        }
        self.escape_bytes[self.escape_len] = byte;
        self.escape_len += 1;

        match self.escape {
            Escape::Start => match byte {
                b'[' => {
                    self.escape = Escape::Csi;
                    InputEvent::None
                }
                b'O' => {
                    self.escape = Escape::DiscardSs3;
                    self.escape_len = 0;
                    InputEvent::Rejected(InputError::UnsupportedEscape)
                }
                b']' | b'P' | b'X' | b'^' | b'_' => {
                    self.escape = Escape::String {
                        osc: byte == b']',
                        escaped: false,
                    };
                    self.escape_len = 0;
                    InputEvent::Rejected(InputError::UnsupportedEscape)
                }
                0x20..=0x2f => {
                    self.escape = Escape::Intermediate;
                    InputEvent::None
                }
                _ => {
                    self.end_escape();
                    InputEvent::Rejected(InputError::UnsupportedEscape)
                }
            },
            Escape::Intermediate => {
                if (0x20..=0x2f).contains(&byte) {
                    InputEvent::None
                } else if (0x30..=0x7e).contains(&byte) {
                    self.end_escape();
                    InputEvent::Rejected(InputError::UnsupportedEscape)
                } else {
                    self.escape = Escape::DiscardIntermediate;
                    self.escape_len = 0;
                    InputEvent::Rejected(InputError::UnsupportedEscape)
                }
            }
            Escape::Csi => {
                if (0x40..=0x7e).contains(&byte) {
                    let sequence = &self.escape_bytes[2..self.escape_len];
                    let event = match sequence {
                        b"A" => InputEvent::Up,
                        b"B" => InputEvent::Down,
                        b"C" => InputEvent::Right,
                        b"D" => InputEvent::Left,
                        b"H" | b"1~" => InputEvent::Home,
                        b"F" | b"4~" => InputEvent::End,
                        b"3~" => InputEvent::Delete,
                        _ => InputEvent::Rejected(InputError::UnsupportedEscape),
                    };
                    let paste = sequence == b"200~";
                    self.end_escape();
                    if paste {
                        self.escape = Escape::Paste { matched: 0 };
                    }
                    event
                } else if (0x20..=0x3f).contains(&byte) {
                    InputEvent::None
                } else {
                    self.escape = Escape::DiscardCsi;
                    self.escape_len = 0;
                    InputEvent::Rejected(InputError::UnsupportedEscape)
                }
            }
            _ => InputEvent::None,
        }
    }
}
