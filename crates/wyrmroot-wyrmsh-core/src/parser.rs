// SPDX-License-Identifier: GPL-3.0-or-later

pub const MAX_LINE_BYTES: usize = 4096;
pub const MAX_ARGUMENTS: usize = 64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ParseError {
    LineTooLong,
    InvalidUtf8,
    Nul,
    TooManyArguments,
    OutputTooLong,
    TrailingBackslash,
    UnsupportedEscape(u8),
    UnterminatedSingleQuote,
    UnterminatedDoubleQuote,
}

/// Half-open byte range in the one unescaped scratch string.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ArgRange {
    pub start: usize,
    pub end: usize,
}

/// Validated UTF-8 arguments, including zero-length quoted arguments.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Arguments<'a> {
    text: &'a str,
    ranges: &'a [ArgRange],
}

impl<'a> Arguments<'a> {
    pub fn len(self) -> usize {
        self.ranges.len()
    }

    pub fn is_empty(self) -> bool {
        self.ranges.is_empty()
    }

    pub fn get(self, index: usize) -> Option<&'a str> {
        let range = self.ranges.get(index)?;
        self.text.get(range.start..range.end)
    }

    pub fn ranges(self) -> &'a [ArgRange] {
        self.ranges
    }

    pub fn scratch(self) -> &'a str {
        self.text
    }

    pub fn iter(self) -> impl ExactSizeIterator<Item = &'a str> + 'a {
        // Only the parser can construct this view; it validates every range.
        self.ranges.iter().map(move |range| {
            self.text
                .get(range.start..range.end)
                .expect("parser validated every argument range")
        })
    }

    pub(crate) fn tail(self) -> Self {
        Self {
            text: self.text,
            ranges: self.ranges.get(1..).unwrap_or(&[]),
        }
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum Quote {
    None,
    Single,
    Double,
}

/// Fixed storage: 4096 scratch bytes and 64 argument descriptors.
pub struct Parser {
    scratch: [u8; MAX_LINE_BYTES],
    ranges: [ArgRange; MAX_ARGUMENTS],
}

impl Default for Parser {
    fn default() -> Self {
        Self::new()
    }
}

impl Parser {
    pub const fn new() -> Self {
        Self {
            scratch: [0; MAX_LINE_BYTES],
            ranges: [ArgRange { start: 0, end: 0 }; MAX_ARGUMENTS],
        }
    }

    /// Scan once after UTF-8/NUL validation. Each iteration consumes at least
    /// one input byte; escapes consume two and never expand the output.
    /// Errors return no argument view, including after a previous successful parse.
    pub fn parse<'a>(&'a mut self, line: &[u8]) -> Result<Arguments<'a>, ParseError> {
        if line.len() > MAX_LINE_BYTES {
            return Err(ParseError::LineTooLong);
        }
        core::str::from_utf8(line).map_err(|_| ParseError::InvalidUtf8)?;
        if line.contains(&0) {
            return Err(ParseError::Nul);
        }
        let mut cursor = 0;
        let mut used = 0;
        let mut count = 0;
        let mut start = None;
        let mut quote = Quote::None;

        while cursor < line.len() {
            let byte = line[cursor];
            cursor += 1;
            if quote == Quote::None && ascii_whitespace(byte) {
                if let Some(begin) = start.take() {
                    self.ranges[count] = ArgRange {
                        start: begin,
                        end: used,
                    };
                    count += 1;
                }
                continue;
            }
            if start.is_none() {
                if count == MAX_ARGUMENTS {
                    return Err(ParseError::TooManyArguments);
                }
                start = Some(used);
            }

            match (quote, byte) {
                (Quote::None, b'\'') => quote = Quote::Single,
                (Quote::Single, b'\'') => quote = Quote::None,
                (Quote::None, b'"') => quote = Quote::Double,
                (Quote::Double, b'"') => quote = Quote::None,
                (Quote::None | Quote::Double, b'\\') => {
                    let next = *line.get(cursor).ok_or(ParseError::TrailingBackslash)?;
                    cursor += 1;
                    let decoded = if quote == Quote::Double {
                        match next {
                            b'\\' | b'"' => next,
                            b'n' => b'\n',
                            b'r' => b'\r',
                            b't' => b'\t',
                            _ => return Err(ParseError::UnsupportedEscape(next)),
                        }
                    } else {
                        next
                    };
                    self.put(&mut used, decoded)?;
                }
                _ => self.put(&mut used, byte)?,
            }
        }
        match quote {
            Quote::Single => return Err(ParseError::UnterminatedSingleQuote),
            Quote::Double => return Err(ParseError::UnterminatedDoubleQuote),
            Quote::None => {}
        }
        if let Some(begin) = start {
            self.ranges[count] = ArgRange {
                start: begin,
                end: used,
            };
            count += 1;
        }
        let text =
            core::str::from_utf8(&self.scratch[..used]).map_err(|_| ParseError::InvalidUtf8)?;
        // Explicitly validate argv boundaries, not just the concatenation.
        for range in &self.ranges[..count] {
            if text.get(range.start..range.end).is_none() {
                return Err(ParseError::InvalidUtf8);
            }
        }
        Ok(Arguments {
            text,
            ranges: &self.ranges[..count],
        })
    }

    fn put(&mut self, used: &mut usize, byte: u8) -> Result<(), ParseError> {
        let slot = self
            .scratch
            .get_mut(*used)
            .ok_or(ParseError::OutputTooLong)?;
        *slot = byte;
        *used += 1;
        Ok(())
    }
}

fn ascii_whitespace(byte: u8) -> bool {
    matches!(byte, b' ' | b'\t' | b'\n' | b'\r' | 0x0b | 0x0c)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scratch_guard_rejects_overflow_without_touching_storage() {
        let mut parser = Parser::new();
        let mut used = MAX_LINE_BYTES;
        assert_eq!(parser.put(&mut used, b'x'), Err(ParseError::OutputTooLong));
        assert_eq!(used, MAX_LINE_BYTES);
        assert!(parser.scratch.iter().all(|byte| *byte == 0));
    }
}
