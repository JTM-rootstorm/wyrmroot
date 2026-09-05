// SPDX-License-Identifier: GPL-3.0-or-later

const PROMPT_AND_ERASE: &[u8] = b"\r\x1b[2Kwyrmsh> ";
const VISIBLE_SCALARS: usize = 71;

/// One deterministic single-row editor frame, emitted incrementally.
///
/// The terminal model is fixed at 80 columns. The eight-column prompt and at
/// most 71 scalar-width characters leave the last column unused. Long lines
/// use a cursor-centered window, clamped at the start and end of the full line.
/// Every Unicode scalar is treated as one display column; grapheme and `wcwidth`
/// behavior are intentionally outside this model.
pub struct Redraw<'a> {
    line: &'a [u8],
    visible_start: usize,
    visible_end: usize,
    cursor_back: [u8; 5],
    cursor_back_len: usize,
    emitted: usize,
}

impl<'a> Redraw<'a> {
    pub(crate) fn new(line: &'a str, cursor: usize) -> Self {
        let cursor_scalars = line[..cursor].chars().count();
        let total_scalars = line.chars().count();
        let visible_start_scalar = cursor_scalars
            .saturating_sub(VISIBLE_SCALARS / 2)
            .min(total_scalars.saturating_sub(VISIBLE_SCALARS));
        let visible_start = byte_at_scalar(line, visible_start_scalar);
        let visible_end = byte_at_scalar_from(line, visible_start, VISIBLE_SCALARS);
        let visible_scalars = line[visible_start..visible_end].chars().count();
        let cursor_in_window = cursor_scalars - visible_start_scalar;
        let back = visible_scalars - cursor_in_window;
        let (cursor_back, cursor_back_len) = cursor_back_sequence(back);
        Self {
            line: line.as_bytes(),
            visible_start,
            visible_end,
            cursor_back,
            cursor_back_len,
            emitted: 0,
        }
    }

    /// Reads the next bytes of this frame. Empty output never advances it.
    pub fn read(&mut self, output: &mut [u8]) -> usize {
        if output.is_empty() {
            return 0;
        }
        let visible = &self.line[self.visible_start..self.visible_end];
        let segments = [
            PROMPT_AND_ERASE,
            visible,
            &self.cursor_back[..self.cursor_back_len],
        ];
        let mut skipped = self.emitted;
        let mut written = 0;
        for segment in segments {
            if skipped >= segment.len() {
                skipped -= segment.len();
                continue;
            }
            let source = &segment[skipped..];
            let count = core::cmp::min(source.len(), output.len() - written);
            output[written..written + count].copy_from_slice(&source[..count]);
            written += count;
            skipped = 0;
            if written == output.len() {
                break;
            }
        }
        self.emitted += written;
        written
    }
}

fn byte_at_scalar(text: &str, scalar: usize) -> usize {
    text.char_indices()
        .nth(scalar)
        .map_or(text.len(), |(index, _)| index)
}

fn byte_at_scalar_from(text: &str, start: usize, count: usize) -> usize {
    text[start..]
        .char_indices()
        .nth(count)
        .map_or(text.len(), |(index, _)| start + index)
}

fn cursor_back_sequence(columns: usize) -> ([u8; 5], usize) {
    if columns == 0 {
        return ([0; 5], 0);
    }
    let mut sequence = [0; 5];
    sequence[0] = 27;
    sequence[1] = b'[';
    if columns >= 10 {
        sequence[2] = b'0' + (columns / 10) as u8;
        sequence[3] = b'0' + (columns % 10) as u8;
        sequence[4] = b'D';
        (sequence, 5)
    } else {
        sequence[2] = b'0' + columns as u8;
        sequence[3] = b'D';
        (sequence, 4)
    }
}
