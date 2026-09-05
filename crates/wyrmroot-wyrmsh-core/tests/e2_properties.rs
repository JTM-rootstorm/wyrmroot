// SPDX-License-Identifier: GPL-3.0-or-later

use wyrmroot_wyrmsh_core::{
    EditError, EditOutcome, Editor, InputDecoder, InputEvent, MAX_LINE_BYTES,
};

const HISTORY_ENTRIES: usize = 32;
const HISTORY_BYTES: usize = 16 * 1024;
const FRAME_BYTES: usize = 302;
const VISIBLE_SCALARS: usize = 71;
const RANDOM_STREAM_SEED: u64 = 0xe2d0_5ca1_a7e5_2026;

struct XorShift64(u64);

impl XorShift64 {
    fn next(&mut self) -> u64 {
        let mut value = self.0;
        value ^= value << 13;
        value ^= value >> 7;
        value ^= value << 17;
        self.0 = value;
        value
    }

    fn byte(&mut self) -> u8 {
        self.next().to_le_bytes()[0]
    }

    fn index(&mut self, bound: usize) -> usize {
        (self.next() as usize) % bound
    }
}

#[derive(Default)]
struct ReferenceEditor {
    line: Vec<char>,
    cursor: usize,
    history: Vec<Vec<char>>,
    draft: Vec<char>,
    draft_cursor: usize,
    browsing: Option<usize>,
    submission_pending: bool,
}

impl ReferenceEditor {
    fn apply(&mut self, event: InputEvent) -> EditOutcome {
        if self.submission_pending {
            return EditOutcome::Busy;
        }
        match event {
            InputEvent::None => EditOutcome::Unchanged,
            InputEvent::Insert(ch) => {
                if self.line_bytes() + ch.len_utf8() > MAX_LINE_BYTES {
                    return EditOutcome::Rejected(EditError::LineTooLong);
                }
                self.line.insert(self.cursor, ch);
                self.cursor += 1;
                EditOutcome::Changed
            }
            InputEvent::Left if self.cursor != 0 => {
                self.cursor -= 1;
                EditOutcome::Changed
            }
            InputEvent::Left => EditOutcome::Unchanged,
            InputEvent::Right if self.cursor != self.line.len() => {
                self.cursor += 1;
                EditOutcome::Changed
            }
            InputEvent::Right => EditOutcome::Unchanged,
            InputEvent::Home if self.cursor != 0 => {
                self.cursor = 0;
                EditOutcome::Changed
            }
            InputEvent::Home => EditOutcome::Unchanged,
            InputEvent::End if self.cursor != self.line.len() => {
                self.cursor = self.line.len();
                EditOutcome::Changed
            }
            InputEvent::End => EditOutcome::Unchanged,
            InputEvent::Delete if self.cursor != self.line.len() => {
                self.line.remove(self.cursor);
                EditOutcome::Changed
            }
            InputEvent::Delete => EditOutcome::Unchanged,
            InputEvent::Backspace if self.cursor != 0 => {
                self.cursor -= 1;
                self.line.remove(self.cursor);
                EditOutcome::Changed
            }
            InputEvent::Backspace => EditOutcome::Unchanged,
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
            InputEvent::Eof if self.line.is_empty() => EditOutcome::Eof,
            InputEvent::Eof => EditOutcome::Unchanged,
            InputEvent::Rejected(error) => EditOutcome::Rejected(EditError::Input(error)),
        }
    }

    fn accept_submission(&mut self) {
        if !self.submission_pending {
            return;
        }
        if !self.line.is_empty() && self.history.last() != Some(&self.line) {
            self.history.push(self.line.clone());
            while self.history.len() > HISTORY_ENTRIES || self.history_bytes() > HISTORY_BYTES {
                self.history.remove(0);
            }
        }
        self.submission_pending = false;
        self.clear_draft();
    }

    fn up(&mut self) -> EditOutcome {
        if self.history.is_empty() {
            return EditOutcome::Unchanged;
        }
        let age = match self.browsing {
            None => {
                self.draft.clone_from(&self.line);
                self.draft_cursor = self.cursor;
                0
            }
            Some(age) if age + 1 < self.history.len() => age + 1,
            Some(_) => return EditOutcome::Unchanged,
        };
        self.browsing = Some(age);
        self.line = self.history[self.history.len() - 1 - age].clone();
        self.cursor = self.line.len();
        EditOutcome::Changed
    }

    fn down(&mut self) -> EditOutcome {
        match self.browsing {
            None => EditOutcome::Unchanged,
            Some(age) if age != 0 => {
                let age = age - 1;
                self.browsing = Some(age);
                self.line = self.history[self.history.len() - 1 - age].clone();
                self.cursor = self.line.len();
                EditOutcome::Changed
            }
            Some(_) => {
                self.line.clone_from(&self.draft);
                self.cursor = self.draft_cursor;
                self.browsing = None;
                EditOutcome::Changed
            }
        }
    }

    fn clear_draft(&mut self) {
        self.line.clear();
        self.cursor = 0;
        self.draft.clear();
        self.draft_cursor = 0;
        self.browsing = None;
    }

    fn line_bytes(&self) -> usize {
        self.line.iter().map(|ch| ch.len_utf8()).sum()
    }

    fn history_bytes(&self) -> usize {
        self.history.iter().flatten().map(|ch| ch.len_utf8()).sum()
    }

    fn line_string(&self) -> String {
        self.line.iter().collect()
    }

    fn cursor_bytes(&self) -> usize {
        self.line[..self.cursor]
            .iter()
            .map(|ch| ch.len_utf8())
            .sum()
    }
}

fn assert_state(editor: &Editor, reference: &ReferenceEditor) {
    assert_eq!(editor.line(), reference.line_string());
    assert_eq!(editor.cursor(), reference.cursor_bytes());
    assert!(editor.line().is_char_boundary(editor.cursor()));
    assert!(editor.line().len() <= MAX_LINE_BYTES);
    assert_eq!(editor.history_len(), reference.history.len());
    assert_eq!(editor.history_bytes(), reference.history_bytes());
    assert!(editor.history_len() <= HISTORY_ENTRIES);
    assert!(editor.history_bytes() <= HISTORY_BYTES);
}

fn apply_event(
    editor: &mut Editor,
    reference: &mut ReferenceEditor,
    event: InputEvent,
) -> EditOutcome {
    let actual = editor.apply(event);
    let expected = reference.apply(event);
    assert_eq!(actual, expected, "event {event:?}");
    assert_state(editor, reference);
    actual
}

fn accept_submission(editor: &mut Editor, reference: &mut ReferenceEditor) {
    editor.accept_submission();
    reference.accept_submission();
    assert_state(editor, reference);
}

fn expected_frame(reference: &ReferenceEditor) -> Vec<u8> {
    let total = reference.line.len();
    let start = reference
        .cursor
        .saturating_sub(VISIBLE_SCALARS / 2)
        .min(total.saturating_sub(VISIBLE_SCALARS));
    let end = core::cmp::min(start + VISIBLE_SCALARS, total);
    let back = end - reference.cursor;

    let mut frame = b"\r\x1b[2Kwyrmsh> ".to_vec();
    for ch in &reference.line[start..end] {
        let mut encoded = [0; 4];
        frame.extend_from_slice(ch.encode_utf8(&mut encoded).as_bytes());
    }
    if back != 0 {
        frame.extend_from_slice(format!("\x1b[{back}D").as_bytes());
    }
    assert!(frame.len() <= FRAME_BYTES);
    frame
}

fn render(editor: &Editor, chunk: usize) -> Vec<u8> {
    assert!(chunk != 0);
    let mut redraw = editor.redraw();
    assert_eq!(redraw.read(&mut []), 0);

    let mut result = Vec::new();
    let mut output = vec![0; chunk];
    let mut exhausted = false;
    for _ in 0..=FRAME_BYTES {
        let count = redraw.read(&mut output);
        assert!(count <= chunk);
        if count == 0 {
            exhausted = true;
            break;
        }
        result.extend_from_slice(&output[..count]);
        assert!(result.len() <= FRAME_BYTES);
    }
    assert!(exhausted, "redraw did not terminate within its frame bound");
    assert_eq!(redraw.read(&mut output), 0);
    assert_eq!(redraw.read(&mut []), 0);
    result
}

fn feed_chunks(
    decoder: &mut InputDecoder,
    editor: &mut Editor,
    reference: &mut ReferenceEditor,
    bytes: &[u8],
    chunks: &[usize],
    accept_submissions: bool,
) -> (Vec<InputEvent>, Vec<EditOutcome>) {
    let mut offset = 0;
    let mut events = Vec::with_capacity(bytes.len());
    let mut outcomes = Vec::with_capacity(bytes.len());
    for &chunk in chunks {
        assert!(offset + chunk <= bytes.len());
        for &byte in &bytes[offset..offset + chunk] {
            let event = decoder.feed(byte);
            assert!(decoder.pending_bytes() <= 16);
            let outcome = apply_event(editor, reference, event);
            events.push(event);
            outcomes.push(outcome);
            if accept_submissions && outcome == EditOutcome::Submitted {
                accept_submission(editor, reference);
            }
        }
        offset += chunk;
    }
    assert_eq!(offset, bytes.len());
    (events, outcomes)
}

#[derive(Debug, Eq, PartialEq)]
struct Trace {
    events: Vec<InputEvent>,
    outcomes: Vec<EditOutcome>,
    line: String,
    cursor: usize,
    history_len: usize,
    history_bytes: usize,
    pending: bool,
    pending_bytes: usize,
    frame: Vec<u8>,
}

fn trace(bytes: &[u8], chunks: &[usize]) -> Trace {
    let mut decoder = InputDecoder::new();
    let mut editor = Editor::new();
    let mut reference = ReferenceEditor::default();
    let (events, outcomes) = feed_chunks(
        &mut decoder,
        &mut editor,
        &mut reference,
        bytes,
        chunks,
        true,
    );
    let frame = render(&editor, 1 + bytes.len() % 17);
    assert_eq!(frame, expected_frame(&reference));
    Trace {
        events,
        outcomes,
        line: editor.line().to_owned(),
        cursor: editor.cursor(),
        history_len: editor.history_len(),
        history_bytes: editor.history_bytes(),
        pending: decoder.is_pending(),
        pending_bytes: decoder.pending_bytes(),
        frame,
    }
}

fn random_chunks(len: usize, random: &mut XorShift64) -> Vec<usize> {
    let mut chunks = vec![0];
    let mut remaining = len;
    while remaining != 0 {
        if random.next() & 3 == 0 {
            chunks.push(0);
        }
        let chunk = 1 + random.index(core::cmp::min(remaining, 19));
        chunks.push(chunk);
        remaining -= chunk;
    }
    chunks.push(0);
    chunks
}

#[test]
fn arbitrary_byte_streams_are_fragment_invariant_and_bounded() {
    const BIASED: &[u8] = b"abcXYZ09 \t\r\n\x03\x04\x08\x1b[]OPX^_~;\x7f\x80\xbf\xc2\xe2\xf0\xff";
    let mut random = XorShift64(RANDOM_STREAM_SEED);

    for len in 0..=192 {
        for style in 0..2 {
            let mut bytes = vec![0; len];
            for byte in &mut bytes {
                *byte = if style == 0 {
                    random.byte()
                } else {
                    BIASED[random.index(BIASED.len())]
                };
            }
            let baseline = trace(&bytes, &[bytes.len()]);
            assert_eq!(trace(&bytes, &vec![1; bytes.len()]), baseline);
            let chunks = random_chunks(bytes.len(), &mut random);
            assert_eq!(trace(&bytes, &chunks), baseline);
        }
    }

    let all_bytes: Vec<u8> = (0..=u8::MAX).collect();
    let baseline = trace(&all_bytes, &[all_bytes.len()]);
    let chunks = random_chunks(all_bytes.len(), &mut random);
    assert_eq!(trace(&all_bytes, &chunks), baseline);
}

#[test]
fn meaningful_stream_is_invariant_at_every_fragment_boundary() {
    let bytes = b"draft \xc3\xa9\xf0\x9f\x90\x89\x1b[D\x08!\nsecond\x1b[H>\x1b[F<\n\x1b[\x80\x1b[Ax\x1b]hidden\x07z\r\n";
    let baseline = trace(bytes, &[bytes.len()]);
    for split in 0..=bytes.len() {
        assert_eq!(trace(bytes, &[split, 0, bytes.len() - split]), baseline);
    }
}

#[test]
fn generated_sessions_match_vec_history_and_scalar_cursor_oracle() {
    const SCALARS: &[char] = &['a', 'Z', '0', 'é', 'λ', '中', '🐉', '\u{301}', '\u{fe0f}'];
    let mut random = XorShift64(0x7157_0a17_5eed_0032);
    let mut decoder = InputDecoder::new();
    let mut editor = Editor::new();
    let mut reference = ReferenceEditor::default();
    let mut previous = String::new();

    for session in 0..80 {
        let line = if session % 11 == 10 {
            previous.clone()
        } else {
            let scalars = 48 + random.index(160);
            (0..scalars)
                .map(|_| SCALARS[random.index(SCALARS.len())])
                .collect()
        };
        previous.clone_from(&line);
        let mut bytes = line.into_bytes();
        bytes.push(b'\n');
        let chunks = random_chunks(bytes.len(), &mut random);
        feed_chunks(
            &mut decoder,
            &mut editor,
            &mut reference,
            &bytes,
            &chunks,
            true,
        );
    }
    assert_eq!(editor.history_len(), reference.history.len());
    assert_eq!(editor.history_bytes(), reference.history_bytes());
    assert!(editor.history_len() <= HISTORY_ENTRIES);
    assert!(editor.history_bytes() <= HISTORY_BYTES);

    let mut navigation = Vec::new();
    navigation.extend(core::iter::repeat_n(b"\x1b[A".as_slice(), 40).flatten());
    navigation.extend_from_slice("temporary🐉".as_bytes());
    navigation.extend(core::iter::repeat_n(b"\x1b[B".as_slice(), 40).flatten());
    let chunks = random_chunks(navigation.len(), &mut random);
    feed_chunks(
        &mut decoder,
        &mut editor,
        &mut reference,
        &navigation,
        &chunks,
        true,
    );
    assert_eq!(render(&editor, 3), expected_frame(&reference));
}

#[test]
fn exact_line_and_history_byte_caps_hold_end_to_end() {
    let mut random = XorShift64(0xb0a1_ded0_4096_1638);
    let mut decoder = InputDecoder::new();
    let mut editor = Editor::new();
    let mut reference = ReferenceEditor::default();

    let unicode_line = "🐉".repeat(MAX_LINE_BYTES / '🐉'.len_utf8());
    let chunks = random_chunks(unicode_line.len(), &mut random);
    feed_chunks(
        &mut decoder,
        &mut editor,
        &mut reference,
        unicode_line.as_bytes(),
        &chunks,
        false,
    );
    assert_eq!(editor.line().len(), MAX_LINE_BYTES);
    assert_eq!(editor.cursor(), MAX_LINE_BYTES);
    let (_, outcomes) = feed_chunks(&mut decoder, &mut editor, &mut reference, b"x", &[1], false);
    assert_eq!(outcomes, [EditOutcome::Rejected(EditError::LineTooLong)]);
    assert_eq!(editor.line(), unicode_line);
    assert_eq!(render(&editor, 1).len(), 13 + VISIBLE_SCALARS * 4);
    feed_chunks(
        &mut decoder,
        &mut editor,
        &mut reference,
        b"\x1b[H",
        &[1, 2],
        false,
    );
    let maximum_frame = render(&editor, 1);
    assert_eq!(maximum_frame, expected_frame(&reference));
    assert_eq!(maximum_frame.len(), FRAME_BYTES);
    assert!(maximum_frame.ends_with(b"\x1b[71D"));
    feed_chunks(
        &mut decoder,
        &mut editor,
        &mut reference,
        b"\x1b[F",
        &[2, 1],
        false,
    );
    feed_chunks(&mut decoder, &mut editor, &mut reference, b"\n", &[1], true);

    for byte in b'a'..=b'd' {
        let line = vec![byte; MAX_LINE_BYTES];
        let chunks = random_chunks(line.len(), &mut random);
        feed_chunks(
            &mut decoder,
            &mut editor,
            &mut reference,
            &line,
            &chunks,
            false,
        );
        feed_chunks(&mut decoder, &mut editor, &mut reference, b"\n", &[1], true);
    }
    assert_eq!(editor.history_len(), 4);
    assert_eq!(editor.history_bytes(), HISTORY_BYTES);

    let duplicate = vec![b'd'; MAX_LINE_BYTES];
    feed_chunks(
        &mut decoder,
        &mut editor,
        &mut reference,
        &duplicate,
        &random_chunks(duplicate.len(), &mut random),
        false,
    );
    feed_chunks(&mut decoder, &mut editor, &mut reference, b"\n", &[1], true);
    assert_eq!(editor.history_len(), 4);
    assert_eq!(editor.history_bytes(), HISTORY_BYTES);

    let chunks = random_chunks(unicode_line.len(), &mut random);
    feed_chunks(
        &mut decoder,
        &mut editor,
        &mut reference,
        unicode_line.as_bytes(),
        &chunks,
        false,
    );
    feed_chunks(
        &mut decoder,
        &mut editor,
        &mut reference,
        b"\x1b[H",
        &[3],
        false,
    );
    let mut move_to_interior = Vec::with_capacity(512 * 3);
    move_to_interior.extend(core::iter::repeat_n(b"\x1b[C".as_slice(), 512).flatten());
    let chunks = random_chunks(move_to_interior.len(), &mut random);
    feed_chunks(
        &mut decoder,
        &mut editor,
        &mut reference,
        &move_to_interior,
        &chunks,
        false,
    );
    assert_eq!(editor.cursor(), 512 * '🐉'.len_utf8());
    feed_chunks(
        &mut decoder,
        &mut editor,
        &mut reference,
        b"\x1b[A",
        &[1, 1, 1],
        false,
    );
    feed_chunks(
        &mut decoder,
        &mut editor,
        &mut reference,
        b"\x1b[B",
        &[1, 2],
        false,
    );
    assert_eq!(editor.line(), unicode_line);
    assert_eq!(editor.cursor(), 512 * '🐉'.len_utf8());
}

#[test]
fn submitted_line_is_typed_frozen_until_explicit_acceptance() {
    let mut decoder = InputDecoder::new();
    let mut editor = Editor::new();
    let mut reference = ReferenceEditor::default();
    let line = "echo é🐉";
    let mut bytes = line.as_bytes().to_vec();
    bytes.push(b'\n');
    let (_, outcomes) = feed_chunks(
        &mut decoder,
        &mut editor,
        &mut reference,
        &bytes,
        &[1; 12],
        false,
    );
    assert_eq!(outcomes.last(), Some(&EditOutcome::Submitted));
    assert_eq!(editor.line(), line);
    assert_eq!(editor.history_len(), 0);
    let frozen_frame = render(&editor, 2);

    let ignored = b"x\x1b[D\x08\x03";
    let (_, outcomes) = feed_chunks(
        &mut decoder,
        &mut editor,
        &mut reference,
        ignored,
        &[0, 1, 2, ignored.len() - 3, 0],
        false,
    );
    assert!(outcomes.iter().all(|outcome| *outcome == EditOutcome::Busy));
    assert_eq!(editor.line(), line);
    assert_eq!(editor.history_len(), 0);
    assert_eq!(render(&editor, 7), frozen_frame);

    accept_submission(&mut editor, &mut reference);
    assert_eq!(editor.line(), "");
    assert_eq!(editor.history_len(), 1);
    assert_eq!(editor.history_bytes(), line.len());
    accept_submission(&mut editor, &mut reference);
    assert_eq!(editor.history_len(), 1);
}

#[test]
fn nested_control_constituents_never_reach_editor_or_redraw() {
    let cases: &[(&[u8], &str)] = &[
        (b"\x1b[\x80\x1b[Ax", "x"),
        (b"\x1bO\x1b[Ax", "x"),
        (b"\x1b(\x80\x1b[Ax", "x"),
        (b"\x1b[\x80\x1bOAx", "x"),
        (b"\x1b[\x80\x1b]A-payload\x07z", "z"),
        (b"\x1b[\x80\x1b[200~A-payload\x1b[201~z", "z"),
    ];
    for &(bytes, suffix) in cases {
        for split in 0..=bytes.len() {
            let result = trace(bytes, &[split, 0, bytes.len() - split]);
            assert_eq!(result.line, suffix);
            assert_eq!(
                result.frame,
                format!("\r\x1b[2Kwyrmsh> {suffix}").as_bytes()
            );
            assert!(!result.frame.windows(2).any(|window| window == b"[A"));
            assert!(!result.frame.windows(7).any(|window| window == b"payload"));
        }
    }
}

#[test]
fn redraw_matches_independent_ascii_viewport_for_all_bounded_positions() {
    for len in [0, 1, 70, 71, 72, 96, 128] {
        let line: Vec<u8> = (0..len).map(|index| b'a' + (index % 26) as u8).collect();
        let positions: Vec<usize> = if len <= 72 {
            (0..=len).collect()
        } else {
            vec![0, 1, 35, len / 2, len - 1, len]
        };
        for position in positions {
            let mut decoder = InputDecoder::new();
            let mut editor = Editor::new();
            let mut reference = ReferenceEditor::default();
            feed_chunks(
                &mut decoder,
                &mut editor,
                &mut reference,
                &line,
                &[line.len()],
                false,
            );
            feed_chunks(
                &mut decoder,
                &mut editor,
                &mut reference,
                b"\x1b[H",
                &[1, 2],
                false,
            );
            for _ in 0..position {
                feed_chunks(
                    &mut decoder,
                    &mut editor,
                    &mut reference,
                    b"\x1b[C",
                    &[2, 1],
                    false,
                );
            }

            let expected = expected_frame(&reference);
            assert!(expected.is_ascii());
            for chunk in [1, 2, 7, FRAME_BYTES] {
                assert_eq!(
                    render(&editor, chunk),
                    expected,
                    "len={len} cursor={position}"
                );
            }
        }
    }
}
