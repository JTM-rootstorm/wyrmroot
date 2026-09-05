// SPDX-License-Identifier: GPL-3.0-or-later

use wyrmroot_wyrmsh_core::{EditError, EditOutcome, Editor, InputError, InputEvent};

fn type_text(editor: &mut Editor, text: &str) {
    for ch in text.chars() {
        assert_eq!(editor.apply(InputEvent::Insert(ch)), EditOutcome::Changed);
    }
}

fn submit(editor: &mut Editor, text: &str) {
    type_text(editor, text);
    assert_eq!(editor.apply(InputEvent::Submit), EditOutcome::Submitted);
    assert_eq!(editor.line(), text);
    editor.accept_submission();
    assert_eq!(editor.line(), "");
}

fn render_with_chunks(editor: &Editor, chunk: usize) -> Vec<u8> {
    let mut redraw = editor.redraw();
    let mut result = Vec::new();
    let mut output = vec![0; chunk];
    loop {
        let count = redraw.read(&mut output);
        if count == 0 {
            return result;
        }
        result.extend_from_slice(&output[..count]);
    }
}

#[test]
fn editor_fixed_state_is_bounded() {
    let bytes = core::mem::size_of::<Editor>();
    assert!(bytes <= 25 * 1024, "editor fixed state is {bytes} bytes");
    eprintln!("EDITOR_SIZE_BYTES={bytes}");
}

#[test]
fn scalar_insert_move_and_delete_preserve_boundaries() {
    let mut editor = Editor::new();
    type_text(&mut editor, "aé🐉z");
    assert_eq!(editor.line(), "aé🐉z");
    assert_eq!(editor.cursor(), editor.line().len());

    assert_eq!(editor.apply(InputEvent::Left), EditOutcome::Changed);
    assert_eq!(editor.cursor(), "aé🐉".len());
    assert_eq!(editor.apply(InputEvent::Left), EditOutcome::Changed);
    assert_eq!(editor.cursor(), "aé".len());
    assert_eq!(editor.apply(InputEvent::Insert('λ')), EditOutcome::Changed);
    assert_eq!(editor.line(), "aéλ🐉z");
    assert_eq!(editor.apply(InputEvent::Backspace), EditOutcome::Changed);
    assert_eq!(editor.line(), "aé🐉z");
    assert_eq!(editor.apply(InputEvent::Delete), EditOutcome::Changed);
    assert_eq!(editor.line(), "aéz");
    assert_eq!(editor.apply(InputEvent::Home), EditOutcome::Changed);
    assert_eq!(editor.apply(InputEvent::Backspace), EditOutcome::Unchanged);
    assert_eq!(editor.apply(InputEvent::Delete), EditOutcome::Changed);
    assert_eq!(editor.line(), "éz");
    assert_eq!(editor.apply(InputEvent::End), EditOutcome::Changed);
    assert_eq!(editor.apply(InputEvent::Right), EditOutcome::Unchanged);
    assert_eq!(editor.apply(InputEvent::Delete), EditOutcome::Unchanged);
}

#[test]
fn exact_line_limit_and_rejections_are_atomic() {
    let mut editor = Editor::new();
    for _ in 0..4095 {
        assert_eq!(editor.apply(InputEvent::Insert('x')), EditOutcome::Changed);
    }
    let before = editor.line().as_bytes().to_vec();
    let cursor = editor.cursor();
    assert_eq!(
        editor.apply(InputEvent::Insert('é')),
        EditOutcome::Rejected(EditError::LineTooLong)
    );
    assert_eq!(editor.line().as_bytes(), before);
    assert_eq!(editor.cursor(), cursor);
    assert_eq!(editor.apply(InputEvent::Insert('x')), EditOutcome::Changed);
    assert_eq!(editor.line().len(), 4096);
    assert_eq!(
        editor.apply(InputEvent::Insert('y')),
        EditOutcome::Rejected(EditError::LineTooLong)
    );
    assert_eq!(editor.line().len(), 4096);

    for ch in [
        '\0', '\n', '\r', '\u{7f}', '\u{85}', '\u{200d}', '\u{2028}', '\u{2029}', '\u{2066}',
    ] {
        assert_eq!(
            editor.apply(InputEvent::Insert(ch)),
            EditOutcome::Rejected(EditError::UnsupportedCharacter)
        );
        assert_eq!(editor.line().len(), 4096);
        assert_eq!(editor.cursor(), 4096);
    }
    assert_eq!(
        editor.apply(InputEvent::Rejected(InputError::InvalidUtf8)),
        EditOutcome::Rejected(EditError::Input(InputError::InvalidUtf8))
    );
    assert_eq!(editor.line().len(), 4096);
}

#[test]
fn normal_unicode_scalars_are_admitted_by_direct_model_calls() {
    let mut editor = Editor::new();
    for ch in ['é', 'λ', '🐉', '中'] {
        assert_eq!(editor.apply(InputEvent::Insert(ch)), EditOutcome::Changed);
    }
    assert_eq!(editor.line(), "éλ🐉中");
}

#[test]
fn submit_is_frozen_until_accept_and_history_is_explicit() {
    let mut editor = Editor::new();
    type_text(&mut editor, "echo one");
    assert_eq!(editor.apply(InputEvent::Submit), EditOutcome::Submitted);
    for event in [
        InputEvent::Insert('x'),
        InputEvent::Submit,
        InputEvent::Cancel,
        InputEvent::Eof,
    ] {
        assert_eq!(editor.apply(event), EditOutcome::Busy);
        assert_eq!(editor.line(), "echo one");
        assert_eq!(editor.history_len(), 0);
    }
    editor.accept_submission();
    assert_eq!(editor.line(), "");
    assert_eq!(editor.history_len(), 1);
    assert_eq!(editor.history_bytes(), 8);
    editor.accept_submission();
    assert_eq!(editor.history_len(), 1);

    submit(&mut editor, "echo one");
    assert_eq!(editor.history_len(), 1);
    assert_eq!(editor.history_bytes(), 8);
    assert_eq!(editor.apply(InputEvent::Submit), EditOutcome::Submitted);
    editor.accept_submission();
    assert_eq!(editor.history_len(), 1);
}

#[test]
fn history_caps_entries_without_changing_on_navigation() {
    let mut editor = Editor::new();
    for index in 0..35 {
        let line = format!("entry-{index:02}");
        submit(&mut editor, &line);
    }
    assert_eq!(editor.history_len(), 32);
    assert_eq!(editor.history_bytes(), 32 * 8);

    for index in (3..35).rev() {
        assert_eq!(editor.apply(InputEvent::Up), EditOutcome::Changed);
        assert_eq!(editor.line(), format!("entry-{index:02}"));
    }
    assert_eq!(editor.apply(InputEvent::Up), EditOutcome::Unchanged);
    assert_eq!(editor.history_len(), 32);
    assert_eq!(editor.history_bytes(), 32 * 8);
}

#[test]
fn history_byte_eviction_and_wrapping_retain_newest_entries() {
    let mut editor = Editor::new();
    let mut expected = Vec::new();
    for marker in ['a', 'b', 'c', 'd', 'e'] {
        let line: String = core::iter::repeat_n(marker, 3000).collect();
        submit(&mut editor, &line);
        expected.push(line);
    }
    let wrapped: String = core::iter::repeat_n('z', 2500).collect();
    submit(&mut editor, &wrapped);
    expected.push(wrapped);

    assert_eq!(editor.history_len(), 5);
    assert_eq!(editor.history_bytes(), 14_500);
    for wanted in expected[1..].iter().rev() {
        assert_eq!(editor.apply(InputEvent::Up), EditOutcome::Changed);
        assert_eq!(editor.line(), wanted);
    }
    assert_eq!(editor.apply(InputEvent::Up), EditOutcome::Unchanged);
    assert_eq!(editor.history_len(), 5);
    assert_eq!(editor.history_bytes(), 14_500);
}

#[test]
fn down_restores_draft_and_recalled_edits_do_not_change_history() {
    let mut editor = Editor::new();
    submit(&mut editor, "oldest");
    submit(&mut editor, "newest");
    type_text(&mut editor, "draft");
    assert_eq!(editor.apply(InputEvent::Left), EditOutcome::Changed);
    let draft_cursor = editor.cursor();

    assert_eq!(editor.apply(InputEvent::Up), EditOutcome::Changed);
    assert_eq!(editor.line(), "newest");
    type_text(&mut editor, "!");
    assert_eq!(editor.line(), "newest!");
    assert_eq!(editor.history_len(), 2);
    assert_eq!(editor.history_bytes(), 12);
    assert_eq!(editor.apply(InputEvent::Down), EditOutcome::Changed);
    assert_eq!(editor.line(), "draft");
    assert_eq!(editor.cursor(), draft_cursor);

    assert_eq!(editor.apply(InputEvent::Up), EditOutcome::Changed);
    assert_eq!(editor.line(), "newest");
    assert_eq!(editor.apply(InputEvent::Up), EditOutcome::Changed);
    assert_eq!(editor.line(), "oldest");
    assert_eq!(editor.apply(InputEvent::Down), EditOutcome::Changed);
    assert_eq!(editor.line(), "newest");
    assert_eq!(editor.apply(InputEvent::Down), EditOutcome::Changed);
    assert_eq!(editor.line(), "draft");
}

#[test]
fn cancel_and_eof_have_bounded_shell_semantics() {
    let mut editor = Editor::new();
    assert_eq!(editor.apply(InputEvent::Eof), EditOutcome::Eof);
    submit(&mut editor, "kept");
    type_text(&mut editor, "partial");
    assert_eq!(editor.apply(InputEvent::Eof), EditOutcome::Unchanged);
    assert_eq!(editor.line(), "partial");
    assert_eq!(editor.apply(InputEvent::Up), EditOutcome::Changed);
    assert_eq!(editor.apply(InputEvent::Cancel), EditOutcome::Cancelled);
    assert_eq!(editor.line(), "");
    assert_eq!(editor.cursor(), 0);
    assert_eq!(editor.history_len(), 1);
    assert_eq!(editor.apply(InputEvent::Down), EditOutcome::Unchanged);
    assert_eq!(editor.apply(InputEvent::Up), EditOutcome::Changed);
    assert_eq!(editor.line(), "kept");
}

#[test]
fn redraw_is_deterministic_resumable_and_positions_ascii_cursor() {
    let mut editor = Editor::new();
    type_text(&mut editor, "abc");
    assert_eq!(editor.apply(InputEvent::Left), EditOutcome::Changed);
    let expected = b"\r\x1b[2Kwyrmsh> abc\x1b[1D";
    assert_eq!(render_with_chunks(&editor, 1), expected);
    assert_eq!(render_with_chunks(&editor, 2), expected);
    assert_eq!(render_with_chunks(&editor, 4096), expected);

    let mut redraw = editor.redraw();
    assert_eq!(redraw.read(&mut []), 0);
    let mut output = [0; 64];
    assert_eq!(redraw.read(&mut output), expected.len());
    assert_eq!(redraw.read(&mut output), 0);
    assert_eq!(redraw.read(&mut []), 0);
}

#[test]
fn redraw_uses_fixed_71_scalar_horizontal_viewport() {
    let text: String = (0..100)
        .map(|index| char::from(b'a' + (index % 26) as u8))
        .collect();
    let mut editor = Editor::new();
    type_text(&mut editor, &text);

    let mut expected_end = b"\r\x1b[2Kwyrmsh> ".to_vec();
    expected_end.extend_from_slice(&text.as_bytes()[29..100]);
    assert_eq!(render_with_chunks(&editor, 7), expected_end);
    assert_eq!(expected_end.len(), 13 + 71);

    assert_eq!(editor.apply(InputEvent::Home), EditOutcome::Changed);
    let mut expected_home = b"\r\x1b[2Kwyrmsh> ".to_vec();
    expected_home.extend_from_slice(&text.as_bytes()[..71]);
    expected_home.extend_from_slice(b"\x1b[71D");
    assert_eq!(render_with_chunks(&editor, 3), expected_home);

    for _ in 0..72 {
        assert_eq!(editor.apply(InputEvent::Right), EditOutcome::Changed);
    }
    let mut expected_middle = b"\r\x1b[2Kwyrmsh> ".to_vec();
    expected_middle.extend_from_slice(&text.as_bytes()[29..100]);
    expected_middle.extend_from_slice(b"\x1b[28D");
    assert_eq!(render_with_chunks(&editor, 11), expected_middle);
}

#[test]
fn redraw_counts_unicode_scalars_as_one_column() {
    let mut editor = Editor::new();
    type_text(&mut editor, "a🐉éb");
    assert_eq!(editor.apply(InputEvent::Home), EditOutcome::Changed);
    assert_eq!(editor.apply(InputEvent::Right), EditOutcome::Changed);
    assert_eq!(
        render_with_chunks(&editor, 4),
        b"\r\x1b[2Kwyrmsh> a\xf0\x9f\x90\x89\xc3\xa9b\x1b[3D"
    );
}
