// SPDX-License-Identifier: GPL-3.0-or-later
//! Host-only E2 measurement fixture, never a guest payload or acceptance shell.

use std::{hint::black_box, mem::size_of};
use wyrmroot_wyrmsh_core::{Editor, InputDecoder, InputEvent, Parser};

const REQUESTED_HOST_THREAD_STACK_BYTES: usize = 108 * 1024;

struct WorkingState {
    editor: Editor,
    decoder: InputDecoder,
    parser: Parser,
    output: [u8; 4096],
}

#[inline(never)]
fn exercise(state: &mut WorkingState) -> usize {
    // Exercise a maximum line, all cursor positions, retained-history pressure,
    // malformed input, parsing and small-buffer resumable redraw on one stack.
    for generation in 0..40 {
        for _ in 0..4095 {
            state.editor.apply(InputEvent::Insert('x'));
        }
        state
            .editor
            .apply(InputEvent::Insert(char::from(b'A' + generation % 26)));
        assert_eq!(state.editor.line().len(), 4096);
        state.editor.apply(InputEvent::Home);
        for _ in 0..4096 {
            state.editor.apply(InputEvent::Right);
        }
        state.editor.apply(InputEvent::Left);
        state.editor.apply(InputEvent::Delete);
        state
            .editor
            .apply(InputEvent::Insert(char::from(b'A' + generation % 26)));
        let arguments = state.parser.parse(state.editor.line().as_bytes()).unwrap();
        assert_eq!(arguments.len(), 1);
        let mut redraw = state.editor.redraw();
        let mut emitted = 0;
        loop {
            let n = redraw.read(&mut state.output[..7]);
            if n == 0 {
                break;
            }
            emitted += n;
            black_box(&state.output[..n]);
            assert!(emitted <= 4096 + 64);
        }
        state.editor.apply(InputEvent::Submit);
        state.editor.accept_submission();
        assert!(state.editor.line().is_empty());
    }
    for generation in 0..40 {
        state
            .editor
            .apply(InputEvent::Insert(char::from(b'A' + generation % 26)));
        state.editor.apply(InputEvent::Submit);
        state.editor.accept_submission();
    }
    state.editor.apply(InputEvent::Insert('q'));
    for _ in 0..40 {
        state.editor.apply(InputEvent::Up);
    }
    for _ in 0..40 {
        state.editor.apply(InputEvent::Down);
    }
    for byte in b"\xe2\x82\x03echo \xf0\x9f\x90\x89\n" {
        state.editor.apply(state.decoder.feed(*byte));
    }
    let result = state.editor.line().len();
    assert!(state.editor.history_bytes() <= 16384);
    assert!(state.editor.history_len() <= 32);
    result
}

#[inline(never)]
fn measurement_entry() -> [usize; 5] {
    let mut state = WorkingState {
        editor: Editor::new(),
        decoder: InputDecoder::new(),
        parser: Parser::new(),
        output: [0; 4096],
    };
    black_box(&mut state);
    black_box(exercise(&mut state));
    [
        size_of::<Editor>(),
        size_of::<InputDecoder>(),
        size_of::<Parser>(),
        size_of::<WorkingState>(),
        size_of::<wyrmroot_wyrmsh_core::Redraw<'_>>(),
    ]
}

fn main() {
    // This bounds the exercised host chain; it does not measure a native shell.
    let sizes = std::thread::Builder::new()
        .stack_size(REQUESTED_HOST_THREAD_STACK_BYTES)
        .spawn(measurement_entry)
        .unwrap()
        .join()
        .unwrap();
    println!("{{\"editor_bytes\":{},\"decoder_bytes\":{},\"parser_bytes\":{},\"working_state_bytes\":{},\"redraw_bytes\":{},\"requested_host_thread_stack_bytes\":{}}}",
        sizes[0], sizes[1], sizes[2], sizes[3], sizes[4], REQUESTED_HOST_THREAD_STACK_BYTES);
}
