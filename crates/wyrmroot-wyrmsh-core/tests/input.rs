// SPDX-License-Identifier: GPL-3.0-or-later
use wyrmroot_wyrmsh_core::{InputDecoder, InputError, InputEvent};

fn events(bytes: &[u8]) -> Vec<InputEvent> {
    let mut decoder = InputDecoder::new();
    bytes
        .iter()
        .map(|b| decoder.feed(*b))
        .filter(|e| *e != InputEvent::None)
        .collect()
}

#[test]
fn keys_and_fragmented_unicode() {
    for (bytes, event) in [
        (&b"\x1b[A"[..], InputEvent::Up),
        (b"\x1b[B", InputEvent::Down),
        (b"\x1b[C", InputEvent::Right),
        (b"\x1b[D", InputEvent::Left),
        (b"\x1b[H", InputEvent::Home),
        (b"\x1b[F", InputEvent::End),
        (b"\x1b[1~", InputEvent::Home),
        (b"\x1b[4~", InputEvent::End),
        (b"\x1b[3~", InputEvent::Delete),
        (b"\x08", InputEvent::Backspace),
        (b"\x7f", InputEvent::Backspace),
        (b"\x04", InputEvent::Eof),
        (b"\x03", InputEvent::Cancel),
        (b"\t", InputEvent::Insert(' ')),
    ] {
        for split in 0..=bytes.len() {
            let mut decoder = InputDecoder::new();
            let mut actual = Vec::new();
            for chunk in [&bytes[..split], &bytes[split..]] {
                actual.extend(
                    chunk
                        .iter()
                        .map(|b| decoder.feed(*b))
                        .filter(|e| *e != InputEvent::None),
                );
            }
            assert_eq!(actual, [event]);
            assert!(!decoder.is_pending());
        }
    }
    for ch in ['é', 'λ', '🐉', '\u{10ffff}'] {
        let mut buf = [0; 4];
        let bytes = ch.encode_utf8(&mut buf).as_bytes();
        for split in 0..=bytes.len() {
            let mut decoder = InputDecoder::new();
            for (index, byte) in bytes[..split].iter().chain(&bytes[split..]).enumerate() {
                assert_eq!(
                    decoder.feed(*byte),
                    if index + 1 == bytes.len() {
                        InputEvent::Insert(ch)
                    } else {
                        InputEvent::None
                    }
                );
                assert!(decoder.pending_bytes() <= 16);
            }
        }
    }
}

#[test]
fn malformed_and_incomplete_input_cannot_submit() {
    for bytes in [
        b"\xc0\x80".as_slice(),
        b"\xed\xa0\x80",
        b"\xf4\x90\x80\x80",
        b"\x80",
        b"\xe2x",
    ] {
        assert!(
            events(bytes)
                .iter()
                .all(|event| matches!(event, InputEvent::Rejected(_)))
        );
    }
    assert_eq!(
        events(b"\xe2\n"),
        [InputEvent::Rejected(InputError::IncompleteUtf8)]
    );
    assert_eq!(
        events(b"\x1b[\n"),
        [InputEvent::Rejected(InputError::IncompleteEscape)]
    );
    assert_eq!(
        events(b"\xe2\x03x"),
        [InputEvent::Cancel, InputEvent::Insert('x')]
    );
    assert_eq!(
        events(b"\x1b[\x03x"),
        [InputEvent::Cancel, InputEvent::Insert('x')]
    );
    assert_eq!(events(b"\r\n\n"), [InputEvent::Submit, InputEvent::Submit]);
    assert_eq!(
        events(b"\xe2\r\n"),
        [InputEvent::Rejected(InputError::IncompleteUtf8)]
    );
    for prefix in [b"\xe2".as_slice(), b"\xe2\x82", b"\x1b", b"\x1b["] {
        let mut decoder = InputDecoder::new();
        for byte in prefix {
            decoder.feed(*byte);
        }
        assert!(matches!(decoder.finish(), InputEvent::Rejected(_)));
        assert!(!decoder.is_pending());
        assert_eq!(decoder.feed(b'x'), InputEvent::Insert('x'));
    }
}

#[test]
fn unknown_and_overlong_sequences_are_consumed() {
    assert_eq!(
        events(b"\x1b[1;5Dx"),
        [
            InputEvent::Rejected(InputError::UnsupportedEscape),
            InputEvent::Insert('x')
        ]
    );
    assert_eq!(
        events(b"\x1b(0x"),
        [
            InputEvent::Rejected(InputError::UnsupportedEscape),
            InputEvent::Insert('x')
        ]
    );
    let mut input = b"\x1b[".to_vec();
    input.extend([b'1'; 1000]);
    input.extend(b"~x");
    assert_eq!(
        events(&input),
        [
            InputEvent::Rejected(InputError::EscapeTooLong),
            InputEvent::Insert('x')
        ]
    );
    assert_eq!(
        events(b"\xe2\x1b[31mx"),
        [
            InputEvent::Rejected(InputError::InvalidUtf8),
            InputEvent::Rejected(InputError::UnsupportedEscape),
            InputEvent::Insert('x')
        ]
    );
    assert_eq!(
        events(b"\x00\x01"),
        [InputEvent::Rejected(InputError::UnsupportedControl); 2]
    );
}

#[test]
fn unsupported_ss3_sequences_are_quarantined_through_their_final() {
    for final_byte in *b"ABCDHF" {
        let input = [27, b'O', final_byte, b'x'];
        assert_eq!(
            events(&input),
            [
                InputEvent::Rejected(InputError::UnsupportedEscape),
                InputEvent::Insert('x'),
            ]
        );
    }
    assert_eq!(
        events(b"\x1bO1;2Ax"),
        [
            InputEvent::Rejected(InputError::UnsupportedEscape),
            InputEvent::Insert('x'),
        ]
    );
}

#[test]
fn unsupported_esc_intermediates_are_quarantined_through_their_final() {
    assert_eq!(
        events(b"\x1b(\x80Ax"),
        [
            InputEvent::Rejected(InputError::UnsupportedEscape),
            InputEvent::Insert('x'),
        ]
    );
}

#[test]
fn csi_discard_quarantines_nested_control_sequences() {
    for input in [
        b"\x1b[\x80\x1b[Ax".as_slice(),
        b"\x1b(\x80\x1b[Ax",
        b"\x1bO\x1b[Ax",
        b"\x1b[\x80\x1bOAx",
    ] {
        assert_eq!(
            events(input),
            [
                InputEvent::Rejected(InputError::UnsupportedEscape),
                InputEvent::Insert('x'),
            ]
        );
    }

    let mut input = b"\x1b[".to_vec();
    input.extend([b'1'; 11]);
    input.extend(b"\x1b[Ax");
    assert_eq!(
        events(&input),
        [
            InputEvent::Rejected(InputError::EscapeTooLong),
            InputEvent::Insert('x'),
        ]
    );

    for nested in [
        b"\x1b[\x80\x1b]Ax\x07z".as_slice(),
        b"\x1b[\x80\x1b[200~Ax\x1b[201~z",
    ] {
        assert_eq!(
            events(nested),
            [
                InputEvent::Rejected(InputError::UnsupportedEscape),
                InputEvent::Insert('z'),
            ]
        );
    }
}

#[test]
fn unicode_control_categories_cannot_enter_text() {
    for ch in [
        '\u{009c}',
        '\u{00ad}',
        '\u{0600}',
        '\u{061c}',
        '\u{06dd}',
        '\u{070f}',
        '\u{0890}',
        '\u{08e2}',
        '\u{180e}',
        '\u{200b}',
        '\u{202e}',
        '\u{2060}',
        '\u{2066}',
        '\u{feff}',
        '\u{fff9}',
        '\u{110bd}',
        '\u{110cd}',
        '\u{13430}',
        '\u{1bca0}',
        '\u{1d173}',
        '\u{e0001}',
        '\u{e007f}',
        '\u{2028}',
        '\u{2029}',
    ] {
        let mut encoded = [0; 4];
        assert_eq!(
            events(ch.encode_utf8(&mut encoded).as_bytes()),
            [InputEvent::Rejected(InputError::UnsupportedControl)]
        );
    }

    for ch in ['é', '🐉', '\u{0301}', '\u{fe0f}'] {
        let mut encoded = [0; 4];
        assert_eq!(
            events(ch.encode_utf8(&mut encoded).as_bytes()),
            [InputEvent::Insert(ch)]
        );
    }
}

#[test]
fn unsupported_control_strings_and_paste_never_become_text() {
    for input in [
        b"\x1b]title\nexit\x07x".as_slice(),
        b"\x1bPpayload\nexit\x1b\\x",
        b"\x1b[200~payload\nexit\x1b[201~x",
    ] {
        assert_eq!(
            events(input),
            [
                InputEvent::Rejected(InputError::UnsupportedEscape),
                InputEvent::Insert('x')
            ]
        );
    }
    assert_eq!(
        events(b"\x1b]discard\x03x"),
        [
            InputEvent::Rejected(InputError::UnsupportedEscape),
            InputEvent::Cancel,
            InputEvent::Insert('x')
        ]
    );
}
