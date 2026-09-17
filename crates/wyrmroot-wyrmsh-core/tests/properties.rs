// SPDX-License-Identifier: GPL-3.0-or-later

use wyrmroot_wyrmsh_core::{
    COMMANDS, Command, JobIdError, MAX_ARGUMENTS, MAX_LINE_BYTES, MAX_PATH_BYTES, ParseError,
    Parser, UsageError, parse_job_id, validate_path,
};

const ARBITRARY_BYTE_SEED: u64 = 0xd1ce_ba5e_cafe_f00d;
const ARBITRARY_STREAMS_PER_LENGTH: usize = 2;
const VALID_ARGV_SEED: u64 = 0x6b6f_626f_6c64_2131;
const VALID_ARGV_CASES: usize = 2_048;
const GRAMMAR_BYTES: &[u8] = b"aaaaZ09 _\t\r\n\x0b\x0c\\'\"|<>;$`(){}#*?/.[ ]";

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
        usize::from(self.byte()) % bound
    }
}

fn assert_success_bounds(parser: &mut Parser, input: &[u8]) {
    let oversized = input.len() > MAX_LINE_BYTES;
    let invalid_utf8 = core::str::from_utf8(input).is_err();
    let contains_nul = input.contains(&0);

    match parser.parse(input) {
        Ok(arguments) => {
            assert!(!oversized && !invalid_utf8 && !contains_nul);
            assert!(arguments.len() <= MAX_ARGUMENTS);
            assert!(arguments.scratch().len() <= MAX_LINE_BYTES);
            assert!(arguments.scratch().len() <= input.len());
            assert!(!arguments.scratch().as_bytes().contains(&0));

            let mut prior_end = 0;
            let mut aggregate_len = 0;
            for (index, range) in arguments.ranges().iter().enumerate() {
                assert_eq!(range.start, prior_end, "gap or overlap at argv[{index}]");
                assert!(range.start <= range.end);
                assert!(range.end <= arguments.scratch().len());
                let value = arguments.get(index).expect("every parser range is valid");
                assert_eq!(
                    value.as_bytes(),
                    &arguments.scratch().as_bytes()[range.start..range.end]
                );
                aggregate_len += value.len();
                prior_end = range.end;
            }
            assert_eq!(aggregate_len, arguments.scratch().len());
            assert_eq!(prior_end, arguments.scratch().len());
            assert_eq!(arguments.get(arguments.len()), None);
        }
        Err(error) => {
            if oversized {
                assert_eq!(error, ParseError::LineTooLong);
            } else if invalid_utf8 && contains_nul {
                assert!(matches!(error, ParseError::InvalidUtf8 | ParseError::Nul));
            } else if invalid_utf8 {
                assert_eq!(error, ParseError::InvalidUtf8);
            } else if contains_nul {
                assert_eq!(error, ParseError::Nul);
            }
        }
    }
}

#[test]
fn arbitrary_bytes_terminate_preserve_bounds_and_allow_reuse() {
    let mut random = XorShift64(ARBITRARY_BYTE_SEED);
    let mut parser = Parser::new();

    for len in 0..=MAX_LINE_BYTES + 1 {
        for stream_index in 0..ARBITRARY_STREAMS_PER_LENGTH {
            let mut input = vec![0; len];
            input.iter_mut().for_each(|byte| {
                *byte = if stream_index == 0 {
                    random.byte()
                } else {
                    GRAMMAR_BYTES[random.index(GRAMMAR_BYTES.len())]
                };
            });
            assert_success_bounds(&mut parser, &input);

            let recovered = parser.parse(b"echo recovered").unwrap();
            assert_eq!(recovered.iter().collect::<Vec<_>>(), ["echo", "recovered"]);
        }
    }

    let mut far_oversize = vec![0; MAX_LINE_BYTES * 2];
    far_oversize
        .iter_mut()
        .for_each(|byte| *byte = random.byte());
    assert_success_bounds(&mut parser, &far_oversize);
}

#[test]
fn nul_and_invalid_utf8_are_rejected_at_every_exact_limit_position() {
    let mut parser = Parser::new();
    let mut line = vec![b'x'; MAX_LINE_BYTES];

    for position in 0..MAX_LINE_BYTES {
        line[position] = 0;
        assert_eq!(
            parser.parse(&line),
            Err(ParseError::Nul),
            "NUL at {position}"
        );
        line[position] = b'x';

        line[position] = 0xff;
        assert_eq!(
            parser.parse(&line),
            Err(ParseError::InvalidUtf8),
            "invalid UTF-8 at {position}"
        );
        line[position] = b'x';

        assert_eq!(parser.parse(b"help").unwrap().get(0), Some("help"));
    }

    let mut oversize = vec![b'x'; MAX_LINE_BYTES + 1];
    oversize[0] = 0xff;
    oversize[MAX_LINE_BYTES] = 0;
    assert_eq!(parser.parse(&oversize), Err(ParseError::LineTooLong));
}

fn push_double_quoted(line: &mut String, value: &str) {
    line.push('"');
    for scalar in value.chars() {
        match scalar {
            '\\' => line.push_str("\\\\"),
            '"' => line.push_str("\\\""),
            '\n' => line.push_str("\\n"),
            '\r' => line.push_str("\\r"),
            '\t' => line.push_str("\\t"),
            _ => line.push(scalar),
        }
    }
    line.push('"');
}

#[test]
fn generated_valid_argv_roundtrips_against_independent_values() {
    const ATOMS: &[char] = &[
        'a', 'Z', '0', ' ', '\t', '\n', '\r', '\\', '"', '\'', '|', '<', '>', ';', '$', '`', '{',
        '}', '(', ')', '#', '*', '?', '/', '.', 'é', 'λ', '🐉', '\u{a0}',
    ];

    let mut random = XorShift64(VALID_ARGV_SEED);
    let mut parser = Parser::new();

    for case_index in 0..VALID_ARGV_CASES {
        let argument_count = if case_index % 127 == 0 {
            MAX_ARGUMENTS
        } else {
            random.index(17)
        };
        let mut expected = Vec::with_capacity(argument_count);
        let mut line = String::new();

        for argument_index in 0..argument_count {
            let scalar_count = random.index(13);
            let mut value = String::new();
            for _ in 0..scalar_count {
                value.push(ATOMS[random.index(ATOMS.len())]);
            }
            if argument_index != 0 {
                line.push(match argument_index % 6 {
                    0 => '\t',
                    1 => '\n',
                    2 => '\r',
                    3 => '\u{0b}',
                    4 => '\u{0c}',
                    _ => ' ',
                });
            }
            push_double_quoted(&mut line, &value);
            expected.push(value);
        }

        assert!(
            line.len() <= MAX_LINE_BYTES,
            "generator exceeded parser limit"
        );
        let actual = parser.parse(line.as_bytes()).unwrap();
        assert_eq!(actual.len(), expected.len(), "case {case_index}");
        assert_eq!(
            actual.iter().collect::<Vec<_>>(),
            expected,
            "case {case_index}"
        );
    }

    let mixed = "echo pre' single | $ 'mid\"double\\n\\t🐉\"post\\ space {}()<>;`";
    assert_eq!(
        parser
            .parse(mixed.as_bytes())
            .unwrap()
            .iter()
            .collect::<Vec<_>>(),
        [
            "echo",
            "pre single | $ middouble\n\t🐉post space",
            "{}()<>;`"
        ]
    );
}

#[test]
fn command_arity_is_bounded_at_every_public_shape() {
    let mut parser = Parser::new();
    let zero_arity = ["help", "clear", "exit", "services", "tasks", "status"];
    assert_eq!(zero_arity.len(), 6);

    for spelling in zero_arity {
        assert!(parser.parse(spelling.as_bytes()).unwrap().command().is_ok());
        let line = format!("{spelling} extra");
        assert!(matches!(
            parser.parse(line.as_bytes()).unwrap().command(),
            Err(UsageError::ArgumentCount { actual: 1, .. })
        ));
    }

    for operands in 0..MAX_ARGUMENTS {
        let line = core::iter::once("echo")
            .chain(core::iter::repeat_n("x", operands))
            .collect::<Vec<_>>()
            .join(" ");
        if operands < MAX_ARGUMENTS {
            assert!(matches!(
                parser.parse(line.as_bytes()).unwrap().command(),
                Ok(Command::Echo(values)) if values.len() == operands
            ));
        }
    }
    let echo_overflow = core::iter::once("echo")
        .chain(core::iter::repeat_n("x", MAX_ARGUMENTS))
        .collect::<Vec<_>>()
        .join(" ");
    assert_eq!(
        parser.parse(echo_overflow.as_bytes()),
        Err(ParseError::TooManyArguments)
    );

    for verb in ["run", "spawn"] {
        assert!(matches!(
            parser.parse(verb.as_bytes()).unwrap().command(),
            Err(UsageError::ArgumentCount { actual: 0, .. })
        ));
        for trailing in [0, 1, MAX_ARGUMENTS - 2] {
            let line = core::iter::once(verb)
                .chain(core::iter::once("bin/TRAILER!!!"))
                .chain(core::iter::repeat_n("arg", trailing))
                .collect::<Vec<_>>()
                .join(" ");
            let command = parser.parse(line.as_bytes()).unwrap().command().unwrap();
            assert!(matches!(
                command,
                Command::Run { path: "bin/TRAILER!!!", argv }
                    | Command::Spawn { path: "bin/TRAILER!!!", argv }
                    if argv.len() == trailing + 1
            ));
        }
    }

    for verb in ["wait", "terminate"] {
        for operands in [0, 2] {
            let line = core::iter::once(verb)
                .chain(core::iter::repeat_n("1", operands))
                .collect::<Vec<_>>()
                .join(" ");
            assert!(matches!(
                parser.parse(line.as_bytes()).unwrap().command(),
                Err(UsageError::ArgumentCount { actual, .. }) if actual == operands
            ));
        }
        assert!(
            parser
                .parse(format!("{verb} 1").as_bytes())
                .unwrap()
                .command()
                .is_ok()
        );
    }

    assert_eq!(COMMANDS.len(), 12);
}

#[test]
fn path_validator_matches_frozen_intersection_at_boundaries() {
    for path in [
        "a",
        "a b/c;d",
        "bin/TRAILER!!!",
        "TRAILER!!!/child",
        "a..b/.hidden",
    ] {
        assert_eq!(validate_path(path), Ok(()), "{path:?}");
    }
    for path in [
        "",
        "/a",
        "a/",
        "a//b",
        ".",
        "..",
        "a/./b",
        "a/../b",
        "a\\b",
        "TRAILER!!!",
        "é",
        "a\0b",
    ] {
        assert_eq!(
            validate_path(path),
            Err(UsageError::InvalidPath),
            "{path:?}"
        );
    }

    assert_eq!(validate_path(&"x".repeat(MAX_PATH_BYTES)), Ok(()));
    assert_eq!(
        validate_path(&"x".repeat(MAX_PATH_BYTES + 1)),
        Err(UsageError::InvalidPath)
    );

    for byte in 1..=0x7f_u8 {
        let path = char::from(byte).to_string();
        let expected_valid = !matches!(byte, b'/' | b'\\' | b'.');
        assert_eq!(
            validate_path(&path).is_ok(),
            expected_valid,
            "ASCII {byte:#04x}"
        );
    }
}

fn expected_job_id(value: &str) -> Result<u64, JobIdError> {
    let bytes = value.as_bytes();
    if !matches!(bytes.first(), Some(b'1'..=b'9')) || !bytes.iter().all(u8::is_ascii_digit) {
        return Err(JobIdError::Noncanonical);
    }
    let mut wide = 0_u128;
    for byte in bytes {
        wide = wide * 10 + u128::from(byte - b'0');
        if wide > u128::from(u64::MAX) {
            return Err(JobIdError::Overflow);
        }
    }
    Ok(wide as u64)
}

#[test]
fn job_id_checked_arithmetic_matches_wide_oracle() {
    for value in [
        "1",
        "9",
        "18446744073709551614",
        "18446744073709551615",
        "18446744073709551616",
        "99999999999999999999",
        "0",
        "00",
        "01",
        "+1",
        "-1",
        "1_0",
        "１",
    ] {
        assert_eq!(
            parse_job_id(value).map(core::num::NonZeroU64::get),
            expected_job_id(value),
            "{value:?}"
        );
    }

    let mut random = XorShift64(0x7573_697a_655f_3634);
    for digits in 0..=40 {
        for _ in 0..64 {
            let mut value = String::with_capacity(digits);
            for _ in 0..digits {
                value.push(char::from(b'0' + (random.byte() % 10)));
            }
            assert_eq!(
                parse_job_id(&value).map(core::num::NonZeroU64::get),
                expected_job_id(&value),
                "{value:?}"
            );
        }
    }

    assert_eq!(
        parse_job_id(&"9".repeat(MAX_LINE_BYTES)),
        Err(JobIdError::Overflow)
    );
}
