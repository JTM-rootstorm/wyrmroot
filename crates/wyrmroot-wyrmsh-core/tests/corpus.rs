// SPDX-License-Identifier: GPL-3.0-or-later

use wyrmroot_wyrmsh_core::{
    COMMANDS, Command, CommandName, JobIdError, MAX_ARGUMENTS, MAX_LINE_BYTES, ParseError, Parser,
    UsageError, parse_job_id, validate_path,
};

fn tokens(line: &[u8], expected: &[&str]) {
    let mut parser = Parser::new();
    let args = parser.parse(line).unwrap();
    assert_eq!(args.iter().collect::<Vec<_>>(), expected);
    assert_eq!(args.len(), expected.len());
    assert_eq!(args.get(expected.len()), None);
    assert_eq!(args.scratch().len(), expected.iter().map(|v| v.len()).sum());
}

#[test]
fn empty_whitespace_and_all_ascii_separators() {
    tokens(b"", &[]);
    tokens(b" \t\r\n\x0b\x0c", &[]);
    tokens(
        b"a b\tc\rd\ne\x0bf\x0cg",
        &["a", "b", "c", "d", "e", "f", "g"],
    );
    tokens("a\u{a0}b".as_bytes(), &["a\u{a0}b"]);
    let mut parser = Parser::new();
    assert_eq!(parser.parse(b" \t").unwrap().command(), Ok(Command::Empty));
}

#[test]
fn quotes_escape_rules_and_empty_arguments() {
    tokens(
        br#"echo '' "" a"b c"'d' '\n'"#,
        &["echo", "", "", "ab cd", "\\n"],
    );
    tokens(
        br#"echo "\\\"\n\r\t" a\ b \n \q"#,
        &["echo", "\\\"\n\r\t", "a b", "n", "q"],
    );
    tokens(b"echo a\\\nb", &["echo", "a\nb"]);
    tokens(
        "echo 'kobold 🐉' \\é".as_bytes(),
        &["echo", "kobold 🐉", "é"],
    );
    tokens(br#"echo a''b""c"#, &["echo", "abc"]);
}

#[test]
fn metacharacters_remain_literal_single_command_data() {
    tokens(
        br#"echo | < > ; $ ` { } ( ) # * ? &&"#,
        &[
            "echo", "|", "<", ">", ";", "$", "`", "{", "}", "(", ")", "#", "*", "?", "&&",
        ],
    );
    let mut parser = Parser::new();
    let Command::Echo(args) = parser
        .parse(b"echo a;exit | status")
        .unwrap()
        .command()
        .unwrap()
    else {
        panic!("expected echo data")
    };
    assert_eq!(args.iter().collect::<Vec<_>>(), ["a;exit", "|", "status"]);
    assert_eq!(
        parser.parse(b"exit;help").unwrap().command(),
        Err(UsageError::UnknownCommand)
    );
}

#[test]
fn malformed_input_returns_typed_errors_and_parser_can_be_reused() {
    let cases: &[(&[u8], ParseError)] = &[
        (b"a\\", ParseError::TrailingBackslash),
        (b"'a", ParseError::UnterminatedSingleQuote),
        (b"\"a", ParseError::UnterminatedDoubleQuote),
        (b"\"a\\", ParseError::TrailingBackslash),
        (br#""\q""#, ParseError::UnsupportedEscape(b'q')),
        (b"echo \0", ParseError::Nul),
        (b"'\0'", ParseError::Nul),
        (b"\xff", ParseError::InvalidUtf8),
        (b"\xc0\x80", ParseError::InvalidUtf8),
        (b"\xed\xa0\x80", ParseError::InvalidUtf8),
        (b"\xf4\x90\x80\x80", ParseError::InvalidUtf8),
        (b"\xe2\x82", ParseError::InvalidUtf8),
    ];
    let mut parser = Parser::new();
    for (line, expected) in cases {
        parser.parse(b"old successful command").unwrap();
        assert_eq!(parser.parse(line).unwrap_err(), *expected);
        assert_eq!(
            parser
                .parse(b"echo fresh")
                .unwrap()
                .iter()
                .collect::<Vec<_>>(),
            ["echo", "fresh"]
        );
    }
}

#[test]
fn every_ascii_double_quote_escape_has_exact_disposition() {
    let mut parser = Parser::new();
    for byte in 1..=127u8 {
        let line = [b'"', b'\\', byte, b'"'];
        let expected = match byte {
            b'\\' | b'"' => Some(byte),
            b'n' => Some(b'\n'),
            b'r' => Some(b'\r'),
            b't' => Some(b'\t'),
            _ => None,
        };
        match expected {
            Some(decoded) => assert_eq!(
                parser.parse(&line).unwrap().get(0).unwrap().as_bytes(),
                [decoded]
            ),
            None => assert_eq!(
                parser.parse(&line).unwrap_err(),
                ParseError::UnsupportedEscape(byte)
            ),
        }
    }
}

#[test]
fn exact_line_scratch_and_argument_limits() {
    let mut parser = Parser::new();
    let line = [b'x'; MAX_LINE_BYTES];
    let args = parser.parse(&line).unwrap();
    assert_eq!(args.get(0).unwrap().len(), MAX_LINE_BYTES);
    assert_eq!(args.scratch().len(), MAX_LINE_BYTES);
    assert_eq!(
        parser.parse(&[b'x'; MAX_LINE_BYTES + 1]).unwrap_err(),
        ParseError::LineTooLong
    );
    let full = (0..MAX_ARGUMENTS)
        .map(|_| "''")
        .collect::<Vec<_>>()
        .join(" ");
    assert_eq!(parser.parse(full.as_bytes()).unwrap().len(), MAX_ARGUMENTS);
    assert_eq!(
        parser.parse(format!("{full} ").as_bytes()).unwrap().len(),
        MAX_ARGUMENTS
    );
    assert_eq!(
        parser.parse(format!("{full} ''").as_bytes()).unwrap_err(),
        ParseError::TooManyArguments
    );
}

#[test]
fn fixed_commands_and_usage_are_exact() {
    let mut parser = Parser::new();
    for (line, expected) in [
        ("help", Command::Help),
        ("clear", Command::Clear),
        ("exit", Command::Exit),
        ("services", Command::Services),
        ("tasks", Command::Tasks),
        ("status", Command::Status),
    ] {
        assert_eq!(
            parser.parse(line.as_bytes()).unwrap().command(),
            Ok(expected)
        );
        assert!(matches!(
            parser
                .parse(format!("{line} extra").as_bytes())
                .unwrap()
                .command(),
            Err(UsageError::ArgumentCount { .. })
        ));
    }
    for line in ["HELP", "unknown", "''", "./help", "#comment"] {
        assert_eq!(
            parser.parse(line.as_bytes()).unwrap().command(),
            Err(UsageError::UnknownCommand)
        );
    }
    for line in [
        "run",
        "spawn",
        "wait",
        "terminate",
        "wait 1 2",
        "terminate 1 2",
    ] {
        assert!(matches!(
            parser.parse(line.as_bytes()).unwrap().command(),
            Err(UsageError::ArgumentCount { .. })
        ));
    }
    assert_eq!(COMMANDS.len(), 11);
    assert_eq!(COMMANDS[0].name, CommandName::Help);
    assert!(
        matches!(parser.parse(b"echo").unwrap().command(), Ok(Command::Echo(args)) if args.is_empty())
    );
}

#[test]
fn launch_model_preserves_child_argv_zero_and_does_not_authorize_paths() {
    let mut parser = Parser::new();
    for verb in ["run", "spawn"] {
        let line = format!("{verb} bin/not-an-allowed-payload '' 'a b'");
        let command = parser.parse(line.as_bytes()).unwrap().command().unwrap();
        let (Command::Run { path, argv } | Command::Spawn { path, argv }) = command else {
            panic!("launch")
        };
        assert_eq!(path, "bin/not-an-allowed-payload");
        assert_eq!(argv.iter().collect::<Vec<_>>(), [path, "", "a b"]);
    }
}

#[test]
fn canonical_path_intersects_transport_and_archive_constraints() {
    for good in [
        "bin/hello",
        "system/wyrmsh",
        "bin/TRAILER!!!",
        "a..b/c",
        "a b/c",
        "a;b",
    ] {
        assert_eq!(validate_path(good), Ok(()), "{good}");
    }
    for bad in [
        "",
        "/bin/hello",
        "bin/",
        "bin//hello",
        ".",
        "..",
        "bin/./hello",
        "bin/../hello",
        "a\\b",
        "TRAILER!!!",
        "b\0n",
        "bin/é",
    ] {
        assert_eq!(validate_path(bad), Err(UsageError::InvalidPath), "{bad}");
    }
    assert!(validate_path(&"a".repeat(256)).is_ok());
    assert!(validate_path(&"a".repeat(257)).is_err());
    let mut parser = Parser::new();
    assert_eq!(
        parser.parse(b"run ../hello").unwrap().command(),
        Err(UsageError::InvalidPath)
    );
}

#[test]
fn canonical_nonzero_job_ids_and_checked_overflow() {
    assert_eq!(parse_job_id("1").unwrap().get(), 1);
    assert_eq!(
        parse_job_id("18446744073709551615").unwrap().get(),
        u64::MAX
    );
    for bad in [
        "", "0", "00", "01", "+1", "-1", " 1", "1 ", "1_0", "0x1", "１", "1\0",
    ] {
        assert_eq!(parse_job_id(bad), Err(JobIdError::Noncanonical), "{bad}");
    }
    assert_eq!(
        parse_job_id("18446744073709551616"),
        Err(JobIdError::Overflow)
    );
    assert_eq!(parse_job_id(&"9".repeat(4096)), Err(JobIdError::Overflow));
    let mut parser = Parser::new();
    assert!(
        matches!(parser.parse(b"wait 1").unwrap().command(), Ok(Command::Wait(id)) if id.get() == 1)
    );
    assert!(
        matches!(parser.parse(b"terminate 2").unwrap().command(), Ok(Command::Terminate(id)) if id.get() == 2)
    );
    assert_eq!(
        parser.parse(b"wait 00").unwrap().command(),
        Err(UsageError::InvalidJobId(JobIdError::Noncanonical))
    );
}
