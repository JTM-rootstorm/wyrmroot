//! The warn-level lint ratchet: counts may fall, never rise.
//!
//! Structural refactor S1.3. `clippy::wildcard_enum_match_arm` and
//! `clippy::undocumented_unsafe_blocks` each name a defect class this project
//! has paid for -- a wildcard arm that let a new variant join a status category
//! silently (`DIAGNOSTIC_CAUSE_CARRIAGE_CONTRACT.md` §3.4), and `unsafe` whose
//! justification lives nowhere. Denying them today would be a flag day across
//! every crate at once, so instead every crate's current count is checked in
//! (`tools/xtask/lint-baseline.toml`) and this gate fails only when a count
//! *rises*. When one falls it says so, and the baseline is lowered by hand in
//! the change that fixed the sites.
//!
//! The lints run over exactly what clippy already reaches: the workspace in its
//! default shape, plus every feature shape a named `*-clippy` host gate lints
//! (including devmgr's role binary). A site compiled in several shapes is
//! counted once, by its primary span.

use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::fs;
use std::path::Path;
use std::process::{Command, Stdio};

use crate::error::Failure;

/// The two ratcheted lints, as clippy's diagnostic codes name them.
pub(crate) const LINTS: [&str; 2] = [
    "clippy::wildcard_enum_match_arm",
    "clippy::undocumented_unsafe_blocks",
];

/// The checked-in counts, relative to the repository.
pub(crate) const BASELINE_PATH: &str = "tools/xtask/lint-baseline.toml";

/// A separate target directory, so these warn-level runs never share
/// fingerprints with the `-D warnings` gates that lint the same crates.
const TARGET_DIRECTORY: &str = ".tmp/cargo-target/lint-ratchet-host-1.98.1";

/// Counts per lint, per package.
pub(crate) type Counts = BTreeMap<String, BTreeMap<String, u64>>;

/// Runs every clippy shape with the two lints at warn level and compares the
/// counts against the baseline.
pub(crate) fn run(repository: &Path, shapes: &[Vec<String>]) -> Result<(), Failure> {
    let baseline_text = fs::read_to_string(repository.join(BASELINE_PATH)).map_err(|error| {
        Failure::task(format!(
            "could not read the lint baseline {BASELINE_PATH}: {error}"
        ))
    })?;
    let baseline = parse_baseline(&baseline_text)?;
    let mut sites = BTreeSet::new();
    for shape in shapes {
        let arguments = ratchet_arguments(shape);
        let cargo = env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
        let output = Command::new(cargo)
            .args(&arguments)
            .current_dir(repository)
            .stdin(Stdio::null())
            .stderr(Stdio::inherit())
            .output()
            .map_err(|error| Failure::task(format!("could not run Cargo: {error}")))?;
        if !output.status.success() {
            return Err(Failure::task(format!(
                "lint ratchet clippy failed: cargo {}",
                arguments.join(" ")
            )));
        }
        let stdout = String::from_utf8(output.stdout)
            .map_err(|_| Failure::task("lint ratchet clippy printed non-UTF-8 output"))?;
        sites.extend(warning_sites(&stdout)?);
    }
    let counts = count_sites(&sites);
    let verdict = compare(&baseline, &counts);
    eprintln!("{}", verdict.report);
    if verdict.risen.is_empty() && verdict.fallen.is_empty() {
        eprintln!("lint ratchet: every count matches {BASELINE_PATH}");
    }
    if verdict.risen.is_empty() {
        Ok(())
    } else {
        Err(Failure::task(format!(
            "lint ratchet: {} count(s) rose above {BASELINE_PATH}: {}",
            verdict.risen.len(),
            verdict.risen.join(", ")
        )))
    }
}

/// A clippy shape's own arguments, rewritten to report the two lints as JSON
/// from the ratchet's target directory. Everything after the shape's `--` is
/// dropped: that is where the `-D warnings` of a named gate lives.
pub(crate) fn ratchet_arguments(shape: &[String]) -> Vec<String> {
    let mut arguments = shape
        .iter()
        .take_while(|argument| *argument != "--")
        .cloned()
        .collect::<Vec<_>>();
    arguments.extend(
        [
            "--message-format=json",
            "--target-dir",
            TARGET_DIRECTORY,
            "--",
        ]
        .map(str::to_owned),
    );
    for lint in LINTS {
        arguments.extend(["-W".to_owned(), lint.to_owned()]);
    }
    arguments
}

/// One warning, identified by where it points.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) struct Site {
    pub(crate) lint: String,
    pub(crate) package: String,
    pub(crate) file: String,
    pub(crate) line: u64,
    pub(crate) column: u64,
}

/// Every ratcheted warning in one Cargo JSON message stream.
pub(crate) fn warning_sites(stream: &str) -> Result<Vec<Site>, Failure> {
    let mut sites = Vec::new();
    for line in stream.lines().filter(|line| line.starts_with('{')) {
        let message = Json::parse(line)?;
        if message.get("reason").and_then(Json::as_str) != Some("compiler-message") {
            continue;
        }
        let Some(diagnostic) = message.get("message") else {
            continue;
        };
        let Some(lint) = diagnostic
            .get("code")
            .and_then(|code| code.get("code"))
            .and_then(Json::as_str)
        else {
            continue;
        };
        if !LINTS.contains(&lint) {
            continue;
        }
        let package = message
            .get("package_id")
            .and_then(Json::as_str)
            .map(package_name)
            .ok_or_else(|| Failure::task("a lint ratchet message names no package"))?;
        let span = diagnostic
            .get("spans")
            .and_then(Json::as_array)
            .and_then(|spans| {
                spans
                    .iter()
                    .find(|span| span.get("is_primary") == Some(&Json::Bool(true)))
            })
            .ok_or_else(|| Failure::task(format!("a {lint} warning has no primary span")))?;
        let field = |name: &str| {
            span.get(name)
                .ok_or_else(|| Failure::task(format!("a {lint} span has no {name}")))
        };
        sites.push(Site {
            lint: lint.trim_start_matches("clippy::").to_owned(),
            package,
            file: field("file_name")?
                .as_str()
                .ok_or_else(|| Failure::task("a span file name is not a string"))?
                .to_owned(),
            line: field("line_start")?
                .as_u64()
                .ok_or_else(|| Failure::task("a span line is not a number"))?,
            column: field("column_start")?
                .as_u64()
                .ok_or_else(|| Failure::task("a span column is not a number"))?,
        });
    }
    Ok(sites)
}

/// The package name in a Cargo package id.
///
/// Cargo spells a path package `path+file:///dir/name#name@version`, or
/// `path+file:///dir/name#version` when the name is the directory's own.
fn package_name(id: &str) -> String {
    let (path, fragment) = id.split_once('#').unwrap_or((id, ""));
    match fragment.split_once('@') {
        Some((name, _)) => name.to_owned(),
        None => path.rsplit('/').next().unwrap_or(path).to_owned(),
    }
}

pub(crate) fn count_sites(sites: &BTreeSet<Site>) -> Counts {
    let mut counts = Counts::new();
    for lint in LINTS {
        counts.insert(
            lint.trim_start_matches("clippy::").to_owned(),
            BTreeMap::new(),
        );
    }
    for site in sites {
        *counts
            .entry(site.lint.clone())
            .or_default()
            .entry(site.package.clone())
            .or_default() += 1;
    }
    counts
}

/// The baseline format: one `[lint]` table per lint, `package = count` rows.
pub(crate) fn parse_baseline(text: &str) -> Result<Counts, Failure> {
    let mut counts = Counts::new();
    let mut current: Option<String> = None;
    for (number, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let malformed = || Failure::task(format!("{BASELINE_PATH}:{}: malformed line", number + 1));
        if let Some(table) = line
            .strip_prefix('[')
            .and_then(|rest| rest.strip_suffix(']'))
        {
            if !LINTS.contains(&format!("clippy::{table}").as_str())
                || counts.insert(table.to_owned(), BTreeMap::new()).is_some()
            {
                return Err(malformed());
            }
            current = Some(table.to_owned());
            continue;
        }
        let table = current.as_ref().ok_or_else(malformed)?;
        let (package, count) = line.split_once('=').ok_or_else(malformed)?;
        let package = package.trim().trim_matches('"').to_owned();
        let count = count.trim().parse::<u64>().map_err(|_| malformed())?;
        if package.is_empty()
            || counts
                .get_mut(table)
                .ok_or_else(malformed)?
                .insert(package, count)
                .is_some()
        {
            return Err(malformed());
        }
    }
    for lint in LINTS {
        if !counts.contains_key(lint.trim_start_matches("clippy::")) {
            return Err(Failure::task(format!(
                "{BASELINE_PATH} has no [{}] table",
                lint.trim_start_matches("clippy::")
            )));
        }
    }
    Ok(counts)
}

/// Renders counts in the baseline's own format.
pub(crate) fn render_baseline(counts: &Counts) -> String {
    let mut text = String::new();
    for (lint, packages) in counts {
        text.push_str(&format!("[{lint}]\n"));
        for (package, count) in packages {
            if *count != 0 {
                text.push_str(&format!("{package} = {count}\n"));
            }
        }
        text.push('\n');
    }
    text
}

pub(crate) struct Verdict {
    /// `lint/package baseline -> current` for every count that rose.
    pub(crate) risen: Vec<String>,
    /// `lint/package baseline -> current` for every count that fell.
    pub(crate) fallen: Vec<String>,
    pub(crate) report: String,
}

pub(crate) fn compare(baseline: &Counts, current: &Counts) -> Verdict {
    let mut risen = Vec::new();
    let mut fallen = Vec::new();
    let lints = baseline
        .keys()
        .chain(current.keys())
        .collect::<BTreeSet<_>>();
    for lint in lints {
        let empty = BTreeMap::new();
        let before = baseline.get(lint).unwrap_or(&empty);
        let after = current.get(lint).unwrap_or(&empty);
        let packages = before.keys().chain(after.keys()).collect::<BTreeSet<_>>();
        for package in packages {
            let was = before.get(package).copied().unwrap_or(0);
            let now = after.get(package).copied().unwrap_or(0);
            let entry = format!("{lint}/{package} {was} -> {now}");
            if now > was {
                risen.push(entry);
            } else if now < was {
                fallen.push(entry);
            }
        }
    }
    let mut report = String::from("lint ratchet counts:\n");
    report.push_str(&render_baseline(current));
    if !fallen.is_empty() {
        report.push_str(&format!(
            "lint ratchet: {} count(s) fell; lower {BASELINE_PATH} to the counts above: {}\n",
            fallen.len(),
            fallen.join(", ")
        ));
    }
    Verdict {
        risen,
        fallen,
        report,
    }
}

/// Just enough JSON for Cargo's message stream.
#[derive(Clone, Debug, PartialEq)]
enum Json {
    Null,
    Bool(bool),
    Number(f64),
    String(String),
    Array(Vec<Json>),
    Object(Vec<(String, Json)>),
}

impl Json {
    fn parse(text: &str) -> Result<Self, Failure> {
        let mut parser = Parser {
            bytes: text.as_bytes(),
            at: 0,
        };
        let value = parser.value(0)?;
        parser.whitespace();
        if parser.at != parser.bytes.len() {
            return Err(parser.fail());
        }
        Ok(value)
    }

    fn get(&self, key: &str) -> Option<&Self> {
        match self {
            Self::Object(fields) => fields
                .iter()
                .find(|(name, _)| name == key)
                .map(|(_, value)| value),
            _ => None,
        }
    }

    fn as_str(&self) -> Option<&str> {
        match self {
            Self::String(value) => Some(value),
            _ => None,
        }
    }

    fn as_array(&self) -> Option<&[Self]> {
        match self {
            Self::Array(values) => Some(values),
            _ => None,
        }
    }

    fn as_u64(&self) -> Option<u64> {
        match self {
            Self::Number(value) if value.fract() == 0.0 && *value >= 0.0 => Some(*value as u64),
            _ => None,
        }
    }
}

struct Parser<'a> {
    bytes: &'a [u8],
    at: usize,
}

/// Cargo's messages nest a handful of levels; this bounds a hostile one.
const MAX_DEPTH: usize = 64;

impl Parser<'_> {
    fn fail(&self) -> Failure {
        Failure::task(format!(
            "lint ratchet could not parse Cargo JSON at byte {}",
            self.at
        ))
    }

    fn whitespace(&mut self) {
        while self
            .bytes
            .get(self.at)
            .is_some_and(|byte| byte.is_ascii_whitespace())
        {
            self.at += 1;
        }
    }

    fn expect(&mut self, literal: &[u8]) -> Result<(), Failure> {
        if self.bytes[self.at..].starts_with(literal) {
            self.at += literal.len();
            Ok(())
        } else {
            Err(self.fail())
        }
    }

    fn value(&mut self, depth: usize) -> Result<Json, Failure> {
        if depth > MAX_DEPTH {
            return Err(self.fail());
        }
        self.whitespace();
        match self.bytes.get(self.at) {
            Some(b'n') => self.expect(b"null").map(|()| Json::Null),
            Some(b't') => self.expect(b"true").map(|()| Json::Bool(true)),
            Some(b'f') => self.expect(b"false").map(|()| Json::Bool(false)),
            Some(b'"') => self.string().map(Json::String),
            Some(b'[') => {
                self.at += 1;
                let mut values = Vec::new();
                self.whitespace();
                if self.bytes.get(self.at) == Some(&b']') {
                    self.at += 1;
                    return Ok(Json::Array(values));
                }
                loop {
                    values.push(self.value(depth + 1)?);
                    self.whitespace();
                    match self.bytes.get(self.at) {
                        Some(b',') => self.at += 1,
                        Some(b']') => {
                            self.at += 1;
                            return Ok(Json::Array(values));
                        }
                        _ => return Err(self.fail()),
                    }
                }
            }
            Some(b'{') => {
                self.at += 1;
                let mut fields = Vec::new();
                self.whitespace();
                if self.bytes.get(self.at) == Some(&b'}') {
                    self.at += 1;
                    return Ok(Json::Object(fields));
                }
                loop {
                    self.whitespace();
                    let key = self.string()?;
                    self.whitespace();
                    self.expect(b":")?;
                    fields.push((key, self.value(depth + 1)?));
                    self.whitespace();
                    match self.bytes.get(self.at) {
                        Some(b',') => self.at += 1,
                        Some(b'}') => {
                            self.at += 1;
                            return Ok(Json::Object(fields));
                        }
                        _ => return Err(self.fail()),
                    }
                }
            }
            Some(byte) if *byte == b'-' || byte.is_ascii_digit() => {
                let start = self.at;
                while self.bytes.get(self.at).is_some_and(|byte| {
                    byte.is_ascii_digit() || matches!(byte, b'-' | b'+' | b'.' | b'e' | b'E')
                }) {
                    self.at += 1;
                }
                std::str::from_utf8(&self.bytes[start..self.at])
                    .ok()
                    .and_then(|text| text.parse::<f64>().ok())
                    .map(Json::Number)
                    .ok_or_else(|| self.fail())
            }
            _ => Err(self.fail()),
        }
    }

    fn string(&mut self) -> Result<String, Failure> {
        self.expect(b"\"")?;
        let mut value = Vec::new();
        loop {
            let byte = *self.bytes.get(self.at).ok_or_else(|| self.fail())?;
            self.at += 1;
            match byte {
                b'"' => break,
                b'\\' => {
                    let escape = *self.bytes.get(self.at).ok_or_else(|| self.fail())?;
                    self.at += 1;
                    match escape {
                        b'"' | b'\\' | b'/' => value.push(escape),
                        b'b' => value.push(0x08),
                        b'f' => value.push(0x0c),
                        b'n' => value.push(b'\n'),
                        b'r' => value.push(b'\r'),
                        b't' => value.push(b'\t'),
                        b'u' => {
                            let unit = self.hex4()?;
                            let scalar = if (0xd800..0xdc00).contains(&unit) {
                                self.expect(b"\\u")?;
                                let low = self.hex4()?;
                                if !(0xdc00..0xe000).contains(&low) {
                                    return Err(self.fail());
                                }
                                0x10000 + ((unit - 0xd800) << 10) + (low - 0xdc00)
                            } else {
                                unit
                            };
                            let character = char::from_u32(scalar).ok_or_else(|| self.fail())?;
                            let mut buffer = [0; 4];
                            value.extend_from_slice(character.encode_utf8(&mut buffer).as_bytes());
                        }
                        _ => return Err(self.fail()),
                    }
                }
                _ => value.push(byte),
            }
        }
        String::from_utf8(value).map_err(|_| self.fail())
    }

    fn hex4(&mut self) -> Result<u32, Failure> {
        let digits = self
            .bytes
            .get(self.at..self.at + 4)
            .and_then(|digits| std::str::from_utf8(digits).ok())
            .and_then(|digits| u32::from_str_radix(digits, 16).ok())
            .ok_or_else(|| self.fail())?;
        self.at += 4;
        Ok(digits)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn message(lint: &str, package_id: &str, file: &str, line: u64) -> String {
        format!(
            "{{\"reason\":\"compiler-message\",\"package_id\":\"{package_id}\",\
             \"message\":{{\"code\":{{\"code\":\"{lint}\",\"explanation\":null}},\
             \"level\":\"warning\",\"message\":\"x \\\"quoted\\\" \\u00e9\",\
             \"spans\":[{{\"file_name\":\"other.rs\",\"line_start\":1,\"column_start\":1,\
             \"is_primary\":false}},{{\"file_name\":\"{file}\",\"line_start\":{line},\
             \"column_start\":5,\"is_primary\":true}}]}}}}"
        )
    }

    #[test]
    fn only_the_two_lints_are_counted_once_per_primary_span() {
        let stream = [
            message(
                "clippy::wildcard_enum_match_arm",
                "path+file:///w/userspace/system-init#wyrmroot-system-init@0.0.0",
                "userspace/system-init/src/lib.rs",
                10,
            ),
            // The same site again, as a second shape of the same crate reports it.
            message(
                "clippy::wildcard_enum_match_arm",
                "path+file:///w/userspace/system-init#wyrmroot-system-init@0.0.0",
                "userspace/system-init/src/lib.rs",
                10,
            ),
            message(
                "clippy::undocumented_unsafe_blocks",
                "path+file:///w/tools/xtask#0.0.0",
                "tools/xtask/src/main.rs",
                3,
            ),
            message(
                "clippy::needless_return",
                "path+file:///w/tools/xtask#0.0.0",
                "tools/xtask/src/main.rs",
                4,
            ),
            "{\"reason\":\"build-finished\",\"success\":true}".to_owned(),
            "   Checking something".to_owned(),
        ]
        .join("\n");
        let sites = warning_sites(&stream)
            .unwrap()
            .into_iter()
            .collect::<BTreeSet<_>>();
        let counts = count_sites(&sites);
        assert_eq!(
            counts["wildcard_enum_match_arm"],
            BTreeMap::from([("wyrmroot-system-init".to_owned(), 1)])
        );
        assert_eq!(
            counts["undocumented_unsafe_blocks"],
            BTreeMap::from([("xtask".to_owned(), 1)])
        );
        assert_eq!(counts.len(), 2);
    }

    #[test]
    fn a_rise_fails_a_fall_is_reported_and_a_new_package_counts_from_zero() {
        let baseline = parse_baseline(
            "# comment\n[wildcard_enum_match_arm]\na = 2\nb = 1\n\n\
             [undocumented_unsafe_blocks]\n",
        )
        .unwrap();
        let mut current = baseline.clone();
        assert!(compare(&baseline, &current).risen.is_empty());

        current
            .get_mut("wildcard_enum_match_arm")
            .unwrap()
            .insert("a".into(), 1);
        let verdict = compare(&baseline, &current);
        assert!(verdict.risen.is_empty());
        assert_eq!(verdict.fallen, ["wildcard_enum_match_arm/a 2 -> 1"]);
        assert!(
            verdict
                .report
                .contains("lower tools/xtask/lint-baseline.toml")
        );

        current
            .get_mut("undocumented_unsafe_blocks")
            .unwrap()
            .insert("c".into(), 1);
        assert_eq!(
            compare(&baseline, &current).risen,
            ["undocumented_unsafe_blocks/c 0 -> 1"]
        );
    }

    #[test]
    fn the_baseline_parser_refuses_what_it_cannot_mean() {
        for malformed in [
            "a = 1\n",
            "[wildcard_enum_match_arm]\na = x\n",
            "[wildcard_enum_match_arm]\na = 1\na = 2\n[undocumented_unsafe_blocks]\n",
            "[unknown_lint]\n",
            "[wildcard_enum_match_arm]\n",
        ] {
            assert!(parse_baseline(malformed).is_err(), "{malformed:?}");
        }
        let counts =
            parse_baseline("[wildcard_enum_match_arm]\na = 3\n[undocumented_unsafe_blocks]\n")
                .unwrap();
        assert_eq!(parse_baseline(&render_baseline(&counts)).unwrap(), counts);
    }

    #[test]
    fn the_checked_in_baseline_parses() {
        let repository = crate::tasks::repository_root().unwrap();
        let text = fs::read_to_string(repository.join(BASELINE_PATH)).unwrap();
        parse_baseline(&text).unwrap();
    }

    #[test]
    fn a_shape_keeps_its_own_arguments_and_loses_its_deny() {
        let shape = [
            "clippy",
            "--locked",
            "--package",
            "p",
            "--lib",
            "--",
            "-D",
            "warnings",
        ]
        .map(str::to_owned);
        let arguments = ratchet_arguments(&shape);
        assert_eq!(arguments[..5], shape[..5]);
        assert!(!arguments.iter().any(|argument| argument == "-D"));
        assert!(arguments.contains(&"--message-format=json".to_owned()));
        let lints = &arguments[arguments.iter().position(|a| a == "--").unwrap() + 1..];
        assert_eq!(
            lints,
            [
                "-W",
                "clippy::wildcard_enum_match_arm",
                "-W",
                "clippy::undocumented_unsafe_blocks"
            ]
        );
    }
}
