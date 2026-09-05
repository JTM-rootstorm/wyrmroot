// SPDX-FileCopyrightText: 1991-2025 Unicode, Inc.
// SPDX-License-Identifier: Unicode-3.0

//! Unicode 17.0.0 `Cf`, `Zl`, and `Zp` general-category membership.
//!
//! The ranges come from the Unicode Character Database file
//! `extracted/DerivedGeneralCategory.txt`, dated 2025-07-24:
//! <https://www.unicode.org/Public/17.0.0/ucd/extracted/DerivedGeneralCategory.txt>.
//! The `Cf` set contains 170 code points in the 21 ranges below; `Zl` and `Zp`
//! are the final two singleton patterns.

pub(super) const fn is_format_or_line_separator(ch: char) -> bool {
    matches!(
        ch,
        '\u{00ad}'
            | '\u{0600}'..='\u{0605}'
            | '\u{061c}'
            | '\u{06dd}'
            | '\u{070f}'
            | '\u{0890}'..='\u{0891}'
            | '\u{08e2}'
            | '\u{180e}'
            | '\u{200b}'..='\u{200f}'
            | '\u{202a}'..='\u{202e}'
            | '\u{2060}'..='\u{2064}'
            | '\u{2066}'..='\u{206f}'
            | '\u{feff}'
            | '\u{fff9}'..='\u{fffb}'
            | '\u{110bd}'
            | '\u{110cd}'
            | '\u{13430}'..='\u{1343f}'
            | '\u{1bca0}'..='\u{1bca3}'
            | '\u{1d173}'..='\u{1d17a}'
            | '\u{e0001}'
            | '\u{e0020}'..='\u{e007f}'
            | '\u{2028}'
            | '\u{2029}'
    )
}
