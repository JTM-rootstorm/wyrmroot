# WYR1-E2 input, editor and redraw contract

**Date:** 2026-09-05
**Scope:** E2A/E2B pure input/editor model, extending section 7 of the
[frozen wyrmsh contract](WYR1_E_WYRMSH_CONTRACT.md).

## Input and resynchronization

`InputDecoder::feed(u8)` consumes exactly one byte and returns at most one event.
Pending storage is four UTF-8 bytes plus twelve ESC/CSI bytes; finite discard
states retain no input payload. Empty transport fragments do nothing. No timer,
terminal reads, syscall or output side effect belongs to the decoder.

- Printable ASCII and complete valid UTF-8 scalars yield `Insert`. The accepted
  scalar predicate excludes Unicode Cc, Cf, Zl and Zp. Cf is the complete Unicode
  17.0.0 normative range set; Cc uses Rust's control classification; Zl/Zp are
  U+2028/U+2029. Letters, emoji, combining marks and variation selectors remain
  accepted under the explicit scalar-width limitation below.
- NUL, unsupported controls, stray continuations, overlong, surrogate and
  out-of-range encodings are rejected. A malformed UTF-8 prefix consumes its
  offending byte without replaying it as text. If that byte is ESC, preserve its
  role as an escape introducer while reporting the malformed prefix.
- Accepted keys: CSI `A/B/C/D` for Up/Down/Right/Left, `H` or `1~` for Home,
  `F` or `4~` for End, and `3~` for Delete. Backspace accepts 0x08 and 0x7F.
  SS3 is recognized only as an unsupported sequence and consumes its final
  byte; it does not alias these keys. No modifier, completion or broader
  linenoise control is admitted.
- Tab emits one ASCII space. Ctrl-D emits an EOF request, interpreted by the
  editor only on an empty line. Ctrl-C always resets pending decoder/discard
  state and emits cancellation.
- LF submits only from complete ground state. The normal consoled path already
  normalizes CR/CRLF/LF; the pure byte API also accepts CR and suppresses only
  its immediately following LF, including across fragments. Enter during an
  incomplete UTF-8 or escape sequence rejects that pending input and does not
  submit; a paired LF must not turn rejection into submission.
- Unknown CSI sequences are consumed through their final byte. An overlong or
  malformed CSI enters discard through the next final byte (0x40..0x7E).
  A nested ESC starts a quarantine-only parser that consumes the entire nested
  CSI/SS3/intermediate/string/paste sequence without producing text or navigation.
  Its introducer must not be mistaken for the outer sequence final. Ctrl-C is the explicit abort;
  Enter rejects/reset the incomplete escape without submitting.
- Unsupported ESC intermediate sequences and SS3 are quarantined through their
  sequence ending (ESC intermediate final 0x30..0x7E, SS3 final 0x40..0x7E).
  Unsupported OSC/DCS/SOS/PM/APC strings consume their payload
  through ST; OSC also accepts BEL. Unsupported bracketed paste consumes its
  payload through the exact `ESC[201~` terminator. Their payload, including
  Enter, never becomes command text or a submission. Ctrl-C aborts these discard
  states; this is rejection of paste, not paste/folding support.
- `finish()` is an end-of-stream check, never Enter. It reports pending incomplete
  input and resets the decoder. The caller must not call it at transport-fragment
  boundaries. Complete rejected sequences leave later ordinary input available.

## Editor and submission

`Editor` retains a 4096-byte UTF-8 line with a byte cursor on a scalar boundary.
All insert/move/delete/history paths preserve that invariant. Direct synthetic
`InputEvent::Insert` is checked against the same printable predicate as decoder
input. An insertion that cannot fit is rejected without partially changing the
line. No edit or decoder error invokes the parser or executes a command.

Left/Right move one scalar, Home/End clamp to line boundaries, Backspace removes
the previous scalar, and Delete removes the next scalar. Edge operations are
unchanged outcomes. EOF on a nonempty line does nothing destructive. Cancellation
clears the active line, browsing state and saved draft, retaining committed history.

Enter returns `Submitted` and freezes the line for the caller to borrow and parse.
Further events return `Busy` until the caller invokes `accept_submission()` after
consuming it. That explicit acknowledgement records eligible history and clears
the active line. Calling it without a pending submission is a no-op. The future
runtime must stop consuming input at submission and retain remaining transport
bytes until it resumes editing; E2 does not implement that adapter.

## History and storage

History holds at most 32 committed entries in one 16 KiB arena. It records nonempty
submitted lines, skips consecutive exact duplicates, and evicts oldest entries
until both bounds fit. A line's execution never depends on history retention.
Up/Down clamp at oldest/newest, and navigation does not evict or mutate committed
history. Edits to a recalled line are temporary, never edits to its stored entry.

The first Up saves the current line and cursor in a separate fixed 4096-byte draft
buffer. Down past the newest entry restores that exact draft and cursor. This is
an explicit E2 addition to the E0 working-buffer list: it preserves unfinished
input without making navigation compete with committed history for arena space.
It adds bounded storage, not a new allocation path. The E2 measurement records
its full footprint; no history/line/parser capacity is reduced to hide its cost.

## Redraw and display model

E2 resolves the older phrase *full-line redraw* as a full redraw of the visible
single-row viewport. Rendering all 4096 bytes and then issuing horizontal cursor
moves cannot faithfully repaint wrapped lines without a terminal-width contract.
This model therefore fixes 80 columns, uses the eight-column `wyrmsh> ` prompt,
and displays at most 71 scalar-width characters, leaving the last column unused.
The complete logical line remains editable; the viewport centers on its cursor
with 35 preceding scalars where possible, then clamps at the ends of the line.
No terminal-width/DSR query, host terminal call or vertical-cursor protocol is added.

A frame is deterministic from line and cursor: CR, erase whole line, prompt,
visible text, then a bounded cursor-back sequence if needed. ASCII positioning
assumes a terminal at least 80 columns wide. Each Unicode scalar counts as one
column; non-ASCII storage/editing is byte-safe, but combining/emoji/wide glyphs
are not a faithful grapheme or `wcwidth` display model. That limitation is explicit.

`Redraw::read(&mut [u8])` emits one finite borrowed frame incrementally. Empty
output advances nothing; nonempty output advances until exhausted; exhaustion
stays exhausted. The immutable borrow prevents changing the editor mid-frame.
A frame has at most 71 four-byte scalars plus 18 framing bytes (302 bytes total),
within 4096 output scratch. There is no self-triggered redraw loop; the caller
creates a frame only in response to input or explicit output demand. Unsupported
input bytes are not replayed into frames.

## Validation boundary

E2 requires fragmentation/malformed decoder tests, editor/history properties,
ASCII viewport/cursor assertions, deterministic chunked redraw, and measured host
fixed-state plus stack-frame evidence. The host measurement is separate from E6's
actual native shell/compiler/runtime call-chain gate against the 108 KiB working
stack (128 KiB mapping minus the 20 KiB startup block). No terminal integration,
WRST adapter, shell executable, product, selector33 or VM acceptance is implied.
