# WYR0 Bootfs Format Contract

## Purpose and authority

WYR0 bootfs is a deterministic, read-only bootstrap transport. It is not the permanent Wyrmroot
filesystem design. This document narrows the WYR0 implementation plan's `cpio newc` choice into one
builder/parser contract; it does not define runtime capability validation, process loading, image
assembly, or later filesystem semantics.

## Archive envelope

- The archive uses uncompressed `cpio newc` records with magic `070701`.
- Each header is 110 bytes and contains the standard thirteen eight-digit hexadecimal fields.
- Names include one terminal NUL in `c_namesize`. Embedded NULs are invalid.
- The name region and payload region are each padded with zero bytes to the next four-byte boundary.
- The final record is exactly `TRAILER!!!` with a zero payload and all numeric metadata zero.
- The trailer is the final aligned record. No trailing bytes or block padding are accepted.
- `070702` CRC records, compression, directories, symbolic links, hard links, device nodes, and
  other record types are not part of WYR0-C.

## Canonical records

Every non-trailer record is an immutable regular file with normalized metadata:

- inode, UID, GID, modification time, device fields, and check field are zero;
- link count is one;
- mode is exactly `0100444` for read-only data or `0100555` for an executable;
- file payload length is the exact `c_filesize` value; archive padding is never payload.

Record names are strictly increasing in byte-lexicographic order. Equal names are duplicates and
decreasing names are noncanonical. The reserved name `TRAILER!!!` cannot be used by an ordinary
record.

## Path policy

Stored names and lookup keys are nonempty relative byte paths. Components are separated by `/`.
Leading, trailing, or repeated separators; `.` and `..` components; NUL; and backslash are rejected.
Paths are validated, not normalized or rewritten. Non-UTF-8 names remain valid byte paths, while
text conversion is an explicit checked operation.

Logical platform names such as `/system/init0` are absolute namespace paths. Their archive record
names remain relative (`system/init0`); the leading slash is not stored and is not accepted by the
archive API.

## Resource limits

One WYR0 archive is bounded by a single shared policy:

- at most 32 MiB of encoded bytes, including every header, name, padding region, payload, and the
  trailer;
- at most 4096 non-trailer records;
- at most 4096 encoded name bytes, including the terminal NUL.

The parser rejects declared extents before slicing them. The builder uses checked size arithmetic
and fallible allocation. Neither side may silently truncate, round an attacker-declared extent,
follow a host filesystem path, or derive archive metadata or ordering from ambient host state.

## Content and consumption boundary

The WYR0-C logical content rule reserves `bin/hello` and `system/init0` for future real executable
artifacts and emits them in canonical byte order. Missing, duplicate, empty, or extra inputs fail
closed; placeholder executables are not generated.

The reusable parser accepts an exact borrowed archive byte slice and returns only borrowed immutable
sub-slices. A later runtime boundary owns `MemoryObject` type, rights, mapping, and exact module
length validation. It must pass the parser only the advertised payload extent, never the
page-rounded allocation slack.
