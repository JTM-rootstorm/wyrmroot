# WYR0-C Security Review

## Scope and disposition

This review covers the WYR0 bootfs format contract, parser, byte-path policy, deterministic builder,
logical content rule, hostile-input tests, and central host tooling at Wyrmroot commit
`cdd33aa3d629d01b65f511ceee79cb3db0f4c65e`.

The final review found no open Critical, High, or Medium findings. Any later security-sensitive
change to the archive envelope, limits, parser, builder, or lookup behavior invalidates this review.

## Closed findings and enforced boundaries

- Parser validation is linear in archive size. Strict increasing byte-path order detects duplicate
  and unsorted records without an attacker-controlled quadratic scan.
- The parser checks all thirteen numeric fields, every checked extent and four-byte alignment,
  both zero-padding regions, the exact trailer, and the absence of trailing bytes.
- Only normalized immutable regular files with exact `0100444` or `0100555` modes are accepted.
  Directories, links, device records, writable modes, special permission bits, and nonzero ambient
  metadata fail closed.
- Stored names and lookup keys share one canonical byte-path policy. Traversal components, absolute
  paths, alternate separators, empty components, embedded NULs, overlong names, and the reserved
  `TRAILER!!!` name are rejected without normalization.
- The archive is bounded to 32 MiB, 4096 file records, and 4096 encoded name bytes. Exact-limit and
  limit-plus-one regressions cover parser and builder decisions.
- The default parser is allocation-free, `no_std`, and forbids unsafe code. Returned names and
  payloads are immutable slices whose lifetimes remain tied to the caller's exact archive slice.
- Builder order, metadata, padding, and trailer bytes are independent of insertion order and host
  filesystem state. All explicit capacity growth is fallible; the infallible public `Clone` surface
  was removed.
- Builder output is parsed back through the hostile parser in tests. A deterministic byte-mutation
  sweep proves malformed inputs do not panic and that every successful parse retains bounded
  canonical entries.
- The host builder and content rule are opt-in features. Central tooling compiles/tests them through
  package-scoped commands without enabling their feature across unrelated workspace crates.
- Image, guest, integration, runtime/bootstrap, and QEMU operations remain unavailable or absent;
  no sentinel media or placeholder executable payload was introduced.

## Deferred authority boundary

WYR0-C accepts only an exact borrowed byte slice. A later runtime integration must independently
validate the bootfs `MemoryObject` type and least rights, keep the backing immutable for every
borrowed-entry lifetime, reject an advertised payload length beyond the mapped object, and pass only
the exact module payload extent to the parser rather than page-rounded allocation slack.

That capability and mapping work belongs to WYR0-F and was not implemented or implied here.

## Evidence

- Bootfs parser/builder/path/content suite: 30 passed.
- Strict bootfs and xtask Clippy with warnings denied: passed.
- Allocation-free default-feature library check and rustdoc warnings gate: passed.
- Focused and unfiltered central host build/test commands: passed.
- Final independent read-only security review: passed with no Critical, High, or Medium findings.
- No VM/QEMU, Rust-fork, README-status, or Deepwyrm ABI changes occurred.

## P0 continuity note — 2026-08-22

The P0 accounting reconciliation mechanically compared the original WYR0-C closure revision
`cdd33aa3d629d01b65f511ceee79cb3db0f4c65e` with final G5 artifact-producing Wyrmroot
`f433baf36d671f3f8b515adf5f613bd01dc8bbb9`. Every reviewed bootfs library source file and the
WYR0-C format contract retain the exact same Git object identity. Later crate changes are limited to
a host-side build wrapper and license metadata. No parser, builder, path, content, or limit behavior
covered by this security review changed, so this review remains current for WYR0-C phase accounting.
