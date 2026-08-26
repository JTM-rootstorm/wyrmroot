# DW1-B selector-26 Wyrmroot product contract

Selector `normal-preemption-up` (ID 26) is a test-only one-CPU preemption
product. It does not extend Deepwyrm's public ABI. Wyrmroot's global generated
ABI/syscall consumers remain pinned to `cfc69bd8a49819ce1cda1a132cf56e55c93f92e4`
and ABI tree `1c6a74f130e386eee95b3780c75950beefd0037d`.
The selector product separately requires kernel candidate
`ae30e879ed61698c7f11d8486639a03a7c7c323e`; this is the canonical selector-26
kernel candidate. This contract does not claim that a Wyrmroot revision which
has not yet been integrated and committed is final.

The exact bootfs has four executable entries: `system/init`, `bin/hello`,
`test/dw1-b/cpu-hog`, and `test/dw1-b/progress`. The CPU hog completes ordinary
handle-free WRLP 1.0 READY, closes that launch endpoint, and only then enters
its audited steady spin loop. That executed loop has no syscall, yield, block,
memory access, or function call. The progress peer instead uses test-private
WRLP 1.4 profile `Dw1bProgress`: INIT transfers exactly one data Channel with
`CHILD_CHANNEL_RIGHTS`; READY remains handle-free on the separate launch
Channel. The launch endpoint is then closed and all eight fixed DWP1 exchanges
occur only on the data Channel. The progress raw operation is submitted once
after the eighth validated request and reply.

Init0 creates/starts the hog and accepts its READY before creating/starting the
progress peer. After progress READY it submits exact ARM arguments, performs
the eight exchanges, observes and queries progress normal exit, and closes its
three retained progress handles. It then launches and fully supervises the
unchanged `bin/hello`, terminates the hog once, waits for EXITED, queries its
terminal record, and closes the hog handles before sending init0 READY.
Failure cleanup follows the same terminate, wait, query, close ownership order,
attempts every remaining cleanup operation, and preserves the first cleanup
failure without falsely reporting a later cleanup as successful.

Schema 5 uses canonical request-relative paths with no traversal, symlink
ancestry, hard-link substitution, or input/output/run-directory aliases. It
binds nonzero exact revisions, the candidate and ABI tree, SHA-256 identities
for loader, kernel, symbols, bootstrap, all four payloads and provenance, the
deterministic bootfs and ESP outputs, nonce, frozen digest
`5E4E054B5C244ACE`, bounded timeout, and measured page ceiling. The canonical
template intentionally leaves the not-yet-integrated Wyrmroot revision and
artifact digests as replacement fields; it is not itself an acceptance
request.

The strict provenance record binds the exact candidate and ABI tree, accepted
Rust revision, kernel and symbols hashes, and the three
`DEEPWYRM_DW1B_*` build values, including the measured page value used for the
kernel build. Its hash is itself request-bound. This proves agreement between
the accepted build record and inspected artifacts; it does not claim to infer
an unrecorded compiler invocation from an ELF file.

The root-owned bounded run writes an exact run receipt. That receipt binds the
frozen request and build-receipt hashes, the actually booted ESP and bootfs
hashes, serial-log hash and request-relative path, run directory, timeout,
observed QEMU debug-exit status 33, and `timed_out = false`. A caller assertion
or serial text alone is never evidence. Acceptance additionally requires the
inspected static x86_64 ELF identities and loaded profile markers, the audited
and request-hashed hog artifact, the exact 122-byte `DWPRE1` with facts
`000000FF`, and an immediately following PASS `DWTEST1` ID 26/detail zero.
This host contract prepares those checks but makes no live selector-26 run
claim.
