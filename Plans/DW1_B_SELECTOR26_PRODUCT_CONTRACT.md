# DW1-B selector-26 Wyrmroot product contract

Selector `normal-preemption-up` (ID 26) is a test-only one-CPU preemption
product. It does not extend Deepwyrm's public ABI. Wyrmroot's global generated
ABI/syscall consumers remain pinned to `cfc69bd8a49819ce1cda1a132cf56e55c93f92e4`
and ABI tree `1c6a74f130e386eee95b3780c75950beefd0037d`.
The selector product separately requires kernel candidate
`0859684651e32655cc9f322fcca5b732d2cb12ca`; this is a candidate descendant
lane and this contract makes no current-main containment claim.

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
Failure cleanup follows the same terminate, wait, query, close ownership order.

Schema 5 binds the request, exact candidate and ABI tree, loader, kernel,
symbols, bootstrap, ESP, four payloads, deterministic bootfs, provenance,
nonce, frozen digest `5E4E054B5C244ACE`, timeout, and measured page ceiling.
The provenance must record the exact `DEEPWYRM_DW1B_*` build environment,
including the measured page value used to build the kernel. Evidence is valid
only when the request, receipt, product, provenance, exact debug-exit status 33,
122-byte `DWPRE1` with facts `000000FF`, and immediately following PASS
`DWTEST1` ID 26/detail zero all agree.
