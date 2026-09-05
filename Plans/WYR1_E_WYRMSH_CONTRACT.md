# WYR1-E wyrmsh contract

**Status:** E0B contract; the companion inventory records its host-model gate.
Production implementation begins at E3, not E0.
**Date:** 2026-09-05
**Authority:** root `WYR1E_DW1F_WYR1F_IMPLEMENTATION_PLAN.md`, E0A/E0B and
Sections 3.1-3.16; platform conventions and bootstrap/recovery architecture.
**Source baseline:** Wyrmroot `6e7830c83806ac39f22840e8983d68591041a053`,
Deepwyrm `18c5b6abf52deb08d2d5ccc45b40896329dc8650`.

This document freezes the next shell contract. The companion
[transition inventory](WYR1_E0_TRANSITION_INVENTORY.md) distinguishes current
implementation from these new obligations. E0 does not change production codecs,
loader profiles, registry service, launch policy, selector dispatch or products.

## 1. Admission and ownership

`system/wyrmsh` is the sole canonical shell bootfs path. Its source and all
statically linked runtime/protocol dependencies remain RRC-A in the immutable
boot generation. No persistent filesystem, interpreter, configuration file,
libc, dynamic linker or new Deepwyrm primitive enters this path.

Init selects one immutable scope when installing each launch connection:

| Scope | Admitted operations |
| --- | --- |
| Historical | Existing WRLJ 1.0 policy and behavior, including selectors 27/32 |
| ConsoleLauncher | ShellV1 for exactly `system/wyrmsh`; existing query/wait/terminate/list/cancel/close operations on its own outer shell job |
| ShellJobs | Ordinary WRLJ 1.0 launches from the explicit shell payload set, and existing job operations on that exact connection's jobs |

The request's path, claimed role or numeric identity never chooses a scope.
ConsoleLauncher rejects ordinary LAUNCH; ShellJobs and Historical reject
ShellV1. ShellJobs may never launch init, registryd, devmgr, uart16550d,
consoled or wyrmsh. Scope is controller state, not a transferred capability or
new kernel right. Connections retain the reached replay and 32-live/32-completed
job accounting bounds; identities are checked nonzero counters, never wrapped
or rebound. Old orphan jobs remain controller-owned and invisible to a new
ShellJobs connection.

The ordinary shell payload set is exactly `bin/hello` and, where the selected
product includes it, `bin/cpu-hog`. Selector-only nonzero-exit/fault fixtures
require explicit selected-product entries and cannot enter production RRC-A.
No directory prefix is an allowlist. Path, content SHA-256, startup ABI/profile,
category and stream mode must all agree with immutable launch policy before
construction. `spawn` uses zero streams; `run` uses exactly three.

The four requester endpoints move atomically from consoled to init. A failed
send leaves them with consoled. A committed send relinquishes them even if
receiver policy rejects the request: init closes the received endpoints and
does not mint registry/session authority, reserve a child or move them again.
Thus rejection before authority changes means before *semantic delegation and
child construction*, not an impossible rollback of a committed transport MOVE.
Consoled closes its own remaining peers; it never reclaims transferred handles.
Malformed input with untrustworthy correlation is closed without a guessed reply.

## 2. WRLJ 1.1 ShellV1 reservation

Reserve message type **16 = LAUNCH_SHELL_V1**, under WRLJ major 1, minor 1.
Types 1-15, their minor-0 bytes and all historical parsers/vectors stay unchanged.
Add separate minor-1 entry points/dispatch; do not widen the minor-0 decoder to
silently accept new semantics. A ConsoleLauncher endpoint is installed with
explicit ShellV1 support by the selected product/controller; software does not
infer support from an OS release or try a minor-0 fallback to launch the shell.

All integers are little-endian. The request is exactly **128 bytes**, four
Channel handles, no variable argv/environment and no trailing bytes:

| Offset | Type/bytes | Value |
| ---: | --- | --- |
| 0 | bytes[4] | `WRLJ` |
| 4 / 6 | u16 / u16 | major 1 / minor 1 |
| 8 / 16 / 24 | u64 each | outer connection ID / connection generation / transaction, all nonzero |
| 32 | u64 | zero, historical envelope reserved |
| 40 / 44 | u32 / u32 | type 16 / flags zero |
| 48 / 56 / 64 | u64 each | console generation / status generation / requested child generation, nonzero |
| 72 / 74 / 76 / 78 | u16 each | path length 13 / startup ABI 2 / WRJP profile 2 / zero |
| 80 / 88 / 96 / 104 | eight-byte descriptors | role u32 followed by zero u32 |
| 112 | bytes[13] | exact UTF-8 `system/wyrmsh`, no NUL |
| 125 | bytes[3] | zero |

Descriptor order and namespace: 1 stdin, 2 stdout, 3 stderr, **4 console status**.
Role 4 belongs only to this new operation; it is not a WRLJ StreamRole or a
fourth WRST stream. Each received endpoint has exact
`READ | WRITE | WAIT | INSPECT | TRANSFER` staging rights, no DUPLICATE. Init
MOVEs them into the child with TRANSFER removed. Fresh metadata/object-info
checks match the existing loader discipline.

Init resolves the executable and independently checks its content hash against
the selected policy. The requester does not supply the executable digest or
either of the controller-minted endpoints. Init constructs ABI-2 argv exactly
`["system/wyrmsh"]` and an empty environment.

ShellV1 replies have the same reservation as the request, minor **1**, no
handles: type 2 LAUNCH_ACCEPTED is exactly 56 bytes with nonzero outer job ID at
48; type 15 ERROR is exactly 56 bytes with ErrorCode u32 at 48 and zero u32 at
52. Error codes 1-10 retain the WRLJ definitions. This is an additive versioned
reply entry point, not a change to minor-0 encoders. Later job operations on
that outer job use the unchanged minor-0 messages and reservation rules.

Only one outer shell construction may be pending/live for the current console.
Fresh parseable transactions enter replay tracking even on semantic rejection.
Retries use fresh transactions; neither duplicate request nor response loss
reconstructs the same launch. Cancellation retains the existing explicit
CancellationUnavailable result when synchronous construction cannot be cancelled.

## 3. WRLP Wyrmsh profile reservation

Reserve `LaunchProfile::Wyrmsh`, WRLP **1.11**, startup ABI **2**. WRLP profiles
have no enum-discriminant field on the wire: the explicit minor, exact role
shape and dedicated loader request select the profile. INIT is **160 bytes**;
READY is **40 bytes** and handle-free. No historical count/order/rights/bytes
may change when the internal loader capacity eventually rises from four to six.
E3B must cover both `launch::MAX_CAPABILITIES` (4 to 6) and
`process::Transaction::delegated_channels` (3 to 6), with a dedicated six-role
custody result and unchanged historical source-contract vectors. The same E3B
change covers `process.rs`'s 128-byte INIT scratch (at least 160), four-entry
transfer array (six), and rollback's explicit delegated indexes 0..2 (iterate
all six). Merely raising the public constant leaves those paths incomplete.

The common WRLP header remains: magic at 0; u16 major/minor at 4/6; u32 type
at 8; zero flags at 12; u32 total bytes at 16; u32 handle count at 20; nonzero
transaction u64 at 24; reserved zero u64 at 32. INIT type 1 has six handles;
READY type 2 has none. READY echoes the exact INIT transaction and minor. Init
also queries the exact Process generation and requires it still RUNNING;
READY raced with terminal state does not authorize publication.

| Index / descriptor offset | Role ID | Exact child role |
| --- | ---: | --- |
| 0 / 40 | 8 | stdin Channel |
| 1 / 48 | 9 | stdout Channel |
| 2 / 56 | 10 | stderr Channel |
| 3 / 64 | **16** | console-status Channel, newly reserved WRLP role |
| 4 / 72 | 6 | registry metadata client Channel |
| 5 / 80 | 7 | ShellJobs launch/session Channel |

Every descriptor is role u32 then reserved zero u32. Every final handle has
exact `READ | WRITE | WAIT | INSPECT`, without TRANSFER or DUPLICATE. There is
no self-root, TaskGroup, bootfs, DeviceResource, Interrupt or publication role.
The dedicated loader API requires all six roles/correlations together; generic
INIT encoding must not create a Wyrmsh record with zero correlation fields.

| Offset | Nonzero u64 correlation |
| ---: | --- |
| 88 | registry generation |
| 96 | registry endpoint ID |
| 104 | registry endpoint generation |
| 112 | ShellJobs connection ID |
| 120 | ShellJobs connection generation |
| 128 | console generation |
| 136 | status generation |
| 144 | child generation |
| 152 | outer launch transaction |

Registry/session correlations come from init's allocators; console/status/child
correlations are reserved by the exact current consoled endpoint relationship.
All are checked against controller-owned records. The header transaction is a
separately reserved controller-local WRLP transaction, not an alias of the outer
WRLJ transaction. Numbers do not confer rights. Init consumes WRRG transaction
1 for the startup metadata preflight below; shell registry requests begin at 2.

The shell validates ABI-2 startup, all six types/rights/order, correlations and
its initial bounded local state before READY. It must not wait for outer
LAUNCH_ACCEPTED, a status snapshot containing a job ID, a prompt drain or a
registry reply to send READY: the controller completes the independent registry
preflight before INIT. Registry installation MOVE and local session installation
precede INIT, but the MOVE alone is not an installation acknowledgement. Init
publishes the outer job only after exact READY, then sends LAUNCH_ACCEPTED and
closes the child bootstrap launch peer. The shell waits for that clean release
before operating or printing its prompt; consoled observes accepted before
declaring its child active. Release failure uses the same exact teardown path.

## 4. WRCN console status reservation

Reserve magic **WRCN**, major 1, minor 0; no conflict exists in the baseline
protocol sources. This is a separate direct Channel between one consoled and
one shell generation. It transfers **zero handles** and has only query,
snapshot and error messages. It cannot trigger recovery or change policy.

The common header is **48 bytes**:

| Offset | Type | Meaning |
| ---: | --- | --- |
| 0 | bytes[4] | `WRCN` |
| 4 / 6 | u16 / u16 | 1 / 0 |
| 8 / 12 | u32 / u32 | message type / flags zero |
| 16 / 20 | u32 / u32 | total byte count / handle count zero |
| 24 | u64 | nonzero transaction |
| 32 / 40 | u64 / u64 | nonzero console / status generation |

Types are **1 QUERY_STATUS** (48 bytes), **2 STATUS_SNAPSHOT** (160 bytes),
**3 ERROR** (56 bytes). Error body is u32 code at 48 and zero u32 at 52:
1 Malformed, 2 StaleGeneration, 3 Replay, 4 Unavailable. Unknown versions,
types, flags, enums, sizes, reserved values, handles or unsupported extensions
are rejected. A correlatable error echoes the *request* tuple, never the
replacement generation. Uncorrelatable malformed input terminates the relation
after received-handle cleanup. Requests have monotonically increasing checked
transactions with one outstanding operation; no counter wraps. Consoled keeps
a high-water mark for the live relationship. Rejected fresh parseable requests
consume their transaction; stale/replay queries do not return a snapshot.

Snapshot fields are copied from one local ConsoleModel observation, plus the
status relationship. They do not claim an atomic observation of other processes:

| Offset | Type | Meaning |
| ---: | --- | --- |
| 48 | u32 | state: 1 Active, 2 RetiringChild, 3 AwaitingReap, 4 Reconnecting, 5 Exhausted, 6 FailClosed |
| 52 | u32 | flags described below |
| 56 / 64 | u64 each | serial registry generation / publication generation |
| 72 / 80 / 88 | u64 each | device bundle / driver attempt / raw stream generation |
| 96 / 104 / 112 | u64 each | child generation / opaque outer job / outer launch transaction |
| 120 | u32 | live-peer mask: bit 0 stdin, bit 1 stdout, bit 2 stderr |
| 124 / 128 / 132 | u32 each | input / stdout / stderr queue bytes, each 0..4096 |
| 136 / 140 | u32 each | current rolling-window child / serial failures, each 0..4 |
| 144 | u32 | last failure category |
| 148 / 152 | u32 / u64 | zero reserved |

Flags: bit 0 serial present, 1 child present, 2 serial invalidated, 3 pending
launch, 4 pending launch cleanup, 5 child restart exhausted, 6 serial restart
exhausted. All other bits are zero. Serial fields are all nonzero iff bit 0 is
set and otherwise all zero. Child fields are all nonzero iff bit 1 is set and
otherwise all zero; no child implies zero peer mask. A pending launch may
therefore return no child/job yet. The generation in the header still identifies
the status relationship. A present child's generation and outer transaction
must equal the values bound in that shell's INIT; a snapshot cannot disclose
or rebind a replacement child on an old status peer. Exhaustion flags reflect
the model rather than an inferred lifetime retry total.

Last-failure IDs explicitly map current ModelError categories, not Rust enum
layout: 0 None, 1 ZeroCorrelation, 2 StaleCorrelation, 3 WrongConnectionState,
4 NoChild, 5 IncompleteCleanup, 6 AlreadyReserved, 7 UnknownReservation,
8 Backpressure, 9 TooLarge, 10 MonotonicRegression, 11 ArithmeticOverflow,
12 RestartExhausted, 13 SerialDisconnected, 14 ChildDisconnected,
15 WrongDirection. Future categories need a versioned contract revision.

No handles, kernel object IDs, raw pointers, process IDs or publication authority
appear in WRCN. Status/registry/launch peer closure is **fatal to the current
shell generation**. Closing status after serial or console replacement revokes
the old relationship; no endpoint is rebound. A status request has a 1000 ms
absolute monotonic-active deadline and bounded queue retry; timeout reports
unavailable and exits the shell rather than hanging or issuing duplicate queries.
No WRCN startup handshake is required before READY.

## 5. Launch transaction and failure precedence

The E0 model names every preparation/commit and tracks unique resources through
their owners. These steps are serialized per console, not a distributed atomic
transaction:

1. Consoled reserves a fresh child/status generation and outer transaction and
   prepares four Channel pairs. Init validates the received request/session and
   reserves outer job/accounting capacity before any fresh authority is minted.
2. After the four-endpoint request MOVE, init owns the received endpoints.
   It creates a fresh registry pair and issues fresh client/endpoint identities
   with BOOTSTRAP_METADATA scope. INSTALL_CLIENT MOVEs the registry-side peer
   into the registry control queue. That queue/registry owns it after commit.
3. Registryd applies the bounded cleanup-before-install rule below. Init sends
   ENUMERATE transaction 1 through the fresh registry peer it still owns and
   validates/drains the complete SERVICE_LIST reply sequence. Only then does
   it create a fresh ShellJobs pair and reserve/install a controller-local
   session in unpublished state. The child cannot use it until it owns the
   matching endpoint. No consoled endpoint is copied or shared.
   The outer shell job is the **sole owner** of the shell Process, TaskGroup
   and bootstrap launch handle. The nested session owns its controller Channel
   and child-job namespace only. It may store non-owning holder/outer-job
   correlation, never another owning `SessionOwner` for the same shell.
4. The dedicated loader transaction constructs the shell, then MOVEs exactly
   six child endpoints in INIT. Before that MOVE the caller/loader's explicit
   custody result governs rollback. After it, child teardown owns those handles;
   stale local handle numbers must never be closed as though still owned.
5. Exact READY permits job/session publication and LAUNCH_ACCEPTED. A failed
   response does not roll back a MOVE or publish a replacement: terminate/reap
   the unreachable shell and retire its session using the same cleanup path.
6. On shell terminal, the outer owner proves Process/TaskGroup teardown and
   destruction of the child-owned endpoints. Consoled closes its stream/status
   peers; registryd removes/closes its installed peer; init disconnects/closes
   its local ShellJobs controller endpoint exactly once. Neither init nor the
   nested session re-closes moved child handle numbers or independently reaps
   the shell. Published jobs follow retain-and-reap orphan policy and keep their
   old connection accounting; they do not become jobs of the replacement shell.
7. Replacement requires exact old-shell teardown, its construction/outer job
   accounting release and the registry ordering proof below. Allocate fresh
   R2/L2/S2; no identity or live endpoint
   from R1/L1/S1 is rebound. Checked identity/capacity/restart exhaustion stops
   admission and follows bounded recovery policy. A disconnected old ShellJobs
   connection with live orphan jobs retains its own bounded tombstone/accounting
   until those jobs reach terminal and are reaped. It may coexist with S2 when
   capacity permits; it never grants S2 access to those jobs. Normal shell exit
   does not silently terminate every old background job.

Ordinary S1-to-S2 child restart on healthy consoled C1 preserves C1's console
generation and ConsoleLauncher connection. It refreshes child/status/registry
client/ShellJobs identities and both launch transactions. Console or serial
replacement changes the corresponding console/outer connection relationship
as required by the existing consoled generation model.

| Failure boundary | Required disposition |
| --- | --- |
| Request preparation/send before commit | Consoled closes its own endpoints; init has no request-owned resources |
| Received malformed/policy/capacity rejection | Init closes only received endpoints; no registry/client/session construction |
| Registry pair creation or INSTALL send before commit | Local rollback and exact abort/release of outer reservation |
| After committed INSTALL, before usable child, including preflight failure | Close local endpoints; if registry slot retirement cannot be proved, poison the registry generation |
| Nested session installation/construction/INIT failure | Remove unpublished session exactly once; loader custody determines local close versus terminate/reap; apply registry poison rule |
| READY failure/timeout or accepted response loss | Terminate/reap any constructed child; retire session and outer accounting; apply registry poison rule if retirement is ambiguous |
| Successful shell exit | Exact shell reap/destruction, session disconnect and ordinary registry peer-close cleanup before the next registry install, established as below |
| Any cleanup failure | Preserve unresolved custody/accounting, block replacement; cleanup failure outranks original error |

Never invent an acknowledgement for WRRG v1 INSTALL_CLIENT. A successful send
means committed MOVE only. Post-MOVE ambiguous cleanup poisons the whole registry
generation; its existing bounded replacement path must prove terminal/reaped
before releasing unresolved registry custody. If that replacement exhausts,
follow the reached degraded/fatal recovery ladder rather than retrying forever.
Normal client peer-close cleanup is a registry-side event, not proof supplied
by `close()` succeeding in another process. E3C must implement these new
complementary obligations without changing WRRG's wire protocol:

1. Before sending the next shell client INSTALL, init proves the old shell
   terminal, reaped and torn down. The old child held the unique client peer
   without DUPLICATE or TRANSFER; its destruction therefore predates this send.
2. Before processing INSTALL_CLIENT, single-threaded registryd snapshots its
   bounded installed endpoints (at most 64: 32 clients plus 32 publication
   endpoints, `registryd::service::MAX_ENDPOINTS`), independently probes each exact
   handle for PEER_CLOSED with an immediate/nonblocking deadline, and retires
   every signaled endpoint through ordinary `peer_closed`/watch cleanup/close.
   READABLE must not mask PEER_CLOSED. One complete pass suffices because the
   required old shell peer was destroyed before the send; do not spin until
   concurrent clients stop closing. Probe/state/cleanup failure terminates the
   registry generation instead of installing on an uncertain state.
3. Registryd then processes the new INSTALL. Init sends ordinary ENUMERATE on
   the fresh retained client peer using transaction 1, with a 1000 ms absolute
   monotonic-active deadline. It must validate and drain **all** SERVICE_LIST
   pages: exact new registry/endpoint/transaction correlation, consecutive page
   indexes from zero, consistent page/total counts, bounded canonical records,
   no handles, and final page. Even an empty list has one page. Reject ERROR,
   closure, stale/malformed replies, timeout or incomplete drainage and poison
   the registry generation after ambiguous committed installation.
4. Only after that positive complete query does init transfer the fresh peer
   in the six-role INIT. The shell begins its registry transactions at 2.

The complete fresh-client response proves installation, scope and receiver
progress. Combined with destruction-before-send and cleanup-before-install,
it proves old-slot retirement before new admission. Init does **not** directly
observe a retirement acknowledgement. Merely receiving a response on R2 without
the registry sweep would not prove R1 retirement in a 32-client table. These
obligations are not implemented in the source baseline and must have E3C
service/adapter tests in addition to the E0 abstract ownership model.
This is a narrow WYR1-E refinement of the reached WYR1-B Section 5 no-ack
failure rule: incomplete proof still poisons, and historical WRRG bytes and
products remain unchanged. The proof applies to exact post-publication teardown,
including forced terminal/reap on console/serial replacement. Only E8's clean
exit gate claims normal exit with application code zero.

Registry generation replacement invalidates the old consoled and shell clients.
Init first retires the old shell/status/streams and console session, retaining
or reaping orphan jobs under the existing policy, and proves old process and
registry teardown. It then establishes the new registry and publication chain,
mints fresh consoled registry/ConsoleLauncher endpoints, reconnects serial and
constructs a fresh shell. The current D5 path does not already provide that full
replacement chain. E3C/E3D implement it; E8B later proves it live.

## 6. Immutable product/policy selection

Reserve additive **WRJP 1.1** in the existing launch-policy path. Preserve WRJP
1.0 parsing/building and historical product bytes. Header/64-byte records/path
pool stay structurally unchanged, with explicit version-selected validation:

- Existing JobV2 entries retain startup ABI 2, profile 1, category 1 (NORMAL),
  and stream-mode bits 1 zero-stream / 2 three-stream as already defined.
- New shell entry is exactly `system/wyrmsh`, startup ABI 2, profile **2
  (Wyrmsh)**, existing classification/category **1**, and existing three-stream
  mode **0b10** only. Profile 2 and ShellV1 jointly require three WRST endpoints
  plus one separate status endpoint; ordinary LAUNCH never admits profile 2.
  The content hash is the exact retained shell ELF. WRRM/RRC owns residency;
  category 1 alone never grants a ShellJobs caller permission to launch it.
- Other profile/category/mode combinations fail. Shell-approved JobV2 paths
  remain the explicit set in Section 1; category 1 alone does not grant launch.
- WRRM Wyrmsh role stays **5**, activation **3 ConsoleBound**, RRC-A residency.
  Reserve first-free startup profile **4 Wyrmsh** for the new product; profile
  **0 Retained** means retained-but-not-launchable and remains selected only by
  historical shell-stub products. Use explicit selected-product validation;
  do not weaken the global retained-profile rule or add an archive alias.

New selected consoled artifacts use ShellV1 through a ConsoleLauncher endpoint.
Selector32 retains its compiled console-echo child policy, Historical scope,
WRLJ 1.0 and exact three-stream transport actor. Keep current product inputs
and historical stub selection; do not globally replace a path constant.
E6 exports and hashes production `artifacts/wyrmsh.elf` explicitly as well as
binding it transitively through WRRM and bootfs; historical D5 exports remain
unchanged.

Reserve selector **33**, WYR1-E interactive shell, in documentation only.
Selector **34** remains reserved for final paired F. No selector registration,
test-ID dispatch, media or PASS record exists until E7; E0 does not invent an
acceptance certificate. E7 must assign unused exact test IDs and structured
evidence types against the registry it remeasures then.

## 7. Parser, editor and command contract

The active plan's Sections 3.8-3.14 are incorporated with these exact decisions.
E2's [input/editor contract](WYR1_E2_EDITOR_CONTRACT.md) now freezes decoder
resynchronization, printable-scalar filtering, history draft restoration and
80-column viewport redraw. It explicitly adds one fixed 4096-byte draft buffer
and resolves full-line redraw as the complete visible viewport, preserving the
4096-byte logical line and all parser/history bounds:

- Input is valid UTF-8, at most 4096 bytes; argv has at most 64 entries. NUL
  is rejected. One bounded, nonrecursive scan separates ASCII whitespace
  outside quotes. Single quotes are entirely literal until closing quote.
  Double quotes admit only `\\`, `\"`, `\n`, `\r`, `\t`; unquoted backslash
  escapes the next byte. Empty quoted arguments survive; unsupported escapes,
  trailing backslash, unclosed quote or invalid unescaped UTF-8 fail the whole
  command before dispatch. Pipes, redirection, semicolon, dollar, backtick,
  braces and parentheses are ordinary bytes, with no shell metasyntax.
- Controls are printable UTF-8 insertion, Left/Right, Home/End, Backspace/Delete,
  Up/Down history, Enter, Ctrl-C line cancellation and Ctrl-D exit only on an
  empty line. Tab becomes one ASCII space. No completion, multiline grammar,
  paste folding, terminal-width/DSR probing, POSIX signals or terminal takeover.
- Decode incrementally across WRST messages. Retain at most four UTF-8 bytes
  and twelve ESC/CSI bytes (16 total); commit only valid whole scalars. Invalid,
  overlong/surrogate/out-of-range/stray continuation or incomplete-on-submit
  UTF-8 is rejected. Unknown/overlong control sequences are consumed as controls,
  never reinserted as executable text. E2 freezes exact discard/resynchronization
  transitions under this rule. Cursor positions are UTF-8 scalar boundaries;
  full grapheme and display-width semantics remain deferred.
- Fixed storage: 4096-byte line, 4096 parser scratch, 64 argv descriptors,
  32 history descriptors with a 16 KiB byte arena, 16 pending decoder bytes,
  4096 output/redraw scratch, plus E2's 4096-byte history draft. Evict oldest history to fit; failure to retain a
  line never prevents otherwise valid execution. E2 redraw uses a fixed 80-column horizontal viewport with at most 71 visible
  scalars and may emit it incrementally through bounded scratch. The full logical
  line remains stored and editable; no terminal-width query is introduced.
- The reached 128 KiB child mapping has a 20 KiB ABI-2 startup block: actual
  downward-growing working stack is **108 KiB**. E2/E6 must measure stack use;
  E0's buffer totals are not a stack measurement or native execution proof.

| Command | Frozen semantics |
| --- | --- |
| help | Compiled fixed command/usage metadata |
| echo | Parsed arguments separated by one space then newline; no further escape evaluation |
| clear | Bounded ANSI clear/home then fresh prompt |
| exit | Normal current-shell exit under consoled's bounded restart policy |
| services | Own BOOTSTRAP_METADATA ENUMERATE; canonical service names, protocol/version set and service generation, no handles/PIDs |
| tasks | Own ShellJobs LIST_JOBS; only visible opaque job IDs and bounded controller state |
| status | WRCN snapshot plus local endpoint health, read-only |
| run | Foreground ordinary three-stream launch, terminal result and output drainage, close completed job then prompt |
| spawn | Background ordinary zero-stream launch, print opaque job ID then prompt |
| wait | Wait for owned job, print structured result, close completed record on success |
| terminate | Request termination of active owned job and report acceptance; no implicit wait |

Job IDs are canonical nonzero unsigned decimal u64, no sign/leading zero or
overflow. For `run`, create three fresh child stream pairs; after publication
close the shell's child-stdin writer so the child sees EOF. Drain stdout and
stderr fairly into shell output with bounded backpressure, and wait for the
authoritative job result. Drain all previously committed output or report an
explicit stream failure before prompt. Editing Ctrl-C never kills a child;
keys are not forwarded during synchronous run. ShellJobs peer loss retires
administration and exits; no fallback to ambient process enumeration.

## 8. E0 gate and downstream nonclaims

The test-only host model lives at
`crates/wyrmroot-launch-proto/tests/wyr1e_e0_model.rs`. Its gate requires failure
injection at every prepare/commit edge, exact current ownership and close/reap
accounting, delayed/ambiguous cleanup, stale-event rejection and fresh S1-to-S2
construction. It does not execute native Channels or prove that E3 implements
the model. E3A-D must separately prove minor-0 compatibility, six-role loader
custody, registry/session construction and real consoled integration.

E0 claims no shell executable, parser/editor implementation, live selector33,
VM run, historical regression rerun, new hardware support, runtime security
gate or final DW1/WYR1 closure. Exact E0 tests, source provenance and closure
identities are recorded in the companion inventory.
