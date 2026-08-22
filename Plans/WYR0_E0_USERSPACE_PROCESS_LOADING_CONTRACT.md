# Wyrmroot WYR0-E0 Userspace Process-Loading Contract

**Status:** WYR0-E0 architecture closure; authoritative for WYR0-E/F/G implementation  
**Prepared:** 2026-08-22  
**Wyrmroot baseline:** `1b091043762fbb1aff65ce8ea5ef855d99fb4de3`  
**Paired Deepwyrm baseline:** `cbc27fd4d09378ff0dee04e3dd66da6763e7083d`  
**Paired contract:** `deepwyrm/Plans/DW0_H0_SMP_CONCURRENCY_CONTRACT.md`  
**Milestone:** reusable static userspace loader and `bootstrap -> init0 -> hello`

This contract freezes the narrow executable subset, child-construction
transaction, capability distribution, and observation protocol needed to prove
ordinary process creation from Wyrmroot userspace. It refines WYR0-D0 and the
paired Deepwyrm G0 contract without defining a VFS, general `exec`, dynamic
linker, libc process API, or service manager.

The baseline hashes are pre-contract design inputs. The OS-Project coordination
plan binds the final compatible Deepwyrm/Wyrmroot contract commit pair after both
independent repositories commit H0.

## 1. E0 disposition: compose the generated native ABI

No new Deepwyrm syscall or object is required. `wyrmroot-loader` composes the
existing generated operations for handle duplication/close, object and task
inspection, Process/Thread construction and termination, MemoryObject mapping,
Channel creation/transfer, and waits.

The public `deepwyrm-syscall` crate must add safe typed wrappers for the existing
generated calls needed by E; it must not reproduce numeric IDs, record layouts,
rights, or raw assembly locally. The required wrapper surface is:

- `handle_close`, `handle_duplicate`;
- basic, MemoryObject, and task-state `object_get_info_v1` topics;
- `process_create`, `process_terminate`;
- `thread_create`, `thread_start`, `thread_terminate`;
- `memory_object_create`;
- `address_region_map`, `address_region_unmap`, and
  `address_region_protect` even when the first loader can avoid a protect step;
- `channel_create`, `channel_send`, `channel_receive`; and
- `wait_one` and `wait_many`.

Process/thread exit wrappers remain runtime terminal operations. WYR0 does not
use an unknown raw syscall ID, a kernel `exec(path)`, a host filesystem share,
or a hand-copied ABI veneer to fill a wrapper gap.

## 2. Accepted native ELF64 subset

WYR0-E accepts only artifacts produced by the pinned
`x86_64-unknown-wyrmroot` static toolchain and `toolchain/native-user.ld` that
satisfy all rules below:

- ELF64, little-endian, x86-64, ELF current version;
- static `ET_EXEC` only; `ET_DYN`, PIE, shared objects, and relocatable objects
  are rejected;
- input length `1..=16 MiB`;
- program-header entry size exactly the ELF64 size, at most 16 program headers,
  and at most 8 `PT_LOAD` segments;
- only `PT_LOAD`, optional `PT_PHDR`, and optional `PT_GNU_STACK` are accepted;
- `PT_INTERP`, `PT_DYNAMIC`, `PT_TLS`, `PT_NOTE`, `PT_GNU_RELRO`, runtime
  relocations, and every unrecognized program-header type are rejected;
- at most one `PT_PHDR` and one `PT_GNU_STACK`; if present, the stack record must
  not request execute permission;
- every `PT_LOAD` has `filesz <= memsz`, a nonzero memory size, valid power-of-two
  alignment no smaller than 4096, and congruent file offset/virtual address;
- all file, raw virtual, page-rounded virtual, and aggregate-size arithmetic is
  checked before any kernel object is created;
- file ranges remain inside the exact bootfs entry bytes;
- page-rounded virtual ranges exclude page zero, are lower-canonical userspace
  below `0x0000_8000_0000_0000`, and do not overlap one another, the initial
  guard/stack range, or reserved startup metadata;
- accepted segment protections are `READ`, `READ | WRITE`, or
  `READ | EXECUTE`; write-only, execute-only, and writable-executable segments
  are rejected;
- the entry address is lower-canonical and lies in the file-backed or zero-fill
  extent of one executable `PT_LOAD` segment; and
- the sum of page-rounded `PT_LOAD` extents is at most 32 MiB.

Section headers, symbols, debug sections, and section names are not loader input.
The host artifact-inspection gate separately proves there is no dynamic section,
interpreter, relocation, undefined symbol, executable stack, or duplicate raw
Deepwyrm syscall veneer.

These are WYR0 limits, not a stable general Wyrmroot executable ABI. Expanding
the subset requires an explicit later contract and adversarial tests; unknown
ELF forms fail closed.

## 3. Segment image planning and materialization

The parser produces a complete immutable load plan before construction begins.
For each `PT_LOAD`, the plan records checked file range, raw memory range,
page-rounded child range, in-page leading displacement, final protections, and
logical content length.

WYR0-E uses one zero-filled page-backed MemoryObject per `PT_LOAD` extent. Its
size is exactly the page-rounded segment extent and its parent handle has exact
rights:

`READ | WRITE | EXECUTE | MAP | INSPECT`

No mapping receives all those permissions. The rights permit the loader to make
one temporary parent `READ | WRITE` alias and, after removing it, one final child
`READ`, `READ | WRITE`, or `READ | EXECUTE` mapping.

Materialization is:

1. create the zero-filled MemoryObject;
2. map its complete extent `READ | WRITE` into the loader's own root
   AddressRegion at allocator-chosen placement;
3. copy exactly `p_filesz` bytes to the checked leading displacement;
4. explicitly zero the complete prefix, BSS range, and page slack not supplied
   by file bytes, even though creation already promises zero-filled pages;
5. unmap the complete temporary parent alias and verify success; and only then
6. map the object into the child root at the exact fixed page-rounded ELF
   virtual address with final protections.

There is never a writable parent alias while an executable child mapping exists.
WYR0-E does not rely on a later protect call to turn an RW mapping into RX, and
it never creates a W+X mapping during construction. A failed parent unmap aborts
before executable publication.

The source bootfs mapping remains read-only and borrowed for the complete parse
and copy. The loader reads only the entry's exact logical bytes, not bootfs page
padding. Segment MemoryObjects and handles are loader-owned until their child
mappings capture the required leases; closing a handle never substitutes for
an unmap that this transaction requires.

## 4. Initial stack and startup state

Every E-created child begins with one unmapped 4 KiB guard followed by exactly
64 KiB of `READ | WRITE`/NX stack mapping. The fixed stack top for WYR0 is
`0x0000_7fff_ffff_0000`; therefore the mapped stack is
`[stack_top - 64 KiB, stack_top)` and the guard is the immediately preceding
4 KiB page. An accepted ELF must not overlap either interval.

The stack MemoryObject is zero-filled, materialized through a temporary parent
RW alias, unmapped from the parent, then mapped into the child RW/NX. Its highest
mapped page is the startup block. Initial `RSP` is the base of that page
(`stack_top - 4096`), leaving 60 KiB below it for downward-growing stack use.
The startup block uses the WYR0-D0 little-endian `argc`/`argv`/`envp`/auxv
layout, all pointers remain inside the same 4 KiB page, and unused bytes stay
zero.

For the H chain:

- `argc = 1`;
- `argv[0]` is the caller-selected canonical UTF-8 display path
  (`/system/init0` or `/bin/hello`) stored in the startup page;
- the environment is empty;
- auxv contains only terminal `(0, 0)`; and
- `RSP` is 16-byte aligned.

`DwThreadStartArgsV1` is exact V1 with zero flags/reserved fields:

- `entry` = validated executable entry;
- `stack_pointer` = startup-block base;
- `startup_argument0` / `RDI` = actual child-local launch Channel handle returned
  by `process_create`;
- `startup_argument1` / `RSI` = Wyrmroot startup ABI version `1`.

No magic handle value, inherited register, ambient environment, TLS base,
dynamic-linker state, or executable-stack convention is implied.

## 5. Primordial TaskGroup refinement

WYR0-D0 `BOOTSTRAP_INIT_V1` remains the exact two-capability DW0-G regression
protocol. It cannot enable userspace process construction because bootstrap has
no TaskGroup handle and generated `process_create` requires one.

The canonical H chain uses `BOOTSTRAP_INIT_V2` with the existing 40-byte `WRBP`
header format, protocol major `1`, minor `1`, message type `INIT`, flags zero,
total size `64`, capability count `3`, nonzero transaction ID `1`, and reserved
zero. Its three eight-byte role descriptors and transferred handles are exactly:

1. `SELF_ROOT_ADDRESS_REGION` (`role = 1`): AddressRegion with
   `MAP | MODIFY | INSPECT`;
2. `BOOTFS_MEMORY_OBJECT` (`role = 2`): MemoryObject with
   `READ | MAP | INSPECT | DUPLICATE | TRANSFER`; and
3. `LOADER_TASK_GROUP` (`role = 3`): TaskGroup with
   `MODIFY | INSPECT | DUPLICATE | TRANSFER`.

The canonical payload bytes are:

```text
57 52 42 50 01 00 01 00 01 00 00 00 00 00 00 00
40 00 00 00 03 00 00 00 01 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 01 00 00 00 00 00 00 00
02 00 00 00 00 00 00 00 03 00 00 00 00 00 00 00
```

`BOOTSTRAP_READY_V2` retains the 40-byte header, uses major `1`, minor `1`, type
`READY`, total size `40`, capability count zero, transaction `1`, and zero
reserved fields. Bootstrap validates receive metadata and fresh object info for
all three handles before use. Exact masks are required; over-broad authority is
rejected.

The TaskGroup is an ordinary delegated object under the primordial hierarchy.
It supplies only explicit descendant-process construction/termination authority.
It grants no scheduler class, ancestor control, service-manager status, or
resource-budget promise.

## 6. Child construction authority and exact handles

The loader receives an explicit `LoadAuthority` containing its own root
AddressRegion, immutable bootfs view, and loader TaskGroup. It never discovers
them globally.

Because generated `channel_create` gives both new endpoints the same requested
mask, the loader initially creates the pair with exact rights:

`READ | WRITE | WAIT | DUPLICATE | TRANSFER | INSPECT`

It immediately duplicates the endpoint it will retain down to exact
`READ | WRITE | WAIT | INSPECT` and closes that endpoint's original broad
handle. The other original endpoint supplies the required `TRANSFER` to
`process_create`; `child_bootstrap_rights` reduces the installed child handle to
exact `READ | WRITE | WAIT | INSPECT`. No broad parent endpoint remains when
the child starts.

`DwProcessCreateArgsV1` uses:

- explicit loader TaskGroup with `MODIFY`;
- the transferable child Channel endpoint;
- returned Process rights `WAIT | MODIFY | INSPECT`;
- returned root AddressRegion rights
  `MAP | MODIFY | INSPECT | TRANSFER`; and
- zero flags/reserved fields.

The loader maps the child image through the returned root. Before launch it
moves that root handle to the child through the launch Channel with rights
reduced to exact `MAP | MODIFY | INSPECT` when the selected launch profile needs
the child to load descendants. A leaf child receives no unused self-root
capability; the parent closes its root handle during post-start cleanup.

The initial Thread handle has exact `EXECUTE | MODIFY | INSPECT`, permitting
start and pre-publication rollback. The parent retains no Thread handle after a
successful start. The Process handle is returned as the only long-lived task
observation/control handle.

Bootfs and TaskGroup delegation uses reduced duplicates followed by the ABI's
move-only Channel transfer, so the parent keeps its own authority. No source
handle is moved speculatively when losing it would prevent rollback or later
descendant construction.

## 7. WYR0 child-launch wire protocol

Ordinary Wyrmroot parent/child launch uses a small protocol distinct from the
kernel-owned primordial `WRBP` transaction. This avoids teaching Deepwyrm
application paths or service-manager policy.

The launch header is the same field layout as the D0 header but has magic
`WRLP`, major `1`, minor `0`:

| Offset | Width | Field | Rule |
|---:|---:|---|---|
| 0 | 4 | magic | ASCII `WRLP` |
| 4 | 2 | major | little-endian `1` |
| 6 | 2 | minor | little-endian `0` |
| 8 | 4 | type | `1=INIT`, `2=READY` |
| 12 | 4 | flags | zero |
| 16 | 4 | total size | exact bytes |
| 20 | 4 | capability count | exact descriptor/handle count |
| 24 | 8 | transaction ID | caller-minted nonzero value |
| 32 | 8 | reserved | zero |

Each capability descriptor is `role: u32, reserved: u32`. Roles reuse the
semantic names in section 5 but are interpreted only inside Wyrmroot's launch
protocol.

Two exact profiles exist in WYR0:

- `INIT0`: INIT size `64`, count `3`, roles in order self root, bootfs, loader
  TaskGroup, with the exact reduced rights from sections 5 and 6;
- `HELLO`: INIT size `40`, count `0`, with no capabilities.

READY is exactly the 40-byte header, count zero, echoes the transaction ID, and
carries no handles or trailing bytes. Wrong version/type/size/count/order,
duplicate or unknown role, zero transaction, nonzero reserved data, unexpected
handle, wrong type, or non-exact rights fails closed.

The parent queues the complete INIT only after child mappings, startup bytes,
Thread resources, and all rollback authority exist, but before `thread_start`.
The child validates its startup Channel and one exact INIT before sending READY.
`hello`'s handle-free INIT/READY Channel exchange is its required non-printing
kernel-object smoke operation.

## 8. Failure-atomic construction and rollback

One launch is a transaction with `thread_start` as the final externally
observable publication action:

1. validate the exact bootfs entry and complete ELF/load/startup plan without
   allocating child state;
2. prepare the Channel pair and reduced capability duplicates;
3. call transactional `process_create`, leaving the child CREATED and
   unrunnable;
4. materialize each segment/stack MemoryObject through a temporary parent alias,
   remove that alias, and map the final child range;
5. create the initial Thread in CREATED state;
6. queue one complete launch INIT, atomically moving only the selected child
   capabilities;
7. ensure no recoverable parent-side allocation, parse, copy, or protocol
   preparation remains; and
8. call `thread_start` as final commit.

Rollback proceeds in reverse ownership order and is idempotent by explicit
state tracking:

- before Process creation, close both Channel endpoints, all reduced duplicates,
  MemoryObject handles, and remove every temporary parent mapping;
- after Process creation but before Thread creation, unmap any published child
  ranges while the parent still owns the root, then terminate/close the Process
  and close remaining handles;
- after Thread creation, terminate the Thread if needed, then terminate the
  still-unrunnable Process and perform the prior cleanup;
- after INIT transfers the child root/capabilities, do not attempt to recreate
  or forge moved handles: terminate the Process, whose handle table and queued
  Channel payload own deterministic drain/finalization, then close the parent
  peer and remaining parent handles; and
- if `thread_start` reports failure, treat publication as uncommitted, terminate
  the Process, drain by ordinary teardown, and return failure.

No error path leaves a writable temporary alias, CREATED task with an execution
pin, queued reference cycle, or parent handle in an unknown moved state.
Successful `thread_start` consumes the transaction: later READY/exit failure is
a launched-child failure, not construction rollback, and uses authorized
Process termination only when bounded supervision must stop the child.

## 9. Readiness and exit observation

Bootstrap supervising `init0` and `init0` supervising `hello` use the same
bounded state machine:

```text
Constructed -> StartedAwaitingReady -> ReadyAwaitingExit -> Complete
```

The parent retains only its launch Channel endpoint and Process handle. It waits
with generated `wait_many` for Channel `READABLE | PEER_CLOSED` and Process
`EXITED`, using the existing monotonic deadline representation selected by the
integration test. It receives and validates exactly one READY before accepting
exit.

The following are failures: Process exit before READY; peer close with no queued
READY; malformed, duplicate, or capability-bearing READY; transaction mismatch;
unexpected Channel handles; wait failure; non-normal termination; or nonzero
application exit code. The parent still observes/reaps structured task state and
closes its handles on failure.

After valid READY, peer close is permitted. Completion requires Process
`EXITED`, fresh `DW_OBJECT_INFO_TASK_STATE_V1`, state `EXITED`, reason
`NORMAL_EXIT`, application code `0`, and zero exception fields. A Channel marker
or diagnostic string never substitutes for structured Process exit.

This is temporary bounded parent/child supervision only. It defines no PID 1,
restart policy, daemon lifecycle, service naming, stdio, signal, orphan, job,
session, or final process-parenting semantics.

## 10. Concrete H-chain capability flow

The complete authority flow is:

```text
Deepwyrm -> bootstrap:
  self root + immutable bootfs + loader TaskGroup

bootstrap -> init0:
  init0 self root + reduced bootfs duplicate + reduced TaskGroup duplicate

init0 -> hello:
  no capabilities; launch Channel only
```

Bootstrap maps bootfs through its own root, loads `/system/init0`, sends INIT0
launch INIT, waits for READY and normal exit `0`, then exits `0`. `init0` maps
the delegated bootfs through its own root, loads `/bin/hello` through the same
`wyrmroot-loader` API, sends the HELLO launch INIT, waits for READY and normal
exit `0`, then exits `0`. `hello` validates startup/INIT, sends READY, performs
its smoke behavior, and exits `0`.

No child receives the parent's Process handle, Thread handle, Channel peer,
MemoryObject segment handles, physical-memory authority, ancestor TaskGroup,
unrelated bootfs writer, or hidden service capability.

## 11. H0 closure and implementation gates

E0 closes with the paired Deepwyrm H0 contract when review confirms:

- the static ELF subset matches the pinned native toolchain output;
- every operation is already present in the generated Deepwyrm ABI;
- the TaskGroup gap is solved by explicit existing-object delegation rather than
  a new kernel primitive or magic self handle;
- temporary aliases, child mappings, stack/startup state, capabilities, and
  reverse rollback ownership are complete before `thread_start`;
- the parent observes both READY and structured Process exit; and
- no dynamic linking, kernel path execution, host share, general service
  manager, or scheduler-policy dependency entered WYR0-E.

E implementation must add hostile-input host tests for every arithmetic,
header/type, overlap, protection, stack, capability, transaction, and rollback
rule above before the live `bootstrap -> init0 -> hello` gate is accepted.
