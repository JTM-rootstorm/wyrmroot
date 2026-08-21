# Wyrmroot WYR0-D0 Primordial Startup Contract

**Status:** WYR0-D0 architecture closure; authoritative for WYR0-D primordial startup/protocol implementation
**Prepared:** 2026-08-21
**Wyrmroot baseline:** `92a33b4aae14dad29f1a2ae407cb5be10ccf7ffe`
**Implementation anchor:** `edc1071f78f4418c05e5bd0762b1c3fb760df094`
**Paired Deepwyrm baseline:** `557f1d9aa801e90b76b7012d827e2bebba2109e1`
**Paired contract:** `deepwyrm/Plans/DW0_G0_PRIMORDIAL_STARTUP_CONTRACT.md`
**Milestone:** WYR0-D native runtime/bootstrap protocol plus DW0-G primordial handoff

This contract locks the Wyrmroot-owned startup and bootstrap-protocol semantics consumed by Deepwyrm G. It refines the WYR0 plan, platform conventions, WYR0-C bootfs contract, active workspace G plan, and paired Deepwyrm G0 contract.

The baseline hashes above are the pre-contract design inputs. Because independent Git repositories cannot embed each other's final contract commit without a circular hash dependency, the OS-Project root closure record binds the final post-contract Deepwyrm/Wyrmroot commit pair.

It does not implement the runtime or protocol. D1 consumes this record to turn the existing deliberate scaffolds into tested code.

## 1. D0 disposition and dependency direction

No public ABI or Deepwyrm schema change is required for this contract. Wyrmroot consumes the existing pinned ABI mechanisms rather than copying or widening them.

The current Wyrmroot manifest pin is Deepwyrm `6de5af17dfef979aeadc150ce3958cd941fedbb2`. Read-only inspection confirms that pinned revision already contains `DwMemoryObjectInfoV1`, `DwProcessCreateResultV1.child_bootstrap_handle`, `DwThreadStartArgsV1.startup_argument0/1`, and the exact-size `address_region_map` contract used here. D0 therefore leaves the manifest pin unchanged. Before accepted G target/VM integration, Wyrmroot must deliberately repin to the exact frozen Deepwyrm G implementation candidate; ABI compatibility with the older pin is not machine-code/runtime acceptance.

`wyrmroot-bootstrap-proto` remains a dependency-free `no_std` wire/role library. It must not hand-copy Deepwyrm object-type IDs, rights bits, syscall numbers, or handle values. `wyrmroot-runtime`, which consumes the exact pinned Deepwyrm ABI/syscall package, binds each Wyrmroot capability role to the required Deepwyrm object type and rights.

This split keeps:

```text
Wyrmroot wire roles
        |
Wyrmroot runtime role validation
        |
pinned Deepwyrm ABI types/rights
```

rather than creating a second kernel ABI truth table in the protocol crate.

## 2. Native startup ABI version 1

For a newly started Wyrmroot-native process using startup ABI version `1`:

- `RDI` / `startup_argument0` is the actual process-local bootstrap Channel handle;
- `RSI` / `startup_argument1` is the numeric startup ABI version `1`;
- `RSP` points at the first word of the bounded startup vector;
- `RIP` is the executable entry selected by the userspace/kernel loader that owns this launch;
- other initial general-purpose registers do not carry Wyrmroot authority or hidden startup pointers; and
- authority is never encoded in environment variables, path names, or reserved handle numbers.

A runtime presented with another startup ABI version fails before consuming bootstrap authority. Startup ABI versioning is independent of the bootstrap Channel protocol major/minor version.

## 3. Startup stack byte contract

Startup ABI V1 uses a conventional vector of little-endian 64-bit words:

```text
argc
argv[0] ... argv[argc-1]
0
envp[0] ... envp[n-1]
0
aux_type, aux_value
...
0, 0
string/data bytes referenced above
```

For the DW0-G primordial process, the vector and every referenced string/data byte must fit wholly within one 4096-byte **startup block** beginning at `RSP`. The runtime therefore validates all counts, pointer arithmetic, terminators, and string extents against `[RSP, RSP + 4096)` before creating borrowed views.

The concrete primordial startup is:

- `argc = 1`;
- `argv[0]` is NUL-terminated UTF-8 `wyrmroot-bootstrap` inside the startup block;
- `argv[1] = 0`;
- environment is empty and immediately terminated by zero;
- auxv has no entries before terminal `(0, 0)`;
- `RSP` is 16-byte aligned; and
- unused startup-block bytes are zero.

Deepwyrm maps 64 KiB RW/NX for the primordial stack, with one unmapped 4 KiB guard page below it. The startup block is the highest mapped page and `RSP = stack_top - 4096`, leaving 60 KiB of normal downward-growing stack below `RSP`.

D1 may test additional bounded nonempty argv/environment vectors for parser correctness, but no additional primordial startup data is implied by G0.

## 4. Bootstrap Channel capability

The raw value in `RDI` is opaque process-local data. The runtime does not assume a fixed handle value and does not search a global handle namespace.

Before protocol use, the runtime queries `DW_OBJECT_INFO_BASIC_V1` and requires the bootstrap handle to be:

- object type `CHANNEL`; and
- exact rights `READ | WRITE | WAIT | INSPECT`.

An invalid handle, wrong type, missing right, or additional unexpected right fails closed. G0 grants no `DUPLICATE` or `TRANSFER` on this Channel.

## 5. Bootstrap protocol encoding

All bootstrap wire integers are little-endian. The protocol is encoded/decoded field-by-field; serializing a Rust `repr(C)` or ordinary in-memory struct is forbidden.

The fixed V1 header is exactly 40 bytes:

| Offset | Width | Field | Rule |
|---:|---:|---|---|
| 0 | 4 | magic | ASCII bytes `WRBP` |
| 4 | 2 | major | `1` |
| 6 | 2 | minor | `0` |
| 8 | 4 | message type | `1=BOOTSTRAP_INIT_V1`, `2=BOOTSTRAP_READY_V1` |
| 12 | 4 | flags | zero |
| 16 | 4 | total size | exact encoded message size |
| 20 | 4 | capability count | exact role/handle count |
| 24 | 8 | transaction id | nonzero; G0 INIT is `1` |
| 32 | 8 | reserved | zero |

Each INIT capability-role descriptor is exactly 8 bytes:

| Offset | Width | Field | Rule |
|---:|---:|---|---|
| 0 | 4 | role | explicit Wyrmroot role ID |
| 4 | 4 | reserved | zero |

Object type and rights are **not encoded as attacker-controlled duplicate truth** in the wire descriptor. Each role has one semantic type/right contract in Section 7, bound by `wyrmroot-runtime` to the exact pinned `deepwyrm-abi` constants.

The maximum G0 bootstrap message is 56 bytes and 2 handles, far below Deepwyrm's current 64 KiB/16-handle Channel limits. D1 constants should nevertheless be derived from this protocol contract rather than from the kernel maxima.

## 6. INIT and READY messages

`BOOTSTRAP_INIT_V1` is exactly 56 bytes:

- V1 header with message type `1`;
- flags zero;
- total size `56`;
- capability count `2`;
- transaction id `1` for the primordial G0 exchange;
- reserved zero;
- descriptor 0: role `1 = SELF_ROOT_ADDRESS_REGION`, reserved zero;
- descriptor 1: role `2 = BOOTFS_MEMORY_OBJECT`, reserved zero; and
- exactly two transferred handles corresponding one-for-one to descriptor order.

`BOOTSTRAP_READY_V1` is exactly 40 bytes:

- V1 header with message type `2`;
- flags zero;
- total size `40`;
- capability count `0`;
- transaction id exactly echoing INIT (`1` in G0);
- reserved zero;
- no descriptors, no transferred handles, and no trailing bytes.

The decoder rejects wrong magic, unsupported major/minor, unknown message type, nonzero flags/reserved fields, wrong exact size, count/size inconsistency, unknown/duplicate/wrong-order roles, unexpected handles, and trailing garbage.

Minor version `0` does not permit implicit optional fields. A future compatible extension must define explicit minor-version parsing rules before using them.


### G0 golden wire vectors

The canonical payload bytes, excluding Channel handle metadata, are:

`BOOTSTRAP_INIT_V1` (56 bytes):

```text
57 52 42 50 01 00 00 00 01 00 00 00 00 00 00 00
38 00 00 00 02 00 00 00 01 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 01 00 00 00 00 00 00 00
02 00 00 00 00 00 00 00
```

`BOOTSTRAP_READY_V1` (40 bytes):

```text
57 52 42 50 01 00 00 00 02 00 00 00 00 00 00 00
28 00 00 00 00 00 00 00 01 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00
```

These vectors are shared test inputs. Changing either vector requires a coordinated G0/D0 contract revision; an implementation must not regenerate a different layout from local struct packing.

## 7. Capability-role semantics

The two INIT roles are exact contracts:

### Role 1: `SELF_ROOT_ADDRESS_REGION`

- expected Deepwyrm object type: `ADDRESS_REGION`;
- exact rights: `MAP | MODIFY | INSPECT`;
- no `DUPLICATE`, `TRANSFER`, or other rights.

### Role 2: `BOOTFS_MEMORY_OBJECT`

- expected Deepwyrm object type: `MEMORY_OBJECT`;
- exact rights: `READ | MAP | INSPECT | DUPLICATE | TRANSFER`;
- no `WRITE` or `EXECUTE`.

The runtime maps these semantic requirements using imported `deepwyrm-abi` constants. `wyrmroot-bootstrap-proto` owns only the role IDs/order and wire parser.

For each received handle the bootstrap performs two checks before use:

1. require `DwReceivedHandleInfoV1` object type and rights to equal the role contract; and
2. issue a fresh `DW_OBJECT_INFO_BASIC_V1` query on the new local handle and require the same exact type and rights.

Exact equality is intentional. An over-broad capability is a protocol violation, not a convenience.

Any failure closes/discards received capabilities as far as the current runtime can do safely and exits nonzero without mapping bootfs or sending READY.

## 8. Bootfs logical length, mapping, and borrow lifetime

After role validation, bootstrap queries `DW_OBJECT_INFO_MEMORY_OBJECT_V1` on the bootfs handle.

The reported `byte_size` is the sole logical archive extent and must be:

- nonzero;
- at most the WYR0-C 32 MiB encoded archive limit; and
- representable by checked `align_up(byte_size, 4096)` without overflow.

Bootstrap maps exactly that rounded capacity at MemoryObject offset `0`, allocator-chosen address, with protection exactly `READ`, through its self-root region. The received root region carries the `MAP | MODIFY` rights required by the existing Deepwyrm map operation.

The final page may contain zero hardware-addressable padding between logical size and rounded mapping capacity. That padding is not archive input. `wyrmroot-bootfs::Archive` receives exactly:

```text
&mapping[0 .. byte_size]
```

and no more.

Every archive object/entry/payload borrow is tied to that mapping. Bootstrap must not unmap, remap, protect, close the backing authority in a way that invalidates it, or otherwise change the mapped bytes until all borrowed parser slices are dead.

G0 requires the Deepwyrm backing to remain immutable/non-writable for this lifetime. Wyrmroot never requests a writable mapping.

## 9. Primordial bootstrap success behavior

For the DW0-G checkpoint, real `bootstrap.elf` performs only:

1. validate startup ABI version and startup block;
2. validate the bootstrap Channel type/rights;
3. receive exactly one INIT datagram;
4. decode/validate its exact envelope and two roles;
5. validate both received capabilities by receive metadata and fresh object info;
6. query and map bootfs read-only using exact logical size;
7. parse it using `wyrmroot-bootfs`;
8. confirm canonical archive paths `system/init0` and `bin/hello` exist as the required real executable entries;
9. send exact `BOOTSTRAP_READY_V1` with no handles; and
10. call native `process_exit(0)`.

This is a WYR0-F bring-up checkpoint, not WYR0-F closure. It does not load or start `init0` yet.

A nonzero bootstrap exit code may provide unstable implementation diagnostics during D/G. No numeric failure-code taxonomy is frozen by this contract.

## 10. Kernel-side construction assumptions consumed by Wyrmroot

Wyrmroot relies on the paired Deepwyrm G0 guarantees that:

- the bootstrap ELF was completely validated before launch;
- load mappings are W^X and page-rounded ranges cannot overlap;
- the user stack is RW/NX with a guard page;
- startup metadata and initial capabilities are complete before the Thread becomes runnable;
- INIT handle transfer uses the ordinary F atomic move machinery;
- transferred rights never exceed source rights;
- bootfs logical size equals the loader's exact BootInfo module `byte_len`;
- bootfs final-page slack is zero and never contains unrelated bytes; and
- any failure before runnable publication leaves no child-visible partial state.

Wyrmroot does not require or infer how Deepwyrm internally represents the ephemeral stager or boot-module backing.

## 11. Process exit and handshake result

A successful G handshake requires both:

- Deepwyrm receives a valid READY for the INIT transaction; and
- Deepwyrm later observes structured `NORMAL_EXIT` with `application_code = 0` for the primordial Process.

READY is sent before `process_exit(0)`. F Channel semantics permit the already committed READY to remain receivable after peer close/process teardown.

Peer closure before READY, malformed READY, `UNHANDLED_EXCEPTION`, explicit termination, or nonzero normal exit is failure. Wyrmroot must not convert a bootstrap fault into a fake success marker.

## 12. Production versus diagnostic channels

The production architectural proof uses only:

- real EFI/BootInfo-delivered bootstrap and bootfs artifacts;
- native startup registers/stack;
- the bootstrap Channel and exact INIT/READY protocol;
- native MemoryObject/AddressRegion operations; and
- structured Process exit.

COM1 traces, test-only Deepwyrm debug exits, test selectors, or temporary diagnostic text may be emitted by test builds after/beside those operations, but bootstrap correctness must not depend on them. D0 does not define stdio, TTY/PTY, syslog, service registry, or a debug-write production ABI.

## 13. Threat-question disposition

- **Malformed bytes or role confusion:** exact header/size/version/count/order checks plus receive metadata and fresh object-info validation prevent a role from conferring the wrong authority.
- **Partial kernel publication:** Deepwyrm's paired transaction keeps the child unrunnable/unobservable until all recoverable preparation and INIT transfer are complete.
- **Bootfs tail exposure:** only exact `byte_size` is passed to the parser; rounded tail is zero and never treated as archive data.
- **Rounded ELF overlap:** Deepwyrm rejects page-rounded overlap before mapping.
- **W+X/executable stack:** the ELF subset rejects W+X and executable stack requests; stack mapping is RW/NX.
- **Rights gain:** F transfers may only preserve/reduce source rights, and Wyrmroot rejects any received mask that differs from the exact role contract.
- **Failed-bootstrap residue:** pre-runnable Deepwyrm rollback owns all kernel resources; once runnable, structured task teardown owns process cleanup, while Wyrmroot closes/discards local handles on protocol failure where safe.

## 14. D1 test contract

`wyrmroot-bootstrap-proto` must gain deterministic golden-byte and negative tests for:

- exact INIT and READY encoding;
- each header field's byte order/offset;
- wrong magic, major/minor, type, flags, reserved, size, count, transaction id, role/order, duplicate role, and trailing bytes; and
- handle-count expectations separate from payload decoding.

`wyrmroot-runtime` must gain tests for:

- startup ABI version mismatch;
- startup-block count/pointer/terminator/alignment/overflow cases;
- empty and bounded nonempty argv/envp/auxv parsing;
- bootstrap Channel wrong type/right set;
- received capability wrong type, too few/too many/over-broad/under-powered rights;
- bootfs zero/oversize/rounding-overflow length;
- exact read-only mapping plan; and
- parser borrow lifetime represented so mapping teardown cannot precede borrowed archive use.

A cross-repository contract test or checked fixture must bind the same 56-byte INIT and 40-byte READY vectors used by Deepwyrm G tests. Neither repository may silently fork the wire constants.

## 15. D0 closure

D0 is closed when this contract and `deepwyrm/Plans/DW0_G0_PRIMORDIAL_STARTUP_CONTRACT.md` are committed against one exact compatible revision pair and shared layout/role/startup rules agree mechanically.

D0 closure does not claim WYR0-D implementation, the Deepwyrm syscall consumer crate, the Wyrmroot Rust target, the real bootstrap executable, VM acceptance, or security closure. Those begin only in their named later phases.
