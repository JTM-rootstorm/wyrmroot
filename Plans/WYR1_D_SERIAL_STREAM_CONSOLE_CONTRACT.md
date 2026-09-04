# Wyrmroot WYR1-D Serial, Stream, and Console Contract

**Status:** Reached WYR1-D0 contract and host-model gate
**Reached:** 2026-08-31
**Scope:** native WRST byte streams, generation-aware serial connection,
production UART staging, bounded console translation/recovery, and selector-32
evidence identity
**Parent plan:** root `DW1E_WYR1D_IMPLEMENTATION_PLAN.md`
**Historical product preserved:** selector
`device-coordinator-restart` / test ID `29`, WRDC `1.0`, and its atomic
two-handle acceptance actor

This contract freezes WYR1-D before production implementation. It composes
the reached JobV2 three-stream launch seam, WYR1-C device coordination, and
Deepwyrm DeviceResource/Interrupt objects. It does not implement D1 native
stream wrappers, D2 UART execution, D3 production `uart16550d`, D4
`consoled`, D5 live selector 32, or a real shell.

## 1. Ownership and invariant boundary

- `devmgr` owns COM2 role policy, the current resource lease, driver attempt,
  publication, connector establishment, and fresh stream-generation issuance.
- Production `uart16550d` owns the reduced DeviceResource and fresh Interrupt
  for one driver attempt, UART configuration/drain policy, the active raw WRST
  endpoint, and hardware/software overrun accounting.
- `consoled` owns CR/LF translation, one console generation, three directional
  JobV2 stream peers, stdout/stderr fairness, and console-child replacement.
- The console child owns only its received stdin/stdout/stderr WRST endpoints.
- `registryd` routes the direct connector endpoint once. It never proxies
  serial bytes, resource authority, or later connector traffic.
- Deepwyrm owns Channel order/atomic MOVE, waits/signals, DeviceResource,
  Interrupt, and the physical DW1-E IRQ3 route.

COM1 remains the loader/kernel diagnostic and trusted structured-evidence
path. COM2 carries raw serial bytes only. A friendly COM2 string cannot be the
trusted pass certificate.

Restart is generation replacement. No old Channel, READY, transaction,
stream, console, child, Interrupt binding, or process-local identity is
silently rebound to a replacement generation.

## 2. WRST version 1 native byte stream

### 2.1 Exact byte grammar

All multibyte integers are little-endian. A WRST v1 message is one complete
Channel datagram with this 24-byte header followed immediately by its payload:

| Offset | Width | Field | Required value |
| ---: | ---: | --- | --- |
| `0x00` | 4 | magic | ASCII `WRST` |
| `0x04` | 2 | major | `1` |
| `0x06` | 2 | minor | `0` |
| `0x08` | 2 | header bytes | `24` |
| `0x0a` | 2 | message type | `1` (`DATA`) |
| `0x0c` | 4 | flags | `0` |
| `0x10` | 4 | payload bytes | `0..=1024` |
| `0x14` | 4 | reserved | `0` |
| `0x18` | variable | payload | exactly `payload_bytes` bytes |

The exact datagram size is `24 + payload_bytes`, computed with checked
arithmetic. There is no alignment padding, trailing data, implicit C/Rust
structure layout, host-endian field, or second variable region.

WRST transfers exactly zero handles. A receiver closes every unexpectedly
received handle and fails that stream generation. Wrong magic, major, minor,
header size, type, flags, reserved data, payload bound, exact size, trailing
bytes, or handle count is a protocol error.

A zero-length DATA record is a byte-stream no-op, not EOF. Channel peer close
is the only WRST EOF/hangup representation. WRST contains no READY, EOF,
flush, terminal, signal, resize, detach, shell, or other control message.
Channel message order is byte order; a sender may split bytes at any legal
payload boundary without changing semantics.

### 2.2 Bounded input semantics

One `NativeInput` endpoint may retain at most one decoded DATA payload of at
most 1024 bytes plus a cursor. It does not receive a second message while
unconsumed bytes from the retained record remain.

- A zero-length caller buffer returns `0` without receiving or waiting.
- A read copies from the retained record first and may then consume additional
  immediately available complete records until the caller buffer is full or
  receive would block.
- If at least one byte was copied, return that partial count rather than
  `WOULD_BLOCK` or EOF.
- If no byte was copied and no record is available, return `WOULD_BLOCK` unless
  a fresh observation proves peer close with no `READABLE` data.
- `READABLE | PEER_CLOSED` means drain readable datagrams first. Peer close is
  accepted as EOF only after a fresh wait/receive observation has no readable
  record. This prevents loss of already-queued final bytes.
- A malformed datagram or received handle fails the endpoint after closing all
  received handles. Bytes from that malformed datagram are never exposed.

### 2.3 Bounded output semantics and wait races

`NativeOutput::write` packetizes at most 1024 input bytes per DATA datagram and
maintains no unbounded retry queue.

- A zero-length caller buffer returns `0` and sends no DATA record.
- Each successful Channel send commits that packet's byte count exactly once.
- If a later send returns `WOULD_BLOCK`, return the already committed partial
  count; if none committed, return `WOULD_BLOCK`.
- A failed atomic send retains all handles and bytes at the sender. WRST sends
  no handles, so retry state is only the caller-owned unsent byte suffix.
- `DW_SIGNAL_WRITABLE` is a capacity wake hint, never a reservation. A sender
  that wakes writable must retry the send and accept a racing `WOULD_BLOCK`.
- A blocking helper waits only while no forward progress is possible, includes
  `PEER_CLOSED`, and rechecks send after every wake. It does not spin or convert
  a racing `WOULD_BLOCK` into success.

## 3. Serial service and connector minor 1.1

### 3.1 Version preservation

The existing service name `device.serial.console0`, protocol ID
`0x53455249414c4330`, and protocol version `1.0` retain their accepted WYR1-C
metadata/control meaning byte-for-byte. Selector 29 continues to publish and
consume only that historical profile.

The WYR1-D selected product advertises the same service/protocol major with
minor `1`. A client must negotiate `1.1` to use the connector. Protocol `1.0`
does not become a byte-stream endpoint and accepts none of the new messages.

### 3.2 WRSC 1.1 connector grammar

The direct service endpoint speaks fixed 128-byte `WRSC` records. All fields
are little-endian; every reserved field is zero.

| Offset | Width | Field |
| ---: | ---: | --- |
| `0x00` | 4 | magic `WRSC` |
| `0x04` | 2 | major `1` |
| `0x06` | 2 | minor `1` |
| `0x08` | 4 | message type |
| `0x0c` | 4 | flags, zero |
| `0x10` | 4 | total bytes, exactly `128` |
| `0x14` | 4 | moved-handle count |
| `0x18` | 8 | publication generation |
| `0x20` | 8 | client transaction ID |
| `0x28` | 8 | device role ID |
| `0x30` | 8 | bundle/lease generation |
| `0x38` | 8 | driver-attempt generation |
| `0x40` | 8 | driver-control endpoint ID |
| `0x48` | 8 | driver-control endpoint generation |
| `0x50` | 8 | devmgr attach transaction ID |
| `0x58` | 8 | stream generation |
| `0x60` | 4 | result code |
| `0x64` | 4 | reserved |
| `0x68` | 24 | reserved |

Message types are:

| Type | Name | Handles | Required shape |
| ---: | --- | ---: | --- |
| 1 | `CONNECT_STREAM` | 0 | publication and client transaction nonzero; role through stream generation and result zero |
| 2 | `CONNECTED` | 1 | every identity nonzero; result zero; one client stream endpoint |
| 3 | `ERROR` | 0 | publication/client transaction nonzero; result typed below; no stream endpoint |

`ERROR` results are `1 BUSY`, `2 NOT_READY`, `3 STALE`, and
`4 INTERNAL_FAILURE`. Zero and unknown results are invalid. A correlatable
response exactly echoes the request publication generation and client
transaction. `CONNECTED` additionally reports the exact current
role/bundle/attempt/control endpoint, the distinct devmgr attach transaction,
and fresh stream generation.

The transferred client endpoint has exact
`READ | WRITE | WAIT | INSPECT` rights. Any extra/reordered/wrong object,
rights, handles, flags, reserved data, zero required identity, or stale
publication fails closed and closes every received handle.

### 3.3 Connector transaction and cleanup

At most one attach is pending and at most one raw stream is active.

1. Validate the complete connector record, including nonzero client transaction
   and exact current publication generation, before allocating identities or a
   Channel pair.
2. Reject a second pending/active request as `BUSY` without creating a pair.
3. Mint a boot-monotonic nonzero attach transaction and stream generation.
4. Create one broad pair, retain the client endpoint, and atomically MOVE only
   the driver endpoint to the exact current driver over its direct control
   Channel.
5. Wait boundedly for correlation-exact `STREAM_READY`.
6. Only then atomically MOVE the client endpoint in `CONNECTED`.

An attach-send failure leaves both endpoints owned by devmgr for reverse-order
close. After a successful driver-endpoint MOVE, devmgr never closes that moved
handle: rejection, timeout, client-reply failure, retirement, or cleanup closes
the retained client endpoint, and the driver closes its endpoint after exact
cancel/retire/control close or observed peer close. Cleanup does not report
complete until both sides are known released. A whole driver generation that
is terminal and reaped proves the moved driver endpoint released, but does not
by itself prove an externally owned client endpoint closed.

The host model names the ownership states explicitly: pre-MOVE (both endpoints
owned by devmgr), post-MOVE pending (client owned by devmgr, driver endpoint
owned by the driver), ready-to-connect, active, awaiting driver release,
awaiting client release, and retiring-active. A stale READY/detach leaves the
exact current state unchanged. For an ordinary active detach, either endpoint
may release first; the slot remains busy until the correlation-exact other
release is observed, then a fresh connect may reuse the still-healthy driver
generation. Retirement is separate: it clears the current publication and
cannot restore it. Driver-generation reap proves only driver-endpoint release;
retirement cleanup remains incomplete until client release is also observed,
in either order.

If the `CONNECTED` MOVE fails atomically, devmgr still owns and closes the
client endpoint; the driver observes peer close and releases the moved peer.
After a committed `CONNECTED`, the client and driver own their endpoints.
Either peer close releases the active slot only after the other endpoint is
closed and devmgr receives a detach/peer-close observation for the exact
stream generation.

Publication/driver retirement first prevents new connections, closes every
retained pending client endpoint, requests exact driver stream cleanup, closes
active connector/client bindings, and proves all pending/active endpoints gone
before replacement publication. A stale `STREAM_READY` or detach closes any
received handle and cannot mutate the current slot.

## 4. WRDC production minor 1.1 and staged handoff

WRDC `1.0` messages and their 72-byte base header remain unchanged for
selector 29. Production WYR1-D uses WRDC `1.1`; historical parsers do not
reinterpret it.

The 72-byte base header retains the reached fields: magic/version/type,
flags/size/handle count, role ID, bundle generation, attempt generation,
control endpoint ID/generation, and transaction ID. New message bodies are:

| Type | Name | Total bytes | Handles | Body after byte 72 |
| ---: | --- | ---: | ---: | --- |
| 8 | `DEVICE_STAGE` | 112 | 1 | stage generation `u64`; resource ID `u64`; PIO base `u16`; length `u16`; source `u32`; 16 reserved zero bytes |
| 9 | `DEVICE_QUIESCED` | 80 | 0 | stage generation `u64` |
| 10 | `INTERRUPT_STAGE` | 96 | 1 | stage generation `u64`; parent resource ID `u64`; source `u32`; reserved `u32` |
| 11 | `ATTACH_STREAM` | 96 | 1 | stream generation `u64`; publication generation `u64`; reserved `u64` |
| 12 | `STREAM_READY` | 96 | 0 | same body as `ATTACH_STREAM` |
| 13 | `STREAM_DETACHED` | 96 | 0 | same body as `ATTACH_STREAM` |

WRDC `DRIVER_READY`, `DRIVER_FAILURE`, and `RETIRE` remain the reached semantic
families but are encoded with minor 1 for the new product. The new production
READY is legal only after both stages below. Selector 29 retains minor 0,
`RESOURCE_BUNDLE`, and its historical READY behavior.

For one attempt, devmgr mints one nonzero stage generation and distinct
nonzero transactions for device stage, interrupt stage, READY, and every
attach. Every message matches role, lease/bundle, attempt, endpoint ID and
generation, transaction, and stage/stream generation as applicable.

### 4.1 Device stage

`DEVICE_STAGE` MOVEs exactly one DeviceResource with exact
`READ | WRITE | INSPECT` rights. The driver freshly queries and requires
resource ID 1, current lease generation, PIO `[0x2f8,0x300)`, source 3, exact
wire correlation, and zero flags/reserved fields before any PIO.

The driver then runs `initialize_quiesced()`. Only after its bounded stale
drain completes with IER still zero may it return correlation-exact
`DEVICE_QUIESCED`. Failure before that reply closes the received resource and
never creates a fresh Interrupt binding.

### 4.2 Interrupt stage and READY

Only after exact `DEVICE_QUIESCED` does devmgr create a fresh Interrupt, which
causes DW1-E to commit/unmask the route. `INTERRUPT_STAGE` MOVEs exactly one
Interrupt with exact `WAIT | MODIFY | INSPECT` rights.

The driver freshly requires source 3, parent resource ID 1, the same lease
generation, nonzero fresh object/binding generations, Armed state, exact
stage/attempt correlation, and zero flags/reserved fields. It then enables
exactly RDI|RLSI and becomes capable of entering its wait/drain/ack loop before
sending production `DRIVER_READY`.

A malformed/stale second stage closes the Interrupt, leaves or restores IER=0,
fails the attempt, and cannot publish. Failure after Interrupt MOVE and before
READY finalizes the Interrupt and masks/releases the route before replacement.

## 5. Fixed bounds and pressure policy

| Item | Exact D0 bound |
| --- | ---: |
| WRST payload | 1024 bytes |
| uart16550d RX ring | 4096 bytes |
| uart16550d TX ring | 4096 bytes |
| active raw serial clients | 1 |
| pending attach transactions | 1 |
| consoled serial-input staging | 4096 bytes |
| consoled stdout staging | 4096 bytes |
| consoled stderr staging | 4096 bytes |
| console child failures | 4 in a rolling 60-second window |
| serial reconnect attempts | 4 in a rolling 60-second window |
| driver IIR iterations per Interrupt wake | 256 |
| stale-init drain iterations | 256 |
| stdout service quantum | 1024 bytes per fairness turn |
| stderr service quantum | 1024 bytes per fairness turn |

All storage is fixed-capacity. Counters and checked identity allocators
saturate or fail closed; they never wrap.

RX hardware cannot be held off indefinitely. When the RX ring is full, the
driver continues draining RBR, drops the newest excess byte, and saturatingly
increments `rx_software_overrun_bytes`. Hardware `LSR.OE` is accounted
separately. Loss is reported through bounded status/evidence.

TX is backpressurable and never silently drops. The driver receives a WRST
client record only when at least 1024 bytes of TX-ring capacity is free. When
the ring is full it stops reading client DATA so Channel pressure reaches the
writer. A WRST RX send removes ring bytes only after send commit; racing
`WOULD_BLOCK` retains them.

An outbound WRST send which races `PEER_CLOSED` enters the same bounded
peer-close drain state as a wait observation; it does not detach the stream
immediately. The driver suppresses further writable work, drains every queued
inbound DATA record under the TX admission gate, and detaches only after a
fresh receive proves the peer-closed queue empty. Other transport failures
still isolate the stream immediately.

Consoled stops raw-serial reads while its 4096-byte input stage is full and
stops stdout/stderr reads while the respective stage is full. Backpressure may
therefore reach the UART RX loss boundary or child writers, but memory remains
bounded. Stdout/stderr turns alternate after at most 1024 committed source
bytes; there is no claimed total order between the two independent Channels.

## 6. Fixed q35 16550 baseline

The initial hardware policy is PC-compatible q35 COM2 at `0x2f8`, IRQ3,
1.8432 MHz clock, divisor 1, 115200 baud, 8 data bits, no parity, one stop bit.
FIFO is enabled with one-byte RX trigger and a 16-byte q35 TX FIFO. MCR is
`OUT2 | RTS | DTR`, loopback is off. Baseline IER after activation is
`RDI | RLSI`; THRI is enabled only while the TX ring is nonempty. The UART IER
modem-status interrupt-enable bit (`MSI`) remains disabled. This is not PCI
MSI; PCI MSI/MSI-X are unrelated and out of scope. WYR1-D exposes no
baud/format configuration.

`initialize_quiesced()` is exactly ordered:

1. write IER=0 immediately;
2. set DLAB;
3. write DLL=1 and DLM=0;
4. restore LCR to 8N1 with DLAB clear;
5. enable FIFO and clear RX/TX FIFOs with RX trigger 1;
6. write MCR `OUT2 | RTS | DTR` with loopback clear;
7. boundedly read/clear stale LSR, MSR, IIR, and RBR state;
8. leave the software TX ring empty and THRI disabled; and
9. return only with IER=0.

`activate_interrupts()` is a separate operation after exact Interrupt intake.
It writes exactly RDI|RLSI. The empty-to-nonempty TX transition enables THRI;
draining the last TX byte disables THRI.

On each Interrupt wake, read IIR and service all indicated causes until
NO_INT, failing at 256 iterations. RLSI reads LSR, accounts OE/PE/FE/BI, and
drains available data. RDI and receiver timeout drain while LSR.DR. THRI fills
at most the known 16-byte FIFO and disables itself when the ring empties. An
unexpected UART modem-status cause reads MSR, records a bounded
unexpected-modem fact, and continues. An unknown cause writes IER=0 and fails
the driver.

Only after the complete bounded cause drain may the driver call
`interrupt_ack`. One ack closes one software pending epoch, not one UART byte.
Ack failure fails the driver; no uncertain generation continues. There is no
idle UART polling outside bounded init/drain work.

Retirement writes IER=0 first when the DeviceResource remains usable, closes
stream-local state, then Interrupt, DeviceResource, and control last. Kernel
Interrupt finalization/masking remains the crash backstop.

## 7. Console transforms and cross-record state

Raw WRST serial is byte-transparent. Only `consoled` transforms newlines.

Input maintains one boolean `suppress_lf_after_cr` across WRST records and
partial staging operations:

- CR emits LF and sets the boolean;
- an immediately following LF is suppressed and clears it;
- a non-LF after CR clears it and is processed normally;
- bare LF emits LF; and
- every other byte passes unchanged.

Thus CRLF split across two WRST records still becomes one LF. The boolean is
discarded with the console generation and never crosses serial replacement.

Output maintains one boolean `previous_was_cr` independently for stdout and
stderr, across records and partial writes:

- LF with `previous_was_cr == false` emits CR then LF;
- LF with `previous_was_cr == true` emits LF only;
- CR passes unchanged and sets the boolean;
- any other byte passes unchanged and clears it.

This prevents CRCRLF even when CR and LF arrive in separate WRST records. Each
source has separate transform state because stdout/stderr have no total order.
State is discarded with the child stream generation.

## 8. Generation replacement and finite restart

The following nonzero identities remain distinct: publication generation,
device role, lease/bundle generation, driver attempt, driver-control endpoint
ID/generation, stage generation/transactions, stream generation, console
generation, launch transaction/job, and child generation. Numeric equality of
different identity types is never a join.

### 8.1 Driver loss

Driver loss retires publication and stream before releasing the old Interrupt.
Devmgr uses its reached policy: four attempts including the initial attempt,
fixed 25,000,000 ns backoff, complete cleanup before overlap, and permanent
failure on exhaustion or unprovable cleanup. A driver-only replacement under a
healthy devmgr retains the lease/bundle generation but receives fresh attempt,
control endpoint, stage, Interrupt binding, publication, and stream identities.
A replacement devmgr must claim a fresh lease generation.

Consoled treats raw peer close/publication retirement as serial-generation
loss: mark the console stale, close all three old child peers, terminate/reap
the child, discard all staged bytes and transform state, boundedly relookup and
reattach, mint a fresh console generation, create fresh three-stream pairs,
and launch a fresh child. Old output is never spliced into the replacement.

### 8.2 Child-only loss

Child loss closes its three stream pairs and transform state but preserves a
healthy raw serial stream and driver generation. Consoled launches a fresh
child generation with fresh stdin/stdout/stderr endpoints.

The child restart window contains failure timestamps, not launch attempts.
Four failures in any rolling 60-second active-monotonic interval exhaust the
local policy. On exhaustion consoled reports bounded failure to its supervisor
and stops automatic child restart; a fifth launch is not attempted. The window
is the half-open interval `(now - 60 seconds, now]`: before recording a failure,
timestamps whose elapsed time is exactly 60 seconds or more are discarded.
Active-monotonic clock regression fails closed.

A **stable run** is exactly 60 continuous seconds beginning only after
correlation-exact child READY while the same raw stream, console generation,
child generation, and all three child stream peers remain live. At that
deadline consoled clears the child-failure timestamp window and restart count.
Construction time, pre-READY time, a replaced serial generation, a closed
stream, or a child that exits before the deadline cannot reset the window.
Correlation-exact READY creates one stable-run token. Any raw-stream, console,
child, or child-stream-peer loss or identity drift permanently invalidates that
token; apparent recovery cannot revive it. A new exact READY is required to
start another 60-second interval.

Serial lookup/attach recovery separately permits four failed attempts in a
rolling 60-second window with 25,000,000 ns between attempts. Successful
correlation-exact `CONNECTED` clears that reconnect window. Exhaustion
on the fourth still-active failure prevents a fifth attempt and escalates to
supervisor/recovery; it does not hot-loop. Reconnect uses the same half-open
expiry and clock-regression rules. Restart windows are current-boot state and
are not persisted across reboot.

## 9. Selector 32 and structured Wyrmroot evidence

The canonical identity registry was checked at D0: existing Wyrmroot selector
owners occupy 24 through 30, the paired plan reserves 31 for DW1-E, and 32 was
free. Cross-repository owner coordination reserves:

```text
selector  native-console-streams
test ID   32
```

No separate private kernel relay/raw-operation identity is needed for D0.
Kernel/platform `DWE1` records remain owned by DW1-E. Wyrmroot uses the
following userspace `WRD1` family over the existing trusted selector collector
path; raw COM2 bytes remain functional evidence only.

Every `WRD1` record is exactly 192 little-endian bytes:

| Offset | Width | Field |
| ---: | ---: | --- |
| `0x00` | 4 | magic `WRD1` |
| `0x04` | 2 | major `1` |
| `0x06` | 2 | minor `0` |
| `0x08` | 4 | record type |
| `0x0c` | 4 | flags, zero |
| `0x10` | 4 | size, exactly `192` |
| `0x14` | 4 | reserved, zero |
| `0x18` | 8 | nonzero sequence |
| `0x20` | 8 | nonzero selector nonce |
| `0x28` | 8 | device role ID |
| `0x30` | 8 | current bundle/lease generation |
| `0x38` | 8 | current driver attempt |
| `0x40` | 8 | current driver-control endpoint ID |
| `0x48` | 8 | current endpoint generation |
| `0x50` | 8 | current operation transaction |
| `0x58` | 8 | current stream generation |
| `0x60` | 8 | current console generation |
| `0x68` | 8 | current child generation |
| `0x70` | 8 | previous bundle generation |
| `0x78` | 8 | previous driver attempt |
| `0x80` | 8 | previous endpoint ID |
| `0x88` | 8 | previous endpoint generation |
| `0x90` | 8 | previous operation transaction |
| `0x98` | 8 | previous stream generation |
| `0xa0` | 8 | previous console generation |
| `0xa8` | 8 | previous child generation |
| `0xb0` | 8 | type-specific value |
| `0xb8` | 8 | reserved, zero |

Record types are `1 DRIVER_READY`, `2 STREAM_ATTACHED`, `3 RAW_RX`,
`4 RAW_TX`, `5 CONSOLE_GENERATION`, `6 CHILD_READY`,
`7 INITIAL_STDOUT_OBSERVED`, `8 INITIAL_STDERR_OBSERVED`,
`9 DRIVER_REPLACED`, `10 POST_DRIVER_STDOUT_OBSERVED`,
`11 CHILD_REPLACED`, and `12 POST_CHILD_STDOUT_OBSERVED`.

- `DRIVER_READY` requires role/bundle/attempt/endpoint/transaction; later
  identities and all previous fields are zero.
- `STREAM_ATTACHED` adds the nonzero stream generation.
- `RAW_RX`/`RAW_TX` require the same driver/stream tuple; value is a nonzero
  bounded committed-byte count, not byte content.
- `CONSOLE_GENERATION` requires driver/stream/console correlation.
- `CHILD_READY` and all four observation types require the complete current
  tuple through child.
- `DRIVER_REPLACED` requires complete previous driver/stream/console/child
  identity and complete fresh current driver/stream/console/child identity.
  Driver-only replacement preserves the role and healthy devmgr bundle/lease;
  the attempt, connector attach transaction, stream, console, and child are
  strictly newer. The control endpoint `(ID, generation)` pair must be distinct;
  the generation alone need not increase because a new endpoint ID starts at
  generation one. It is emitted only after old cleanup and new child READY.
- The operation transaction in WRD1 is the connector attach transaction, not
  the driver's launch transaction or the child's JobV2 transaction.
- `CHILD_REPLACED` requires the same current driver/bundle/attempt/endpoint/
  attach transaction/stream/console in both groups, a strictly newer current
  child generation, and zero value. It proves the healthy driver was preserved.
- `POST_DRIVER_STDOUT_OBSERVED` must follow the corresponding
  `DRIVER_REPLACED`; its current tuple must equal the replacement record's
  current tuple. `POST_CHILD_STDOUT_OBSERVED` has the analogous requirement
  for `CHILD_REPLACED`. Previous fields are zero in observation records.

The four observation legs and their fixed identifiers are:

| Leg ID | Record | Child output Channel |
| ---: | --- | --- |
| `1` | `INITIAL_STDOUT_OBSERVED` | stdout |
| `2` | `INITIAL_STDERR_OBSERVED` | stderr |
| `3` | `POST_DRIVER_STDOUT_OBSERVED` | stdout |
| `4` | `POST_CHILD_STDOUT_OBSERVED` | stdout |

For each leg, the host and trusted selector controller derive a 64-bit
challenge as FNV-1a-64 over the concatenation of these eight little-endian
`u64` values, in order:

```text
selector_nonce, 32, leg_id, bundle_generation, driver_attempt,
stream_generation, console_generation, child_generation
```

FNV-1a uses offset basis `0xcbf29ce484222325`, prime
`0x00000100000001b3`, XOR-before-multiply, and wrapping `u64`
multiplication. The challenge is rendered as exactly 16 uppercase hexadecimal
ASCII digits, including leading zeroes. For stdout legs 1, 3, and 4 the host
sends exactly `ping <CHALLENGE>\r\n`; consoled presents exactly
`ping <CHALLENGE>\n` to the child, and the child writes exactly
`pong <CHALLENGE>\n` to stdout. The host must observe exactly
`pong <CHALLENGE>\r\n`, 23 bytes. For stderr leg 2 the host sends exactly
`err <CHALLENGE>\r\n`; consoled presents exactly `err <CHALLENGE>\n`, and the
child writes exactly `err <CHALLENGE>\n` to stderr. The host must observe
exactly `err <CHALLENGE>\r\n`, 22 bytes.

For each observation record, type-specific value is FNV-1a-64 over the exact
host-visible response bytes, including the final CRLF. Acceptance recomputes
the challenge, requires the type-specific exact length and byte-for-byte
response, recomputes its value, and rejects any prefix, suffix, case change,
wrong Channel, wrong leg, wrong nonce, or wrong current generation tuple. A
post-replacement challenge is therefore fresh even if an old console or child
continues producing bytes.

All fields forbidden for a record type are zero. Sequence is exact,
monotonic, and gap-free for one nonce. The trusted controller emits a record
only after validating the underlying direct status/Channel/launch fact; a
driver, consoled, or child payload cannot mint terminal success.

Selector 32 joins the current nonce to the full WRD1 generation chain and to
the exact expected COM2 response framing. Unexpected COM2 prefix/suffix bytes
fail unless a later contract explicitly admits an exact bounded banner.

## 10. Host-model D0 gate

The D0 executable model is intentionally an integration test in
`wyrmroot-device-proto`; it exports no production API. It proves:

- canonical WRST zero, ordinary, and 1024-byte payloads;
- wrong magic/version/header/type/flags/reserved/size, oversized payload,
  trailing bytes, and unexpected-handle rejection;
- one-record partial retention, queued-final-byte drain before EOF, partial
  writes, and a WRITABLE/send `WOULD_BLOCK` race;
- connector zero/stale/not-ready/busy behavior, exact READY correlation,
  explicit pre-/post-MOVE ownership, attach/reply failures, timeouts, active
  client-first and driver-first detach with healthy-generation reuse,
  order-independent retirement cleanup, and deferred moved-endpoint release
  without stale-event mutation;
- exact 4096-byte RX/TX and staging bounds, drop-newest/saturating RX overflow,
  TX backpressure without drop, and all three console stages rejecting byte
  4097 without mutation;
- selector-nonce/generation/leg-specific challenges, exact stdout/stderr
  response lengths and bytes, and type-specific response hashes across initial,
  post-driver, and post-child legs;
- fourth-failure exhaustion, exact 60-second expiry, continuous stable-run and
  exact-CONNECTED reset policy, plus both UART drain budgets accepting 256
  iterations and failing before iteration 257; and
- input/output CR/LF transforms when CR and LF cross record boundaries.

D1 must replace the test-only WRST model with the production
`wyrmroot-stream-proto` crate and native runtime wrappers without weakening
these vectors. D2 must implement the UART core separately. Passing D0 proves
the frozen grammar/model only; it is not a production or live-UART claim.

## 11. Required reading and prior-art receipt

### 11.1 In-tree authority and reached implementation

The following were read before D0 changes:

- root `DW1E_WYR1D_IMPLEMENTATION_PLAN.md` — **adapt**: active phase scope,
  exact D0 decisions, bounds, stage order, selector, and gates;
- root `BOOTSTRAP_AND_RECOVERY_ARCHITECTURE.md` — **adapt**: finite monotonic
  recovery, fresh generations, stale-resource rejection, and no resurrection;
- `Plans/ARCHITECTURE_INDEX.md` — **adapt**: Wyrmroot ownership and reading
  order;
- `Plans/WYR1_B_REGISTRY_LAUNCH_CONTRACT.md` — **adapt**: exact JobV2 zero-or-
  three stream roles, Channel rights, direct routing, MOVE cleanup, and opaque
  stream handoff;
- `Plans/WYR1_C_DEVICE_COORDINATOR_CONTRACT.md` — **adapt**: role/attempt/
  endpoint/publication identity separation, four-attempt policy, and
  retire-before-replace;
- `Plans/WYR1_C_DEVICE_HANDOFF_CONTRACT.md` — **adapt**: exact DeviceResource/
  Interrupt rights, lease correlation, MOVE ownership, and cleanup order;
- `Plans/WYR1_C_VALIDATION.md` — **adapt**: accepted selector-29 tuple and
  byte-for-byte historical/non-I/O boundary;
- `crates/wyrmroot-device-proto/src/{lib,manifest,control,controller,coordinator,driver_launch}.rs`
  — **adapt**: current service identity, WRDC 1.0, generations, codec style,
  and allocation-free model conventions;
- `crates/wyrmroot-runtime/src/{lib,native,device,startup,supervision}.rs` —
  **adapt**: complete-datagram Channel wrappers, wait validation, object-info
  facade, startup roles, and fresh-wait peer-close handling;
- `userspace/wyr1-retained-stubs/src/uart16550d.rs` and
  `userspace/wyr1-retained-stubs/tests/uart16550d_c5_source.rs` —
  **not-applicable** as production architecture; **adapt** only the requirement
  to preserve its selector-29 artifact/feature behavior unchanged; and
- `tools/xtask/src/{h_request,dw1b,wyr1,wyr1b,dw1c,wyr1c6,dw1d6}.rs` —
  **adapt** for the checked canonical selector occupancy through ID 30.

### 11.2 Pinned external prior art

All use is conceptual. No upstream code, ABI, data structure, or wire format
was copied or adapted.

- Fuchsia revision `6a606ff7fd9b055edee6557566fb3f112df1a812`:
  - `zircon/kernel/object/interrupt_dispatcher.cc` — **concept**: coalesced
    wait/ack state and destruction before rebinding;
  - `zircon/kernel/object/resource_dispatcher.cc` — **concept**: rights/range
    authority and lifetime release;
  - `src/devices/bin/driver_manager/resource.{h,cc}`,
    `node.{h,cc}`, `driver_host.{h,cc}`, and `driver_runner.{h,cc}` —
    **concept**: coordinator/driver process separation, dependency retirement,
    and not reusing a dying host. BSD/MIT-style headers were observed. FIDL,
    Component Manager, dynamic linking, node topology, devfs, and colocation
    policy are **not-applicable**.
  - Receipt for the eight driver-manager files: each exact-revision Gitiles
    `...?format=TEXT` response was fetched read-only over HTTPS on 2026-08-31,
    base64-decoded, read, and SHA-256 hashed. No mutable checkout or upstream
    file was created. Decoded hashes are:

    | Exact path under `src/devices/bin/driver_manager/` | SHA-256 |
    | --- | --- |
    | `resource.h` | `4d5eaf84f767cbe75fc75a6a15c8f28867d55a836635ff826deefa2457f68138` |
    | `resource.cc` | `eae8e971b7cb01adce0ddcc0bd2cf34e38c83ea8ef164cb1c061fbe3c3d3a539` |
    | `node.h` | `76e6e301c2c61058f7608798102f28aece3aa5e8d288f6df7d6ed6bf41df2708` |
    | `node.cc` | `9f3223ccd90b4f797ebbf2848e6e6ffbedb7b80a11bd1081a429489828d46033` |
    | `driver_host.h` | `c3bf9e54b6a8a82c9b59833aaee72c2a71ca4ff1140fddc630ff802b19e9f7ed` |
    | `driver_host.cc` | `e5366cbf7797f537ebacb14b685a353db0cd33d6c3cc0a9d5a16ac0f20076bb9` |
    | `driver_runner.h` | `912e086f3c14f7987c7743e0b55af678507e2d442b5ef49248d41d941c09e327` |
    | `driver_runner.cc` | `7cce7060368df58f905d974f650754981941d798ba0d8e8927c5c17862bed846` |
- xv6-riscv revision `35b088427ef37611c38afdeed5a52a278cae38f9`:
  - `kernel/uart.c`, `console.c`, `trap.c`, and `plic.c` — **concept**: disable
    interrupts during initialization, drain receive causes before controller
    completion, and simple byte-flow tests. RISC-V PLIC, global console,
    synchronous echo, Unix fd, and line discipline are **not-applicable**.
- rust-osdev `uart_16550` revision
  `176b07b076bdc1fe999a5e757ab53a0e24b4005c` (0.8.0):
  - `README.md`, `src/lib.rs`, `src/config.rs`, `src/spec.rs`, and
    `src/backend/pio.rs` — **concept**: register constants, init-disable/
    activate-last ordering, IIR cause decoding, FIFO/OUT2 configuration,
    nonblocking partial operations, and an injectable backend shape. Direct
    `inb`/`outb`, unsafe address authority, MMIO, its TTY helper, and blocking
    spin APIs are **not-applicable**. If later code is adapted, the MIT grant
    and notice are required; D0 adapted none.
- linenoise revision `a473823d74b93eab2ba83480df16ed37617493f2`:
  - `linenoise.c` and `linenoise.h` — **concept** for CR/CRLF normalization
    and carrying parser state across input chunks. Its line editor, dynamic
    allocation, termios, POSIX fds, signals, ioctl, history, and terminal
    control sequences are **not-applicable** to WYR1-D.

## 12. Nonclaims and released seam

D0 claims only an indexed contract and executable host model. It does not
claim:

- production `wyrmroot-stream-proto` or runtime wrappers;
- production UART register I/O, physical IRQ3, IOAPIC, or live UART behavior;
- production `uart16550d`, devmgr connector, `consoled`, or console child;
- selector-31 or selector-32 live acceptance;
- a real `wyrmsh`, line editor, terminal emulator, PTY, termios, libc, POSIX
  descriptors/signals/ioctl, VFS, `/dev`, network, or physical hardware;
- general PCI/IOAPIC/MSI/MSI-X/x2APIC policy;
- a changed Deepwyrm public ABI;
- altered selector-29 WRDC 1.0 or acceptance-actor behavior; or
- final WYR1 security closure or a Daybreak gate.

The released D1 seam is the WRST v1 byte grammar, bounded partial-I/O/wait
semantics, and malformed corpus. The released D2 seam is the fixed UART
baseline, two-step init/activation contract, drain ordering, rings, and
overflow/backpressure policy. D3/D4 may rely on the connector, staged handoff,
generation replacement, newline, restart, and WRD1 joins only after their own
production tests land.
