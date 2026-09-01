# DW1-E3B / WYR1-D selector-31 product lifecycle status

**Status:** Wyrmroot host/model lifecycle gate reached; native selector join
awaits the paired Deepwyrm E3B revision.

**Date:** 2026-08-31

## Scope

E3B keeps selector 31 private.  It does not alter selector 29, the historical
WRDC 1.0 path, or normal WYR1-D operation.

The Wyrmroot product model now requires the following causal order:

1. U1 completes challenge 1, then makes its final FIFO fill and successfully
   acknowledges its exact Interrupt.
2. Only after those two facts, a bounded timer-paced UART `LSR.TEMT` poll
   waits for the first exact `TEMT=1` to establish the U1 transport-empty
   barrier. A `TEMT=0` result retains the barrier state; exhausting the fixed
   poll/deadline budget fails the selector rather than assuming transport is
   empty.
3. The active stream's queued inbound DATA is observed before U1 peer close.
   This keeps the D3D peer-close drain ordering intact rather than turning a
   close into permission to discard queued bytes.
4. U1 peer close is followed independently by the controller-owned U1 driver
   terminate/reap proof and both connector endpoint-release facts. Neither the
   driver reap nor one endpoint release proves the other endpoint.
5. The retained U1 probe is terminated/reaped after its ordered peer-close
   report. A separately launched U2 probe is bound as the fresh reporter.
6. U2, P2, and its raw stream identity must each differ from U1/P1. Only then
   can the existing action 1 bind U2 and action 3 arm the fresh nonce-bound
   challenge 2.
7. Challenge 2 completes before the controller observes the kernel-owned
   saved-U1 replay rejection, accounting, and the existing trusted terminal
   path. This observation is neither a Wyrmroot raw report nor a private
   action.

The fixed private kernel interface stays four actions: action 1 binds U1/U2,
action 2 binds the one current probe reporter, action 3 arms either challenge,
and action 4 reports only `0x07`, `0x09`, `0x0a`, `0x15`, and `0x17`. E3B does
not introduce action tags or report-event numbers. The kernel supplies its own
retirement, U2, stale-replay, accounting, and terminal records from live
kernel seams.

## Validation

The `wyrmroot-dw1e3-com2-test` host/model gate verifies the full ordered U1 to
U2 lifecycle and negative cases for pre-ack TEMT, a timed-out TEMT poll,
skipped queued-data observation, premature U2 admission, stale identities,
and reusing the U1 probe reporter.

The native product still needs the paired Deepwyrm E3B interface revision to
exercise the existing action calls against live selector records. No VM or
physical-I/O claim is made by this status.

## Required-source disposition

The active DW1-E/WYR1-D plan, WYR1-D stream/connector contract, D3B/D3D
status, E3A status, WYR1-B/C contracts, and bootstrap/recovery architecture
provided the authority order. Fuchsia, xv6, rust-osdev `uart_16550`, and
linenoise remain conceptual/not-applicable prior art as recorded in D3B/D3D;
no upstream code, ABI, or wire format was imported.
