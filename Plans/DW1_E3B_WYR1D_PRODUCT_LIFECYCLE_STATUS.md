# DW1-E3B / WYR1-D selector-31 product lifecycle status

**Status:** Selector-private native lifecycle is implemented in the Wyrmroot
lane and covered by focused model/source gates. Freestanding pairing against
the accepted Deepwyrm E3B revision remains the final cross-repository gate.

**Date:** 2026-08-31

## Scope

E3B keeps selector 31 private.  It does not alter selector 29, the historical
WRDC 1.0 path, or normal WYR1-D operation.

The Wyrmroot product model now requires the following causal order:

1. U1 completes challenge 1, then makes its final FIFO fill and successfully
   acknowledges its exact Interrupt.
2. Before TEMT polling, the driver performs one fresh receive-side probe of
   the raw stream. Only a clean `WOULD_BLOCK`/peer-close result proves that
   no extra WRST DATA record is queued behind the exact response; any such
   record fails the selector before stream retirement.
3. Only after those facts, a bounded timer-paced UART `LSR.TEMT` poll
   waits for the first exact `TEMT=1` to establish the U1 transport-empty
   barrier. A `TEMT=0` result retains the barrier state; exhausting the fixed
   poll/deadline budget fails the selector rather than assuming transport is
   empty.
4. The active stream's queued inbound DATA is observed before U1 peer close.
   Handle-bearing datagrams and nonempty post-challenge data fail closed; a
   close is never permission to discard them. Zero-length WRST DATA remains a
   legal no-op while either fixed challenge or response is being accumulated.
5. The controller first requests selector-private U1 stage-1 retirement:
   disable IER, read back exact IER=0, and detach the stream while retaining
   the Interrupt/resource/control/process. The retained probe then observes
   queued-data drain and peer close, closes its externally owned client stream
   endpoint, and only then emits its exact `StreamPeerClosed` correlation.
   System-init submits `0x0a` and sends the existing type-7 `FinalizeRetire`
   tuple. Devmgr accepts type 7 as the client-release certificate only when
   its full nonce/T/P/G/Q/length/hash tuple matches the current active attach;
   it retires the broker and records client release before forwarding stage-2
   finalize to the driver. Exact `DriverReaped` then releases the driver
   endpoint; devmgr requires an Empty broker before discarding it or admitting
   U2. Neither endpoint release nor reap proves the other endpoint.
6. System-init accepts U1 Process exit only after every Q1 causal join,
   controller FinalizeRetire, and an exact zero normal-exit record. A
   premature or nonzero exit performs fail-closed cleanup and cannot advance
   challenge generation.
7. System-init takes U1 probe ownership after the ordered peer-close report:
   it closes the controller launch endpoint for graceful exit, boundedly
   reaps the exact task group/process, and uses hard termination only as the
   bounded fallback. A separately launched U2 probe is then bound as the
   fresh reporter.
   A probe launch-channel `PEER_CLOSED` or Process `EXITED` signal at any
   earlier point (C1 pre-response, pre-peer-close, or U2) is instead an exact
   fail-closed supervision event: validate an observed exit when present,
   clean up the probe and active driver with bounded fallback, and do not
   advance the selector lifecycle.
   When `READABLE|PEER_CLOSED` arrives together, system-init drains the queued
   exact controller message first; a subsequent fresh close then receives the
   normal lifecycle classification.
   The intentional U2 probe exit after `ResponseCommitted` is separately
   reaped with an exact successful-exit check while retaining the U2
   binding/TEMT join for the controller terminal claim.
8. U2, P2, and its raw stream identity must each differ from U1/P1. Only then
   can the existing action 1 bind U2 and action 3 arm the fresh nonce-bound
   challenge 2.
9. Challenge 2 has its own acknowledged final-FIFO/TEMT proof. Only after
   joining U2 response plus that fact does system-init make the controller-only
   existing action-4 terminal claim (`E=0xff,V=0,X=0`). The kernel then owns
   saved-U1 replay rejection, accounting, and terminal records.

The fixed private kernel interface stays four actions: action 1 binds U1/U2,
action 2 binds the one current probe reporter, action 3 arms either challenge,
and action 4 reports only `0x07`, `0x09`, `0x0a`, `0x15`, and `0x17`, plus the
controller-only fixed terminal claim `0xff/0/0`. E3B does not introduce action
tags. The kernel supplies its own retirement, U2, stale-replay, accounting,
and terminal records from live kernel seams.

## Validation

The `wyrmroot-dw1e3-com2-test` host/model gate verifies the full ordered U1 to
U2 lifecycle and negative cases for pre-ack TEMT, a timed-out TEMT poll,
skipped queued-data observation, premature U2 admission, descending/stale
identities, and reusing the U1 probe reporter. Native source gates additionally
cover BindingReady-before-arm, the observed response accumulator, exact WDE3
type routing, type-7 client-release custody, stage-1/FinalizeRetire
correlation, the post-IER0 interrupt race, U1 probe reaping, fresh U2
admission, and the U2 response/TEMT join before the controller-only terminal
claim.

Freestanding product build and live selector-record exercise still need the
paired Deepwyrm E3B interface revision. No VM or physical-I/O claim is made
by this status.

All lane validation must set a fresh absolute
`WYRMROOT_PINNED_TARGET_DIR` below this lane's `.tmp/` directory (for example,
`$PWD/.tmp/dw1e3b-native-check`); the canonical pinned target is not an
admitted shared output. This applies to formatting as well as test, clippy,
and freestanding preparation commands.

## Required-source disposition

The active DW1-E/WYR1-D plan, WYR1-D stream/connector contract, D3B/D3D
status, E3A status, WYR1-B/C contracts, and bootstrap/recovery architecture
provided the authority order. Fuchsia, xv6, rust-osdev `uart_16550`, and
linenoise remain conceptual/not-applicable prior art as recorded in D3B/D3D;
no upstream code, ABI, or wire format was imported.
