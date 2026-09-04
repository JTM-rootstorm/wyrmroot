# WYR1-D5 Transport Drain Fence

Date: 2026-09-04. This reached selector-private integration requirement
supplements the frozen serial/stream console contract; it does not extend
the public WRST protocol or kernel ABI.

## Cause and ownership

Consoled's raw Channel-send commit is not UART transmission completion.
Ordinary WRDC RETIRE gives control priority and closes the stream without
draining queued WRST, software TX, or hardware TX. Final WRD1 submission
likewise may exit QEMU before UART transmission. Therefore system-init must
fence both U1 retirement after leg 2 and terminal submission after leg 4.

Reuse the first-party selector-31 `EvidenceDrain`/`prove_transport_empty`
ordering in `userspace/uart16550d/src/main.rs`: consume normal stream input,
service and acknowledge interrupts, then test software and hardware empty.
No external source code is imported. Driver hardware ownership stays in
uart16550d; system-init and Deepwyrm must not poll COM2 registers themselves.

## WDR5 extension

The existing selector-private 96-byte WDR5 v1.0 record admits type 4
`RequestDrain(D5DrainIdentity)` and type 5 `TxDrained(D5DrainIdentity)`.
The common driver fields at offsets 16 through 56 retain the exact role,
bundle, attempt, endpoint ID/generation, and launch transaction. The tail is:

| Offset | u64 value |
| --- | --- |
| 64 | connector attach transaction |
| 72 | raw stream generation |
| 80 | cumulative response bytes accepted during this driver attempt |
| 88 | completed observation leg |

Only `(leg, target) = (2, 45)` or `(4, 46)` is admitted: U1 sends the 23-byte
stdout plus 22-byte stderr response; U2 sends two 23-byte stdout responses.
All identity fields are nonzero. Existing message types and reserved-field
requirements are unchanged. These records carry no handles.

## Required sequence

1. System-init retains the consoled observation batch rather than submitting
   record 8/retiring U1 or submitting terminal record 12. It sends one exact
   RequestDrain through the retained devmgr controller Channel.
2. Devmgr matches the active driver and active broker attach/stream, retains
   one pending identity, and forwards it on the existing driver control
   Channel. It admits no duplicate/crossed request or unsolicited completion.
3. UART matches its exact control/stream identity and fixed target, continues
   normal receive/IRQ/ack service, and counts accepted response bytes from
   the beginning of the attempt, including bytes accepted before the request.
   Completion requires the exact target, a fresh empty Channel observation,
   empty software TX, and LSR.TEMT. Over-target input is failure. A bounded
   timer may pace observation of hardware completion; elapsed time alone
   never proves completion. Preserve selector-31 and ordinary production
   behavior under their existing features.
4. UART returns the same identity as TxDrained. Devmgr validates its pending
   fence and forwards it once. System-init validates its pending identity,
   publishes the retained batch, and only then sends U1 RequestRetire or
   submits final WRD1. Failed sends do not fabricate a completion.

No extra COM2 commands or responses are introduced. The host's exact four
responses remain mandatory independent evidence. The fence is internal
ordering evidence, not a replacement for live UP/SMP acceptance.

Required tests include queued bytes when the fence arrives, partial TX,
TEMT still false after software drain, wrong/stale/reused identity, premature
or duplicate completion, over-target bytes, and no terminal/retire action
before the exact driver completion.
