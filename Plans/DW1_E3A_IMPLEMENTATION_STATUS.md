# DW1-E3A Wyrmroot implementation status

Date: 2026-08-31

DW1-E3A now has a `q35-com2-interrupt` selector-31-only Wyrmroot product path for the first raw
COM2 challenge round trip. The public ABI and the normal five-role WRRM
inventory are unchanged. The product keeps production `devmgr` and
`uart16550d`, and adds `test/dw1e3/com2-probe` as explicit test-only bootfs
content.

## Reached implementation

- the private `0xffff_ff1f` runtime wrapper uses the exact six-word
  BindDriver, BindProbe, ArmChallenge, and Report records, rejects zero
  required values, and leaves reserved words zero. BindProbe is issued by
  system-init with its retained probe Process handle, so the kernel resolves
  both the controller caller and controller-launched probe instead of guessing
  a primordial identity;
- system-init launches the probe through the existing RegistryClient grant
  path after accepting the real driver construction request;
- devmgr configures one existing `ConnectorBroker`, receives WRRG
  `ConnectOffer`, accepts WRSC `ConnectStream`, sends WRDC `AttachStream`,
  requires `StreamReady`, and returns the moved WRST endpoint;
- the probe receives the exact 24-byte nonce-bound binary challenge and emits
  the exact 24-byte deterministic response without newline transformation;
- `uart16550d` binds its real Interrupt handle and launch attempt, attributes
  the exact newly drained bytes, reports `C1_UART_DRAIN` after drain and before
  acknowledgement, and never invents object, binding, lease, or generation
  identities;
- ArmChallenge occurs only after stream attachment. Successful action 3 is
  the kernel-owned COM1 readiness point with grammar
  `DWE3READY|01|<NONCE16>|<STREAM16>|<CHALLENGE16>|<FNV16>|<FNV32>`; COM2 has
  no prefix, suffix, or handshake byte;
- the bootfs builder and xtask snapshot keep the five production WRRM roles
  while adding the separately named probe artifact;
- `dw1-e3a-prepare <output> <deep-repo> <deep-revision> <nonce>` builds and
  freezes the immutable artifacts and ESP, profile-local domain XML and mutable
  OVMF variables, source/build receipts, acyclic request/handoff/profile-pair
  graph, and nine-record partial `DWE3E1` parser grammar. The partial grammar
  rejects `DWTEST1` and does not create an acceptance receipt. Each profile's
  COM2 serial source uses libvirt `mode="connect"` to join the runner-owned
  Unix-socket listener; the handoff freezes that mode and ownership explicitly,
  and the generated domain never tries to bind the socket; and
- the request freezes the exact 354-byte `ovmf-bds-session-banner` COM2
  prelude as uppercase hexadecimal plus its length and SHA-256 alongside the
  OVMF/ESP identities. Both profile handoffs rejoin its kind, length, and hash
  through the request identity rather than treating firmware output as an
  unbound runner assumption.

## Canonical raw payload

For the frozen nonzero `u64` nonce, the challenge bytes are:

```text
0D 0A 00 7F 44 57 31 45 || nonce.to_le_bytes() || nonce.rotate_left(17).to_le_bytes()
```

For index `i` in `0..24`, the response byte is
`challenge[23-i] XOR (0xA5 + i)`. Length, FNV-1a-64, and full SHA-256 are
frozen by the host request over these exact arrays.

## Required-source receipt

The implementation followed the root DW1-E/WYR1-D plan E3/E3A stop line,
Deepwyrm E0 section 11 `DWE3E1` contract, the WYR1-D serial/stream contract,
the reached D3A-D3D status, WYR1-C product/restart precedent, the Wyrmroot
architecture index, and the bootstrap/recovery architecture. The pinned
Fuchsia, xv6, rust-osdev `uart_16550`, and linenoise sources were used only for
the conceptual dispositions already recorded by E0 and D3; no external code,
ABI, expression, or wire format was copied. New code remains
GPL-3.0-or-later.

## Explicit nonclaims and E3B seams

This status does not claim a VM run, physical IRQ3 observation, UP/SMP guest
evidence, the U1-to-U2 replacement leg, stale-U1 rejection, final accounting,
the full 26-record collector, `DWTEST1 31 0`, or selector acceptance. E3B
still owns probe/driver replacement cleanup, challenge 2, stale binding proof,
final accounting, and terminal closure.
