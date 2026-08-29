# WYR1-C3 Host/Native Validation

**Status:** reached host/native construction gate only

WYR1-C3 adds a private, pre-resource native driver construction seam. After
the initial publication install/status exchange, devmgr creates a fresh direct
Channel pair and retains its broad, future-TRANSFER peer. It sends one fixed
WRDL request over the existing private supervisor Channel with exactly the
rights-reduced child endpoint. Init dispatches WRCS and WRDL by exact magic,
validates received metadata and a fresh capability query, and rejects stale or
nonmonotonic correlations before construction.

Init revalidates the retained WRRM/bootfs product, joins the request actor
identity through the immutable WRDM to exact `system/uart16550d` bytes, creates
an attempt task group, and invokes the dedicated loader entry point. Only
after storing the constructed process, task group, launch Channel, and complete
attempt correlation does init return a zero-handle WRLA acknowledgement.
The new WRLP 1.6 `DeviceDriver` profile carries self-root plus that endpoint,
and binds supervisor generation, role, attempt, launch session, endpoint ID and
generation, and transaction. The loader request separately rejects every path
except `/system/uart16550d`; the host launch model separately retains the
product-bound actor identity. No ambient path selection is admitted.

The actor validates the new startup record and sends `WRDC CONTROL_READY` on
the direct Channel. Devmgr validates it against the retained peer and the exact
active request. `CONTROL_READY` is explicitly zero-bundle and distinct from
`DRIVER_READY`; it cannot claim resource delivery, matching, publication, or a
device-bound result. The resident init wait set separately observes driver
exit and reaps the exact process/task group/launch Channel; devmgr or supervisor
replacement first cleans the old driver attempt. All other WRDC messages
retain their nonzero-bundle requirement and fail closed.

The complete WRLA plus direct `CONTROL_READY` handshake uses one checked
absolute monotonic-active deadline and the accepted one-second readiness
interval; the second wait cannot reset the budget. Driver correlation values
are allocated from a supervisor-generation high 32-bit namespace. Attempt,
launch session, endpoint, and transaction then use four distinct,
nonoverlapping 30-bit lanes. The first launch from a replacement devmgr remains
above the previous per-type high-water marks without treating one typed
identity as another, while an old direct endpoint still fails exact
correlation.

The synthetic C3 actor intentionally exits after `CONTROL_READY` so this gate
can prove init's terminal observation and reap path. It has no post-resource
failure or RETIRE obligation; that behavior remains C4+ after DW1-D provides
real resource authority.

Init is process-construction/reap authority only. The C3 loader request type
has no field capable of carrying a future resource bundle, so failed launch or
pre-resource child exit leaves that hypothetical custody entirely in devmgr.
The host model rejects wrong path/profile shape, wrong Channel kind/rights,
stale direct endpoint, duplicate READY, and post-reap replay.

Validated with the pinned host launcher in the isolated
`/tmp/wyr1c-c3-target` target:

```text
WYRMROOT_PINNED_TARGET_DIR=/tmp/wyr1c-c3-target \
  tools/pinned-cargo test --tests \
    -p wyrmroot-loader -p wyrmroot-device-proto -p wyrmroot-devmgr \
    -p wyrmroot-system-init -p wyrmroot-wyr1-retained-stubs

result: 209 passed, 0 failed

WYRMROOT_PINNED_TARGET_DIR=/tmp/wyr1c-c3-target \
  tools/pinned-cargo test --test toolchain_lane_contract -p xtask

result: 7 passed, 0 failed

WYRMROOT_PINNED_TARGET_DIR=/tmp/wyr1c-c3-target \
  tools/pinned-cargo clippy \
    -p wyrmroot-device-proto -p wyrmroot-loader -p wyrmroot-devmgr \
    -p wyrmroot-system-init --lib --tests --offline -- -D warnings

result: pass
```

The exact accepted Rust-fork artifact at revision
`a92dc7f7464ad6ddfece4402bd7b86dbfa86166d` also compiled the native
`system-init`, `devmgr`, and `uart16550d` binaries for
`x86_64-unknown-wyrmroot` with locked offline Cargo state. The first native
compile exposed and corrected one host-only import; the fresh rerun passed.
The release build used the registered `wyrmroot-1.97.1-a92dc7f7` compiler and
Cargo from accepted request `RUST-WYR0-I-B-SYSROOTS-007`; its final fresh run
reported `Finished release profile [optimized]` with no network access.

## Required-source disposition

The implementation follows the root recovery architecture, platform
conventions, WYR1 supervisor contract, WYR1-B launch contract, and reached
WYR1-C device-coordinator contract named by the active phase plan. The exact
Fuchsia revision `6a606ff7fd9b055edee6557566fb3f112df1a812` files
`resource.{h,cc}`, `node.{h,cc}`, `driver_runner.{h,cc}`, and the focused
`driver_host.{h,cc}` comparison informed only the separation of coordinator,
construction, execution, and retire-before-replace lifetimes. Their BSD-style
licensed implementation, FIDL/component topology, driver-host colocation,
dynamic linking, node graph, and devfs policy were not copied or adapted.

This is not guest execution, selector-29 admission, DeviceResource or
Interrupt authority, a resource-bundle transfer, UART I/O, driver publication,
or WYR1-C acceptance. DW1-D remains the required next authority seam.
