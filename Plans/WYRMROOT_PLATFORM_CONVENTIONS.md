# Wyrmroot Platform Conventions

**Status:** Canonical pre-phase-0 platform specification  
**Repository:** `JTM-rootstorm/wyrmroot`  
**Applies to:** WYR0 and all later Wyrmroot milestones unless explicitly revised  
**Companion kernel specification:** `JTM-rootstorm/deepwyrm/Plans/DEEPWYRM_PRE_PHASE0_INVARIANTS.md`

This document is the system-wide convention layer for Wyrmroot. Milestone plans may refine implementation details, but they must not silently contradict these rules. A convention in this document is changed only through an explicit architecture revision that identifies affected Deepwyrm ABI, Wyrmroot service, package, compatibility, or desktop contracts.

The goal is not to design every future subsystem before WYR0 boots. The goal is to prevent temporary bootstrap choices, Linux compatibility conveniences, or individual Codex agents from becoming accidental permanent platform ABI.

The governing principle is:

> **Wyrmroot is a native capability-oriented operating system first. Unix/POSIX, Linux, Windows, DOS/Win16/Win9x, and other compatibility environments are personalities layered above native Wyrmroot interfaces. Compatibility requirements may reveal missing native abstractions, but they do not authorize them merely because the result could be generalized; personality semantics stay above native interfaces unless a separately justified native need exists.**

---

# 1. Convention hierarchy and change control

For compatibility/personality-driven changes, `../personality-plan/CROSS_PERSONALITY_KERNEL_MECHANISM_DOCTRINE.md` is a **scope/admission overlay** on the hierarchy below. Existing Deepwyrm ABI/schema remains authoritative for the semantics of mechanisms already admitted, but more permissive older text must not be interpreted as permission to widen those mechanisms or native Wyrmroot services for compatibility. Family plans may narrow the doctrine, not broaden it.

When documents appear to conflict on ordinary native semantics, use this order unless a newer explicit architecture revision says otherwise:

1. Deepwyrm native ABI schema and locked kernel invariants for kernel-facing behavior.
2. This Wyrmroot Platform Conventions specification for system-wide userspace behavior.
3. The active milestone implementation plan and its locked addenda.
4. Subsystem/interface specifications created by later milestones.
5. Implementation details.

Rules:

- Do not resolve ambiguity by inventing a local convention inside one crate or daemon.
- Cross-repository changes to Deepwyrm/Wyrmroot contracts must be updated in both repositories before dependent implementation proceeds.
- ABI/protocol changes during version `0` are allowed when coordinated and intentional.
- Once an ABI or protocol declares a stable major version, identifiers and incompatible semantics are not silently reused.

---

# 2. Native interface description and wire protocols

Wyrmroot native services use **schema-defined, versioned, typed protocols** over Deepwyrm Channels. The interface-description system may use the working name **WyrmIDL**; the exact schema file syntax/tooling may evolve before its implementation milestone, but the rules below are locked.

## 2.1 Required protocol properties

Native service protocols must:

- define requests, responses, events, records, enums, bitsets, byte/string fields, and transferred handles explicitly
- use fixed-width integer representations on the wire
- use an explicitly defined canonical byte order; Wyrmroot native wire data is **little-endian** unless a subsystem specification explicitly defines an external standardized format
- never serialize Rust/C in-memory structs by accident and call that the wire format
- carry explicit interface/protocol version information
- assign explicit numeric method/event identifiers; IDs are not derived from source order
- never reuse a stable method/event identifier for a different meaning
- bound arrays, strings, nested records, and total message sizes
- identify transferred handle count, expected object type, and minimum required rights in the schema where practical
- reject malformed sizes, impossible enum values when required, unsupported required flags, and unexpected handle sets
- preserve Channel atomicity: payload and transferred handles constitute one transaction

## 2.2 Protocol evolution

Use **major/minor** interface versions:

- major change: compatibility-breaking semantics or wire change
- minor change: backward-compatible additive functionality

Rules:

- clients negotiate/query versions and features explicitly
- software must not infer protocol capability from the Wyrmroot OS release number
- extensible records include size/version information or an equivalent schema-defined extension mechanism
- receivers may ignore documented unknown optional trailing data/extensions
- unknown required flags/features fail explicitly rather than being silently ignored
- removing a stable field/method does not make its identifier available for reuse

## 2.3 Request/reply behavior

The protocol model must permit asynchronous implementations.

- request/reply operations use transaction identifiers when replies are expected
- events are distinguishable from replies
- clients must not rely on all services being single-threaded or replies always arriving synchronously
- long-running operations should be asynchronous or accept a cancellable/absolute-deadline model rather than forcing indefinite synchronous blocking
- protocols document idempotency/retry behavior where service restart or retry matters

## 2.4 Direct channels after discovery

The service registry is a discovery/connection authority, **not a mandatory message router**.

Preferred path:

```text
client
  -> service registry lookup
  -> receive/connect Channel capability
  -> communicate directly with service
```

Do not create a universal broker through which every native IPC message must flow.

## 2.5 FIDL is the principal WyrmIDL prior-art lineage, not a compatibility target

WyrmIDL should begin from Fuchsia FIDL as its primary design prior art and justify meaningful departures instead of independently rediscovering solved IDL/wire-protocol problems. This does **not** promise FIDL source syntax, Fuchsia API, or byte-for-byte wire compatibility.

Concepts to preserve or seriously evaluate include:

- typed protocols with one-way calls, two-way transactions, and events;
- explicit transaction identity and asynchronous implementations;
- bounded strings/vectors/records and deterministic malformed-message rejection;
- strict versus extensible enums/unions/records/protocols, or equivalent explicit evolution semantics;
- typed client/server endpoints layered over ordinary Channels;
- schema-declared transferred-handle object type and minimum rights, enforced by generated bindings using Deepwyrm transfer metadata;
- canonical little-endian validation with complete byte/handle accounting; and
- a compiler frontend that produces one canonical semantic IR consumed by Rust/C/documentation/conformance/fuzzing backends.

Wyrmroot-specific locks remain authoritative where they intentionally differ from FIDL: stable method/event identifiers are explicit numeric IDs rather than source-order or hash-derived ordinals; major/minor versions plus feature negotiation remain explicit; `DwHandle`, Deepwyrm object types/rights, and Channel semantics are native; boundedness requirements remain mandatory; and Rust-first bindings/tooling are preferred.

The WyrmIDL milestone should compare adapting suitable permissively licensed FIDL compiler/generator components against implementing a smaller Rust-native compiler informed by them. Reuse requires file-by-file license/provenance verification and preservation of required notices. Do not fork a large Fuchsia-specific compiler merely to avoid writing a small frontend if the retained Fuchsia policy surface would cost more than it saves.

Keep transport choice below the schema semantics. Deepwyrm Channel transport is the first canonical WyrmIDL transport; a future same-process/colocated optimization may reuse generated protocol semantics only if it preserves the same observable contract and authority checks.

Primary FIDL prior art to inspect and pin at the WyrmIDL implementation milestone includes:

- `https://fuchsia.dev/fuchsia-src/reference/fidl/language/wire-format`
- `https://fuchsia.dev/fuchsia-src/reference/fidl/language/bindings-spec`
- `https://fuchsia.googlesource.com/fuchsia/+/refs/heads/main/docs/reference/fidl/language/fidlc.md`
- `https://fuchsia.dev/docs/contribute/governance/rfcs/0131_fidl_wire_format_principles`

These references inform WyrmIDL; they do not supersede Wyrmroot's locked protocol properties. Pin exact source revisions and record file-level licenses before source adaptation.

---

# 3. Native naming and namespaces

## 3.1 Service and interface names

Wyrmroot-owned native system services/interfaces use the reverse-domain namespace:

```text
org.wyrmroot.*
```

Examples:

```text
org.wyrmroot.task
org.wyrmroot.device
org.wyrmroot.storage
org.wyrmroot.log
org.wyrmroot.package
```

Service names identify semantic services, not implementation binaries or process IDs. Protocol version is negotiated separately and is not embedded into the stable service name unless a future compatibility migration explicitly requires parallel service families.

Existing project namespaces remain canonical:

- Prismdrake: `org.prismdrake.*`
- Glasswyrm native interfaces: existing generic `GW_*` conventions remain authoritative where already defined
- Deepwyrm does not own a userspace global service namespace

## 3.2 Native C symbol prefixes

Where stable/native C bindings are provided:

- Deepwyrm ABI symbols/macros use a `dw_` / `DW_` family
- Wyrmroot native SDK symbols/macros use a `wr_` / `WR_` family

Do not pollute the global C namespace with generic names that collide with libc/POSIX or third-party libraries.

## 3.3 Reserved environment prefix

System-defined Wyrmroot environment variables, where unavoidable, use:

```text
WYRMROOT_*
```

Environment variables are not the primary configuration API; see section 13.

---

# 4. Configuration, state, cache, runtime data, and secrets

These categories are **semantically distinct** and may not be collapsed into one miscellaneous configuration tree.

## 4.1 System categories

The native filesystem/service model must preserve at least:

- **system content**: package-managed operating-system files and immutable/default assets
- **administrator configuration**: persistent intentional policy/configuration
- **service state**: persistent mutable state owned by services
- **cache**: disposable/reconstructible data
- **runtime state**: ephemeral state valid only for the current boot/session
- **secrets**: protected credentials/keys/tokens, not ordinary configuration values
- **user data**: user-owned persistent content

Preferred native top-level direction, to be finalized with the persistent-filesystem milestone:

```text
/system   package-managed system content/defaults
/config   administrator-managed persistent configuration
/state    persistent machine/service state
/cache    disposable system caches
/run      ephemeral boot/session state
/home     user homes/data
/tmp      temporary scratch data
```

These names are the preferred native layout. A later filesystem milestone may refine substructure but must preserve the category separation. POSIX/FHS compatibility may expose `/etc`, `/var/lib`, `/var/cache`, and related paths as adapters/views where required.

## 4.2 Human-edited configuration

When a subsystem uses file-based human-edited configuration, **TOML is the default Wyrmroot configuration format** unless a standardized external format or a concrete technical reason makes another format better.

Do not invent a custom configuration language merely to express normal typed settings.

Configuration files should have schemas/validation where practical. Unknown required configuration fields or invalid types fail clearly; services must not silently reinterpret malformed values.

## 4.3 Package defaults and administrator overrides

Packages may install defaults under package-managed system content. Administrators own overrides under the configuration category.

Packages must not overwrite administrator configuration during normal upgrades without an explicit merge/migration mechanism.

## 4.4 Service state and cache

- mutable service databases do not live beside package-owned binaries
- caches are safe to delete and rebuild by contract
- installation scripts do not prepopulate arbitrary mutable service state when a declarative first-run/migration mechanism can be used
- runtime directories should be declared by the package/service and created by bootstrap/runtime-state machinery, not ad hoc shell scripts

## 4.5 Secrets

Secrets are not normal configuration.

Native Wyrmroot policy:

- do not place secrets in command-line arguments when avoidable
- do not use environment variables as the canonical secret-delivery mechanism
- do not log secrets
- do not include secrets in crash metadata by default
- system services should receive a narrow secret capability or access to a protected secret service/store
- secret values should be exposed to a process only for the scope/lifetime required

Exact at-rest secret storage/encryption is deferred to the identity/security milestone.

---

# 5. Native filesystem and pathname semantics

The initial persistent root filesystem is **ext4**. FAT32 is the EFI System Partition filesystem used for guest-side boot-management access once ordinary userspace owns boot updates. The eventual Wyrmroot-native persistent filesystem/on-disk format remains deliberately unfrozen, but the native namespace semantics below are locked. `WYRMROOT_STORAGE_FILESYSTEM_DIRECTION.md` defines the reached role/sequencing and future-design direction.

## 5.1 Path component representation

- low-level filesystem/path components remain byte-safe
- native Wyrmroot text/path APIs expect valid UTF-8
- `/` is the native path separator
- NUL is not permitted within a path component
- `.` and `..` retain their conventional navigation meanings and are reserved
- the kernel does not perform Unicode localization, collation, case folding, or normalization

## 5.2 Case and Unicode

The native Wyrmroot namespace is **case-sensitive**.

Native path comparison does not silently Unicode-normalize names. A compatibility personality may provide case-insensitive or normalized views when required by Windows/DOS behavior.

## 5.3 Object lifetime versus names

Opening/resolving an object yields a capability/handle or service object independent of later path lookup.

Renaming or unlinking a namespace entry does not retroactively change the identity of an already-open object. Exact deletion/final-lifetime policy is filesystem/service-owned but must support safe open-object lifetime semantics.

## 5.4 Rename and atomicity

A normal native filesystem should provide atomic rename within one filesystem/namespace domain. Cross-filesystem rename is not silently represented as atomic; higher-level software may copy+delete explicitly.

Package/config update machinery may rely on same-filesystem atomic replacement once the persistent filesystem claims that capability.

## 5.5 Links

- symbolic links are explicit namespace objects and require loop/depth protection
- hard links are an optional filesystem capability, not a requirement for every filesystem implementation
- software must query filesystem capabilities rather than assuming every backing store supports hard links, reflinks, sparse files, xattrs, or snapshots

---

# 6. Native executable, library, and dynamic-linking policy

## 6.1 Static-first early system

Early Wyrmroot native milestones use static ELF64 executables. Static linking remains the preferred bootstrap path until the native runtime, TLS, exception/unwind behavior, and library boundaries are proven.

## 6.2 Dynamic loader is userspace

The eventual Wyrmroot dynamic loader is a userspace component.

Deepwyrm must not become aware of:

- `.so` dependency graphs
- symbol lookup
- SONAMEs
- library search paths
- ELF `PT_INTERP` semantics beyond handing control to a userspace-selected loader where future process-loading policy requires it

## 6.3 No stable native shared-library ABI before declaration

Do not treat the first shared native library layout as permanent.

Until a specific native userspace ABI/library major version is deliberately declared stable:

- native shared libraries may change incompatibly
- Wyrmroot base packages are rebuilt together when required
- no compatibility promise is inferred from a filename such as `libwyrmroot.so.1` unless its ABI contract has actually been specified

Kernel ABI versioning and userspace library ABI versioning are independent.

## 6.4 Kernel-provided native vDSO

Wyrmroot should eventually map a kernel-matched, schema-generated Deepwyrm vDSO into every native process. This object is a special kernel/native-ABI mapping, not evidence that the normal dynamic linker or shared-library dependency graph has become a kernel concern. Static native executables must be able to consume it without `PT_INTERP`.

The public native kernel-facing application ABI should be the vDSO's stable `dw_*` symbol surface; raw syscall numbers/register conventions remain bootstrap/private machine-entry details once the vDSO transition is complete. The image should be immutable to applications, freestanding, relocation-free for normal bootstrap use, and limited to read-only data plus executable code. Safe invariant queries and clock reads may gain userspace fast paths behind the same symbols without changing callers.

The exact startup carrier for locating the vDSO is deferred to the loader/startup-contract milestone; do not import Linux `auxv` merely because Linux/Fuchsia use adjacent mechanisms. Mandatory syscall-origin checking against approved vDSO call sites is also deferred and, if adopted, remains defense in depth rather than a substitute for capability authorization.

Foreign personalities retain their own observable ABI entry machinery. A Linux process may require Linux vDSO/vsyscall semantics and a Windows process may require NT/`ntdll`-style stubs even when their translated operations ultimately consume native Deepwyrm/Wyrmroot facilities.

---

# 7. Identity, authorization, capabilities, and privilege separation

Wyrmroot separates:

```text
identity:      who/principal/session is this?
authorization: what policy permits?
capability:    what object authority does this process actually hold?
```

These are not interchangeable.

## 7.1 No native omnipotent UID 0

POSIX UID/GID/root semantics belong to the POSIX personality.

Native Wyrmroot/Deepwyrm does not contain a general rule equivalent to:

```text
if uid == 0: allow everything
```

## 7.2 Principal identifiers

Native principals use opaque stable identifiers. Human-readable names are labels and may change. Software must not assign security meaning to lexical ordering or small integer values of native principal identifiers.

The exact on-disk identity database format is deferred.

## 7.3 Least authority from process start

System services should start with the minimum capabilities they need.

Do not make the native security pattern:

```text
start omnipotent -> initialize -> drop privileges
```

the default merely because traditional Unix daemons do this.

Capability delegation occurs explicitly through bootstrap/service channels.

## 7.4 Elevation

A future native elevation/authorization broker grants narrow capabilities for a requested operation. Elevation should not ordinarily mean replacing the caller with an all-powerful identity.

POSIX `sudo`/`doas` compatibility may be provided later.

---

# 8. Cryptographic randomness

Deepwyrm/Wyrmroot must provide a first-class cryptographically secure randomness source before security-sensitive services depend on random values.

Policy:

- Deepwyrm owns the foundational entropy pool/CSPRNG mechanism
- firmware-provided entropy from the UEFI handoff is an initial seed source, not the only future source
- hardware/platform entropy may be mixed in where trustworthy
- a native secure-random operation returns CSPRNG output without requiring `/dev/random` or `/dev/urandom`
- failure/not-ready behavior is explicit; cryptographic callers do not silently fall back to weak pseudo-random data
- non-cryptographic high-speed PRNGs are userspace libraries seeded from secure randomness as needed

The POSIX personality may synthesize `/dev/random`, `/dev/urandom`, `getrandom()`, or equivalent interfaces from the native facility.

---

# 9. Time and clock domains

Clock domains are explicit.

Wyrmroot reserves at least:

- **monotonic-active clock**: never moves backward; intended for intervals/deadlines during active execution
- **boottime clock**: monotonic since boot and suitable for elapsed-time semantics that may include future suspend intervals
- **civil/UTC time**: userspace-maintained wall clock derived from RTC/network/time policy

DW0's existing monotonic nanosecond deadlines remain valid. Suspend semantics are deferred until power management, but software must identify the clock domain rather than treating all timestamps as interchangeable.

Rules:

- native kernel deadlines use absolute monotonic values
- civil time/timezone formatting is not a kernel responsibility
- structured logs/crash records identify the clock domain of timestamps where ambiguity matters
- timezones/locales are userspace policy

---

# 10. Process termination and exit status

Native Wyrmroot distinguishes **termination reason** from **application exit code**.

A process termination record must be able to represent at least:

- normal exit with a 32-bit application-defined exit code
- explicit termination by authorized task/control operation
- unhandled exception/fault
- policy/resource termination
- parent/task-group teardown where useful

POSIX may map native termination to `waitpid()`/signal conventions. Windows compatibility may map it to Windows process exit/exception conventions.

Do not reduce every native termination to an 8-bit Unix exit status.

---

# 11. TaskGroups, resource limits, and accounting

`TaskGroup` remains the native hierarchy for future resource policy and accounting.

Wyrmroot must be able to grow structured limits/accounting for:

- process/thread counts
- memory
- CPU time/share/priority policy
- IPC/resource-object quotas
- I/O/device policy where appropriate

Do not require Linux cgroups or a cgroup pseudo-filesystem as the native control plane.

Limits and accounting are queried/changed through typed rights-controlled interfaces.

Exact scheduler/resource algorithms are deferred.

## 11.1 Future real-time resource policy

Wyrmroot remains a general-purpose platform, but its native resource-policy layer must preserve the ability to authorize **firm/soft real-time** execution for latency-sensitive native workloads without turning the whole OS into an RTOS.

Platform direction:

- ordinary processes and services use the normal general-purpose scheduling class by default;
- real-time scheduling is privileged resource policy, not an ambient application preference. A future service/resource controller should grant bounded RT authority to an eligible TaskGroup or equivalent scope only when policy and admission control permit it;
- pro-audio, VR/tracking, media, and latency-sensitive display services are expected native consumers, but those examples do not justify audio-, VR-, or graphics-specific Deepwyrm scheduler semantics;
- a synchronous native service dependency that must complete on behalf of RT work must be able to preserve or inherit appropriate scheduling urgency across the client -> service -> driver/service chain. Native service design must not assume that putting only the leaf application at high priority solves end-to-end latency;
- future RT policy should pair execution budgets/reservations with throttling and CPU/IRQ affinity where needed so an authorized RT workload cannot indefinitely starve the normal desktop;
- services entering RT execution should be able to prefault/pin/commit the working memory and resources required for their bounded path before the time-sensitive section begins rather than depending on pageable/file-backed fault handling at an arbitrary instant;
- latency guarantees are measurable properties of an exact kernel, userspace dependency chain, and hardware profile. Wyrmroot must not advertise hard-real-time guarantees on commodity hardware merely because Deepwyrm provides priority/deadline mechanisms; and
- POSIX/Linux/Windows compatibility scheduling APIs translate onto admitted native scheduling/resource mechanisms and remain subject to native authorization/admission policy.

No WYR0 protocol, package declaration, service-manager field, priority scale, or real-time capability format is reserved here. The first post-DW0 scheduler work belongs to Deepwyrm's normal preemptive/SMP foundation; Wyrmroot should begin live end-to-end RT policy integration only after its real process/service dependency chain is sufficiently developed to test propagation honestly.

---

# 12. Feature discovery and compatibility negotiation

Software must query capabilities, interfaces, versions, and feature bits explicitly.

Forbidden native pattern:

```text
if Wyrmroot version >= 3.4, assume feature X exists
```

Preferred pattern:

```text
query interface version
query feature/capability
attempt operation and handle NOT_SUPPORTED
```

OS release/version strings are for humans, diagnostics, packaging policy, and coarse compatibility information, not feature discovery.

---

# 13. Environment variables and command lines

Environment variables are supported as **process-local convenience/compatibility data**, not as the Wyrmroot configuration database.

Native policy:

- system services do not require global environment mutation to configure the machine
- environment values should be UTF-8 in native APIs; POSIX compatibility may preserve byte-oriented semantics where required
- sensitive values should use secret/capability delivery rather than environment variables
- command lines are not secret channels
- startup configuration that carries authority is transferred as capabilities/handles, not magic environment strings

---

# 14. Package ownership and installed-system hygiene

Once package management exists, every package-managed persistent system artifact has an owner.

Rules:

- the base operating system is package-managed too
- installed files are tracked by package manifests/hashes where appropriate
- administrator-created unmanaged files are distinguishable from package-owned files
- package upgrades do not silently seize ownership of unrelated administrator files
- package scripts do not mutate arbitrary system state outside declared transaction/migration boundaries
- packages declare runtime directories, service identities/capabilities, and state/cache needs where practical
- local source builds produce the same installable package format as downloaded binary builds

The package manager may provide `owns`, `verify`, and repair/audit operations from this ownership database.

---

# 15. Update generations and recovery

Wyrmroot boot-critical/system updates are designed around **staged generations**, not irreversible in-place mutation.

The architecture must preserve the ability to represent at least:

```text
current generation
previous known-good generation
rescue/recovery generation
```

A generation may include coordinated versions of:

- Deepwyrm kernel
- bootfs/bootstrap components
- base Wyrmroot packages
- generation manifest and hashes

Rules:

- a new boot generation is staged and verified before becoming current
- boot-critical artifacts are not partially switched one file at a time
- at least one previous known-good boot path can be selected by the Wyrmroot loader/recovery path
- persistent user/service data and administrator configuration are not implicitly rolled back merely because the boot generation changes
- automatic health-check rollback may be implemented later; manual previous-generation selection must remain possible

Cryptographic repository/generation signing policy is deferred to the package/security milestone, but the generation manifest must be designed to accept authenticated hashes/signatures later.

---

# 16. Hardware identity and naming

Hardware identity is not equivalent to enumeration order.

Do not make names such as:

```text
gpu0
net0
disk1
```

the stable persistent identity of a device.

The device manager derives stable identity using the best available evidence, preferring intrinsic identifiers such as device serial/WWN/UUID where available, then stable topology plus hardware descriptors where unavoidable.

Human-readable aliases and current enumeration labels are separate metadata.

Applications that need persistence bind to a stable device identity or user-defined alias, not whichever device happened to enumerate first this boot.

---

# 17. Driver ABI and driver/service protocol stability

Deepwyrm's driver-facing kernel ABI is **not promised stable during early development**.

Rules:

- do not copy Linux internal kernel driver ABI as Wyrmroot's native ABI
- driver/resource operations remain typed and rights-controlled
- userspace driver/service protocols use explicit versions/features
- kernel/driver compatibility is checked explicitly
- once a stable driver ABI major is declared, incompatible changes require a new major rather than silent reinterpretation

The system may rebuild drivers together with Deepwyrm during ABI 0.

---

# 18. Debug/test interfaces versus production interfaces

QEMU/test conveniences are not production ABI.

Rules:

- debug/test-only syscalls, exit ports, host-injected metadata, or test channels use an unmistakably debug/test-only namespace/build mode
- release/native system components must not require QEMU-only interfaces
- debug-only functionality may disappear/change without production ABI compatibility promises
- production builds disable or capability-gate dangerous debug facilities
- test harnesses document when they bypass normal policy so security review does not mistake a test hook for a production backdoor

Host-side GDB over QEMU gdbstub remains normal development tooling and does not imply a guest production debugger service.

---

# 19. Compatibility-personality isolation

Compatibility belongs at explicit boundaries.

## 19.1 POSIX/Linux

The POSIX/Linux environment may provide:

- libc
- Unix file descriptors
- POSIX signals
- `/proc`, `/sys`, `/dev`
- Linux `ioctl` translation where needed
- D-Bus bridge
- udev-like compatibility
- traditional shell/core utilities
- Linux binary syscall personality later

These are adapters over Wyrmroot/Deepwyrm mechanisms, not reverse dependencies of native services.

## 19.2 Windows/NT

Windows compatibility may map native handles, MemoryObjects, waits, task groups, exceptions, filesystem overlays, and service IPC into Win32/NT semantics. Windows-specific quirks such as case-insensitive paths, drive letters, NT status behavior, or historic Win9x differences remain within the Windows personality unless a generally useful native abstraction is independently justified.

## 19.3 DOS/Win16/Win9x

Retro compatibility may use emulation/capsules and behavioral contracts. DOS drive letters, real-mode behavior, VxD quirks, legacy hardware profiles, and similar semantics do not become native Wyrmroot primitives.

## 19.4 General rule

Do not add a native kernel/service feature merely because one or several compatibility personalities expose nearby concepts. **General-purpose, architecture-neutral, or reusable is not sufficient justification.**

Use this order:

1. compose existing native mechanisms/services inside the owning personality;
2. if several personalities genuinely share implementation mechanics, prefer a restartable shared compatibility/Wyrmroot userspace helper while preserving separate observable semantics;
3. add a Wyrmroot-native service feature only when it has an independently justified native-system semantic and does not branch on personality identity to redefine the native contract; and
4. request a Deepwyrm primitive only when a genuinely new personality-blind privileged operation, kernel-lifetime state transition, or atomicity/security guarantee cannot be safely provided above the kernel.

A generic personality/ABI routing hook may identify which installed personality handler should receive a foreign executable/syscall/event. It must not make generic Process, VM, VFS, wait, Channel, or service operations reinterpret the same request according to caller personality. Modest duplicated personality-side code is acceptable when deduplication would create an omnibus native interface or one-more-flag policy surface.

## 19.5 Foreign ABI translation may converge on WyrmIDL native services

After a personality has decoded a foreign syscall/API and applied that personality's observable semantics, route the **resulting native operation** according to what it fundamentally is:

1. use an admitted Deepwyrm mechanism directly when the operation is privilege-bound/kernel-lifetime state already represented by the native kernel ABI, such as VM protection or a wait primitive;
2. use a WyrmIDL native service when the operation belongs to Wyrmroot service/policy, such as storage, networking, graphics, audio, device, or other service-owned behavior; or
3. keep it inside the personality/compatibility service when the semantic object is foreign-specific and does not need a native service operation.

Hybrid foreign objects may choose among these destinations per operation. A Linux fd or Windows HANDLE can wrap a native capability while retaining personality-owned table, inheritance, flag, error, and lifetime behavior. Returned native capabilities may be projected back into Linux fd or Windows HANDLE/object-manager semantics without exposing WyrmIDL to the foreign application.

The foreign ABI terminates at the personality adapter. Native WyrmIDL services receive native semantic requests, not Linux syscall numbers/struct layouts/`errno`, Windows syscall numbers/NT structures/`NTSTATUS`, or a generic personality discriminator. Do not create a universal `org.wyrmroot.compat.Syscall.Invoke(personality, number, args...)` protocol or mechanically serialize every foreign syscall through WyrmIDL.

This is also the width-conversion boundary for service operations: Linux i386/Windows x86 pointer-sized structures are decoded explicitly by the personality and converted into width-neutral WyrmIDL records/handles. Native services must not need to know whether the originating application was 32-bit, 64-bit, Linux, or Windows in order to interpret the same native request.

---

# 20. Native service restart and failure expectations

Wyrmroot services are processes and may crash/restart.

Native clients should be designed with explicit failure behavior:

- Channel peer closure is a normal detectable failure state
- service registry lookups can be repeated to reconnect where policy permits
- durable state is not assumed to live only in process memory unless intentionally ephemeral
- client libraries should expose restart/disconnection errors rather than hanging indefinitely
- critical services may be supervised, but supervision does not make their IPC endpoints immortal

Service activation, registry, supervision, and dependency management remain distinct responsibilities.

## 20.1 Post-WYR0 userspace bootstrap and persistent-root ordering

The first permanent Wyrmroot control process after the primordial bootstrap is a **small init/supervisor**, not a general system-management monolith. The WYR0 `init0` smoke process is explicitly not this component.

Its boot-critical authority is narrow: consume the immutable bootstrap manifest/capabilities, launch and reap the small set of early processes, distribute only required capabilities, observe READY/failure state, apply bounded restart policy where allowed, and coordinate shutdown/reboot sequencing. A minimal static startup graph is acceptable before the general dependency controller exists.

The default dependency spine is:

```text
Deepwyrm
  -> primordial bootstrap
  -> permanent init/supervisor
  -> bootstrap service discovery/registry
  -> device coordinator
  -> essential driver servers, especially block storage
  -> VFS + FAT32 ESP access when boot management requires it
  -> ext4 persistent-root discovery/mount
  -> normal foundational services + recovery/admin console
  -> non-boot-critical drivers/subsystems
  -> login/session/desktop
```

The service registry remains separate from supervision, and the later general dependency controller remains separate from both. Early bootstrap ordering does not authorize init to accumulate their full policy surfaces.

The device coordinator owns enumeration/binding/ownership/hotplug policy; it is not one giant driver process. Individual drivers or coherent driver families should use separate restartable fault domains where practical. Boot-critical storage drivers and filesystem servers must be launchable from bootfs without first requiring persistent root.

FAT32 support exists early for the EFI System Partition and must become available through Wyrmroot's own block/VFS path before running userspace is expected to inspect or mutate installed boot artifacts. It is not the normal root filesystem. The first persistent root is ext4; reaching and mounting that ext4 root is the boundary before the normal persistent userspace is considered fully online.

Bootfs is therefore a real bootstrap/recovery substrate, not merely an executable smoke-test archive and not the permanent filesystem. It should eventually carry enough trusted components to reach the ext4 persistent root and to leave a bounded recovery environment available when that root filesystem cannot be mounted.

Persistent configuration, package/service state, and the full structured logging/configuration services are not bootstrap prerequisites. Bootstrap-critical policy comes from immutable boot-generation/bootfs metadata; file-backed administrator configuration and the normal `/config`/`/state` model become authoritative only after the persistent namespace is available. Secrets remain separate as already specified.

This ordering is a dependency invariant, not a requirement that every listed component be a single process or that unrelated services serialize unnecessarily. Independent early services may start in parallel once their capabilities and dependencies exist.

---

# 21. No universal mutable system registry

Wyrmroot does not adopt a single global mutable key/value registry as the required storage model for all applications/services.

Typed service configuration and file-backed configuration/state are preferred according to ownership/lifetime needs.

A settings service may exist for appropriate desktop/user/system settings, and Windows compatibility may expose registry semantics, but the entire operating system is not required to store arbitrary state in one global registry database.

---

# 22. Text, locale, and presentation

- native system text APIs use UTF-8 when a field is defined as text
- opaque binary data remains bytes and is never forcibly decoded
- system configuration text uses UTF-8 and LF line endings by default
- kernel/Deepwyrm error/status strings are diagnostic presentation layered over numeric/typed status values
- kernel and low-level services do not localize messages
- locale, collation, number/date formatting, and translations are userspace/application concerns

---

# 23. Pre-phase-0 locks intentionally *not* made

The following remain implementation/milestone decisions and must not be inferred from this specification:

- physical page allocator algorithm
- final scheduler algorithm/quantum
- final normal/real-time scheduler-class representation, priority scale, reservation/admission interface, and urgency-propagation policy
- eventual Wyrmroot-native persistent filesystem on-disk format/algorithms beyond the locked initial ext4-root direction
- dynamic-linker implementation details
- package recipe syntax beyond already pinned high-level direction
- final user/account database format
- network stack implementation
- audio API implementation
- Bluetooth/Wi-Fi policy
- USB architecture beyond later driver requirements
- power-management policy
- final graphical buffer/device API
- native shell language beyond the existing native-not-POSIX-first direction
- Secure Boot policy
- installer design
- final shared-library ABI
- exact WyrmIDL surface syntax/compiler implementation and byte layout beyond the locked semantic/evolution/boundedness rules and FIDL prior-art lineage
- exact native-vDSO startup locator/mapping API and optional syscall-origin enforcement policy beyond the locked kernel-matched symbol ABI direction

These are deferred because implementation experience is likely to improve the decision.

---

# 24. Milestone compliance checklist

Every future Wyrmroot milestone plan should explicitly check whether it introduces or changes any of the following:

- native protocol/IDL contract
- service namespace
- post-primordial bootstrap/supervision/device/VFS dependency topology
- filesystem/path semantics
- configuration/state/cache/secret ownership
- identity/capability authority
- native library ABI
- package ownership/update generations
- task/resource accounting
- scheduler/real-time authorization, admission, or urgency-propagation policy
- clock domains
- device identity
- debug-only API
- compatibility-personality boundary

If yes, the plan must either conform to this specification or include an explicit architecture revision.

---

# 25. Phase-0 readiness statement

With this specification plus the existing WYR0 plan/addenda and the Deepwyrm companion invariants, Wyrmroot has enough pre-phase-0 architecture locked to begin implementation.

Do **not** continue adding speculative platform architecture before WYR0 unless a concrete implementation blocker exposes a missing contract. From this point forward, prefer implementing, testing, security-reviewing, and revising based on evidence over designing distant subsystems in advance.
