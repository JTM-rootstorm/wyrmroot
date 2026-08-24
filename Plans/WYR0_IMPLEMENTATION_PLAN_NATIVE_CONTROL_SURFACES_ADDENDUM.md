# Wyrmroot WYR0 Implementation Plan Addendum: Native Control Surfaces and Utility Direction

**Status:** Canonical locked addendum to `Plans/WYR0_IMPLEMENTATION_PLAN.md`  
**Repository:** `JTM-rootstorm/wyrmroot`  
**Milestone:** WYR0 and forward architecture constraint  
**Scope:** Native system introspection, service discovery, device management, tracing/crash handling, logging, storage tools, elevation, scheduled tasks, and utility-porting policy

This document is part of the Wyrmroot implementation contract. Codex and human contributors must treat the decisions below as **locked** unless an explicit revision updates this addendum and the matching Deepwyrm addendum together.

This addendum does **not** expand WYR0 into implementing all of these facilities. It pins how later Wyrmroot milestones should approach common Linux userspace facilities so that WYR0/WYR1 code does not accidentally hard-code compatibility interfaces as native architecture.

The central rule is:

> **Wyrmroot-native administration uses typed services, capabilities, and structured protocols. Linux-shaped interfaces such as `/proc`, `/sys`, `/dev`, D-Bus, udev rules, syslog, cron, `ioctl`, and util-linux conventions are compatibility layers or optional frontends rather than foundational APIs.**

---

# 1. Native system/task introspection instead of `/proc` and `/sys`

Wyrmroot must not require native utilities to scrape Linux pseudo-filesystems.

Native system/task tooling should consume structured Deepwyrm/Wyrmroot APIs and eventually support operations such as:

```text
taskctl list
taskctl tree
taskctl inspect <task>
taskctl handles <task>
taskctl terminate <task>
sysctl get <key>
sysctl set <key> <typed-value>
sysctl describe <key>
```

The command names above are preferred working names, but the **semantics are locked** even if naming changes later.

The native configuration/introspection model should preserve:

- typed values rather than arbitrary text parsing
- descriptions/schema metadata
- explicit permissions
- ranges/validation
- mutability
- stable versioning
- event/change notification where useful

A future POSIX/Linux personality may synthesize `/proc`, `/sys`, and `/proc/sys` from these native interfaces.

---

# 2. Native service registry and typed IPC instead of foundational D-Bus

Wyrmroot should build a small native service-discovery layer over Deepwyrm Channels and transferable handles.

Conceptually:

```text
application
    |
service registry lookup
    |
versioned typed Channel protocol
    |
service
```

Service interfaces should be schema-driven where practical, with generated Rust/C bindings and explicit protocol versions.

The native service system should support, as needed:

- service/interface names
- protocol version discovery
- capability/handle transfer
- connection establishment
- optional activation policy implemented outside the kernel
- change/event messages

Do not make D-Bus itself mandatory for Wyrmroot-native services.

A future D-Bus bridge may translate D-Bus calls/signals/name ownership to Wyrmroot-native services for Qt/Linux/POSIX software that expects D-Bus.

---

# 3. Device manager instead of native udev

Wyrmroot's future userspace device manager (`devmgr` as the preferred working name) owns:

- device discovery consumption
- driver matching/binding
- driver process launch/restart
- capability/resource delegation
- device metadata
- human-readable naming/aliases
- hotplug events
- user/session access policy

Native policy rules should be declarative and typed, preferably schema/TOML-like where rules are needed.

Do not adopt arbitrary shell-script udev rules as the native Wyrmroot policy mechanism.

A native inspection/control tool should eventually provide behavior such as:

```text
devctl list
devctl inspect <device>
devctl driver <device>
devctl events
```

The native device manager works with Deepwyrm capabilities rather than making `/dev` nodes fundamental.

---

# 4. No native `/dev` or universal `ioctl` dependency

Wyrmroot-native applications should acquire device/service capabilities through native service discovery and typed protocols rather than by opening magic device paths.

A POSIX/Linux compatibility layer may provide `/dev` nodes.

Native service protocols should use explicit typed operations rather than a universal `ioctl(fd, request, void *)` escape hatch.

Linux ioctl translation may be implemented later in the compatibility personality.

---

# 5. Native tracing and debugging utility

Wyrmroot should eventually provide a native tracing facility, with `trace` as the preferred working CLI name.

The tracing substrate should be capable of presenting authorized information such as:

- native syscalls
- task creation/exit
- exceptions
- waits/blocking
- IPC/channel metadata
- service-protocol calls where userspace instrumentation/schema support permits it

Desired debugging experience:

```text
trace ./program
```

with structured output showing operations and native statuses rather than requiring Linux `strace` semantics internally.

A POSIX/Linux layer may implement `strace`/`ptrace` compatibility over the native tracing/debug substrate.

The tracing design should be considered before Deepwyrm ABI 1 so the required inspection/exception rights are not impossible to add cleanly later.

---

# 6. Native crash service

Wyrmroot should plan a userspace crash service consuming Deepwyrm's structured exception mechanisms.

A native crash record may include, subject to rights/security policy:

- process/thread identity
- exception/fault type
- register state
- fault address
- mappings
- task hierarchy
- selected handle/object metadata
- native backtrace/symbol information when available

A preferred future CLI is:

```text
crashctl list
crashctl inspect <crash>
```

The native crash format does not need to be an ELF core file.

The POSIX personality may generate ELF core dumps; Windows compatibility may expose Windows-style exception/dump behavior from the same underlying information.

---

# 7. Structured logging service separate from init/service supervision

Wyrmroot should provide a separate logging service (`logd` as the preferred working name) consuming kernel diagnostics and service/application records.

The logging service is **not** PID 1, the bootstrap runner, or the service supervisor.

Native records should support structured metadata such as:

- monotonic and later civil timestamp
- source/service identity
- severity
- subsystem/category
- message
- optional typed fields

Preferred native CLI direction:

```text
logctl show
logctl follow
logctl kernel
logctl service <name>
logctl since <time>
```

A POSIX compatibility layer may expose syslog sockets/files or a `dmesg` frontend.

Do not make journald or classic syslog the native architecture.

---

# 8. Storage/mount control instead of util-linux conventions

Wyrmroot should build typed storage/filesystem services and small native tools rather than making the util-linux collection the native system-management contract.

Preferred working tools:

```text
diskctl
fsctl
mountctl
```

Expected responsibilities include:

- enumerating block devices
- partition inspection
- filesystem inspection/creation when supported
- mounting/unmounting
- mount namespace/view management where later introduced
- image-backed block devices

Native configuration should be structured rather than requiring `/etc/fstab` as the canonical source of truth.

A future mount configuration might use schema/TOML-like records containing source identity, target, filesystem, options, and required/optional policy.

The concrete filesystem-role direction is pinned in `WYRMROOT_STORAGE_FILESYSTEM_DIRECTION.md`: FAT32 serves guest-side EFI System Partition management, ext4 is the initial persistent root, and the eventual Wyrmroot-native filesystem remains a later evidence-driven design track.

POSIX compatibility may provide `mount`, `umount`, `findmnt`, `/etc/fstab`, and related conventions as adapters/frontends.

---

# 9. Image-backed block devices instead of Linux loop-device semantics

The storage architecture should allow a file or `MemoryObject` to be exposed to the storage stack as a block-device object/service through typed operations.

Do not require:

```text
/dev/loopN
losetup
Linux loop ioctls
```

for the native implementation.

This becomes useful for:

- filesystem images
- ISO images
- package/test media
- VM/disk inspection tooling
- removable-media simulation

---

# 10. Capability-aware elevation instead of foundational `sudo`

Wyrmroot's future privilege-elevation model should be based on authorization plus explicit capability delegation.

The preferred direction is:

```text
request operation
      |
authorization broker
      |
restricted capabilities/rights for this invocation
      |
target process
```

rather than automatically transforming the process into an all-powerful UID 0 environment.

A future CLI may use a working name such as:

```text
elevate <command>
```

or provide a familiar `sudo`/`doas` compatibility frontend.

The authorization broker, authentication UI/policy, and account database are later milestones. The locked architectural rule is that native elevation should support least-privilege capability delegation.

---

# 11. Scheduled jobs remain separate from service management

The system service supervisor/controller is not the scheduled-job system.

Wyrmroot should eventually provide a separate scheduled-task service consuming native timers/time services and explicit capability policy.

Jobs should be declarative where practical and should identify the capabilities/authority required to execute.

A future cron-compatible frontend may translate crontab semantics into the native scheduler, but cron is not the native storage/control model.

This preserves the already locked separation:

```text
boot != init != service supervision != dependency control != scheduled tasks
```

---

# 12. Runtime directories/state should be declarative and package-aware

Do not create a separate opaque ecosystem merely to imitate systemd-tmpfiles.

When package/service metadata exists, runtime-state requirements should be declarable alongside the package/service definition where practical, including concepts such as:

- runtime directory creation
- owner/service identity
- permissions
- ephemeral vs persistent state
- cleanup policy

A small dedicated runtime-state component may implement this policy, but it must remain separate from the service supervisor and package resolver.

---

# 13. Native core utilities: port/adapt rather than rewrite everything

Wyrmroot should **not** spend project effort reimplementing commodity utilities merely to claim ownership.

For conventional tools such as:

```text
cat
cp
mv
rm
mkdir
head
tail
wc
sort
cut
find
xargs
diff
cmp
```

prefer adapting mature Rust implementations such as the uutils ecosystem or other suitably licensed projects once Wyrmroot's native Rust `std`/platform support is mature enough.

Ported utilities should use Wyrmroot-native Rust/platform APIs where practical rather than introducing libc as a hidden base dependency.

Write native Wyrmroot-specific tools where they expose uniquely Wyrmroot concepts, especially:

```text
taskctl
sysctl
devctl
logctl
trace
crashctl
diskctl
fsctl
mountctl
elevate
svc
pkg
```

The names remain adjustable; the separation of responsibilities is the locked part.

---

# 14. Priority order for future architecture/implementation

Do not confuse **boot dependency order** with the broader order in which control-plane interfaces deserve design attention.

## 14.1 Boot-critical bring-up order

After WYR0 closes, the default bring-up sequence is:

1. **Small permanent init/supervisor** from bootfs, using only a static bootstrap manifest/readiness graph and the minimum lifecycle/restart authority needed to bring up the base system.
2. **Separate bootstrap service discovery/registry** sufficient for early components to obtain direct Channel capabilities without turning init into a message broker.
3. **Device coordinator plus essential driver servers**, with storage first where required to reach the root device. The coordinator binds/owns devices; it does not become a single all-driver process.
4. **VFS plus FAT32 ESP access**, using real block-device/partition paths. FAT32 is the boot-management filesystem: once running Wyrmroot userspace owns inspection or mutation of installed EFI/boot artifacts, that access must go through Wyrmroot's own storage/VFS/filesystem path rather than host tooling or firmware-runtime shortcuts.
5. **ext4 persistent-root discovery and mount.** Ext4 is the initial normal root filesystem and is required before the persistent post-bootstrap userspace is considered fully online. FAT32 is not promoted into the root role.
6. **Foundational post-root services and recovery/admin console**, including the full registry/discovery surface, configuration/state/runtime machinery, structured logging/crash services, console/TTY/PTY support, and a first useful recovery/administration shell path.
7. **Non-boot-critical hardware/service families** such as general USB classes, networking, audio, accelerated graphics/display/render services, and other restartable domains as their dependencies become available.
8. **Login/session and desktop stack**, followed by normal applications and compatibility environments.

Bootfs must contain enough trusted userspace to execute steps 1-5 without the persistent filesystem already being mounted. Root-mount failure should leave a bounded recovery-capable userspace rather than forcing an immediate reboot or dead machine. FAT32 and ext4 filesystem work may proceed in parallel after common block/VFS prerequisites are stable; the numbered list expresses boot dependencies, not a mandatory implementation serialization.

General service activation, dependency policy, registry/discovery, and supervision remain distinct even when the bootstrap supervisor starts them. The bootstrap supervisor may understand a deliberately tiny static graph; it must not grow into the final dependency controller.

## 14.2 Broader control-plane design priority

Across and after that boot spine, prioritize these interfaces before driver-heavy desktop/audio work unless a concrete dependency justifies interleaving:

1. **Native service registry + typed IPC schemas** so system services do not fragment into ad-hoc protocols or foundational D-Bus.
2. **Device-manager contract** before substantial userspace-driver/hotplug expansion.
3. **Native system/task introspection** so Wyrmroot does not grow `/proc`/`/sys` dependencies.
4. **Native tracing/crash/debug substrate** before ABI 1.
5. **Structured logging service and `logctl`.**
6. **Storage/mount control model** before persistent-system tooling grows around util-linux assumptions.
7. **Authorization/elevation broker architecture.**
8. **Scheduled-task service.**
9. **User/account/credential model.**
10. **Port/adapt conventional command-line utilities.**

This second ordering is directional, not a claim that all ten must exist before the machine can mount root. Dependency-driven parallelism/interleaving is allowed, but implementations must preserve the pinned native-vs-compatibility and fault-domain boundaries.

---

# 15. Driver/service families explicitly deferred

The following remain later subsystem work and are not pulled into WYR0 by this addendum:

- audio service and audio-driver APIs
- network stack/network policy services
- Wi-Fi management
- Bluetooth
- USB policy/classes beyond what boot/storage milestones require
- accelerated graphics
- Glasswyrm native backend
- Prismdrake native desktop integration

When implemented, these should follow the same principle:

> define the native Wyrmroot service/API from native requirements; layer Linux compatibility only where required for third-party software.

Do not invent a native service feature merely because it would unify two compatibility adapters, and do not request a Deepwyrm mechanism merely because a native service can be drawn generically. Shared adapter mechanics should remain restartable userspace unless the cross-personality admission test proves a real privileged/atomicity requirement.

For example, ALSA/PulseAudio/PipeWire compatibility may be useful later, but none should automatically become Wyrmroot's native audio ABI merely because Linux software expects them.

---

# 16. WYR0 implementation implications

This addendum does not expand WYR0 deliverables.

WYR0 implementation must simply avoid choices that make the future architecture impossible:

- temporary diagnostic output must not become the final syslog/TTY/service API
- temporary bootfs access must not become `/proc`, `/sys`, or `/dev`
- bootstrap Channels must remain compatible with a later service-registry layer
- process/task primitives must remain inspectable through rights-bearing native mechanisms
- no WYR0 utility should introduce D-Bus, udev, cron, syslog, util-linux, or sudo as a hidden foundational dependency

If a commodity host-side build utility is useful during WYR0, using it on Gentoo does not violate this policy. The constraint applies to Wyrmroot-native architecture and guest runtime dependencies.

---

# 17. Security implications

The security-validation flow should review later native control services for:

- unauthorized task/system information disclosure
- service-name spoofing or confused-deputy routing
- overly broad capability delegation
- device-manager resource escalation
- tracing/debug authority leaks
- crash/log leakage of secrets or kernel pointers
- elevation brokers granting ambient root-like authority instead of scoped capabilities
- scheduled tasks executing with broader rights than declared
- compatibility bridges bypassing native policy checks

Compatibility adapters must not become a route around Deepwyrm handle rights or Wyrmroot authorization policy.

---

# 18. Locked Wyrmroot native-control gate

Before the corresponding subsystems are considered stable or before native ABI/service contracts are frozen, architecture review must confirm:

- native system/task tools do not depend on `/proc` or `/sys`
- the permanent init/supervisor remains a narrow bootstrap/lifecycle component rather than absorbing the global registry, general dependency controller, device drivers, filesystem implementations, logging, or package policy
- boot-critical discovery, device/storage drivers, and VFS/filesystem services can start from bootfs without persistent root already mounted, with root-mount failure remaining recoverable userspace policy
- FAT32 guest access is available through the native storage/VFS path when userspace must manage ESP boot artifacts, while ext4 is the initial persistent root required for full persistent-userspace onlining
- the device coordinator remains an enumeration/binding/ownership authority rather than a single all-driver fault domain
- native device access/management does not depend on `/dev` or udev rules
- native service discovery does not require D-Bus
- native subsystem control does not use a universal `ioctl` escape hatch
- logging remains separate from init/service supervision
- scheduled tasks remain separate from service supervision
- storage/image control does not require Linux loop-device semantics or `/etc/fstab` as the source of truth
- privilege elevation supports scoped capability delegation
- tracing/crash infrastructure is based on native structured mechanisms rather than Linux `ptrace`/core-dump assumptions
- commodity utilities are ported/adapted where sensible instead of needlessly rewritten
- Linux/POSIX interfaces can be layered as compatibility frontends without defining Wyrmroot's native architecture

This gate is additive to the existing WYR0 functional, security, toolchain, libc-independence, and image-delivery contracts.