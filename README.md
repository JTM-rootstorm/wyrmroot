# Wyrmroot

Wyrmroot is an experimental Rust-first, capability-oriented operating-system project whose architecture is built around the [Deepwyrm](https://github.com/JTM-rootstorm/deepwyrm) kernel.

## Intent

Wyrmroot's architecture defines native operating-system interfaces first. Unix/POSIX and other compatibility environments belong as personalities layered above native Wyrmroot interfaces rather than foundations of the kernel ABI.

Native service protocols are required to be typed and versioned, and the platform is based on explicit delegation of authority. The base system is not founded on libc or POSIX.

The architecture keeps boot loading, executable loading, service management, package management, compatibility, graphics, and desktop policy as distinct responsibilities rather than one privileged subsystem.

## Architectural shape

```text
UEFI firmware
    |
Wyrmroot EFI loader
    |
Deepwyrm
    |
primordial Wyrmroot bootstrap
    |
normal Wyrmroot userspace and services
```

This diagram describes durable component boundaries, not implementation or acceptance status.

## Platform boundary

Deepwyrm owns the native kernel ABI, kernel objects and rights, and low-level mechanisms. Wyrmroot owns the EFI loader, bootfs, userspace startup semantics above the primordial handoff, executable-loading policy, native service protocols, image assembly, and higher-level capability distribution.

Wyrmroot consumes generated Deepwyrm ABI definitions from an exact pinned Deepwyrm revision rather than duplicating kernel definitions. Linux-shaped control surfaces and compatibility APIs may be exposed by adapters where useful, but they are not foundational Wyrmroot interfaces. Multiple foreign APIs wanting similar behavior does not, by itself, justify a new native service or kernel primitive; compatibility is expected to compose existing mechanisms first and keep foreign policy in adapters.

## Related projects

- [Deepwyrm](https://github.com/JTM-rootstorm/deepwyrm) provides the kernel.
- [Glasswyrm](https://github.com/JTM-rootstorm/glasswyrm) is the intended native window-system and compositor foundation.
- [Prismdrake Desktop Environment](https://github.com/JTM-rootstorm/prismdrake-de) is the intended desktop environment.

## Documentation

- [Architecture and plan index](Plans/ARCHITECTURE_INDEX.md)
- [Platform conventions](Plans/WYRMROOT_PLATFORM_CONVENTIONS.md)
- [WYR0 implementation plan](Plans/WYR0_IMPLEMENTATION_PLAN.md)
- [Licensing policy and component map](LICENSING.md)
- [Validation records](validation/)
- [Security reviews](security/)

Architecture documents define design contracts. Validation and security evidence applies only to the revisions and artifacts each record names; it does not imply production, VM, or physical-hardware acceptance.

## License

Wyrmroot currently uses a component-aware mix: the repository fallback and several existing foundations are [GPL-2.0-or-later](LICENSE), while selected applications and tools are `GPL-3.0-or-later`. New wholly first-party project code defaults to GPL-3.0-or-later; GPLv2-compatible lanes are selected when actual provenance or combination requirements call for them. See [LICENSING.md](LICENSING.md) for the authoritative current map and provenance rules.
