# Wyrmroot

**Wyrmroot** is an experimental Rust-first operating system built around the [Deepwyrm](https://github.com/JTM-rootstorm/deepwyrm) kernel.

The project aims to provide a modern native operating-system substrate with a Unix/POSIX environment as one userspace personality rather than making traditional Unix semantics the kernel's only internal model. Long term, Wyrmroot is also intended to host native Windows-compatibility and retro-compatibility layers while remaining its own operating system.

> **Status:** early architecture and bootstrap planning. Initial implementation should stop at a reliable text-mode/self-hosting system before graphical integration begins.

## Repository bootstrap status

The repository is being scaffolded for phase WYR0-A. The initial tree establishes project
boundaries, pinned-input metadata, and host-checkable workspace structure only. It does not yet
implement the UEFI boot path, native runtime, image construction, QEMU integration, or any WYR0
acceptance gate.

Command names described in `Plans/` are planned interfaces until their corresponding tooling is
implemented and tested. Do not treat the presence of a crate, target definition, manifest, or
placeholder entry point as evidence that a Wyrmroot guest artifact can boot or run.

## Project goals

- **Own the operating system stack.** Wyrmroot is not intended to be a Linux distribution or a reskinned existing Unix.
- **Rust first.** Core userspace, system tooling, and the Deepwyrm kernel should prefer Rust, with C/C++/assembly used where required or advantageous.
- **Native API first, Unix compatibility above it.** POSIX and Unix behavior should be provided without forcing every kernel primitive to imitate Unix internally.
- **Modular system services.** Boot loading, PID 1, bootstrap orchestration, service supervision, dependency management, logging, networking, sessions, and desktop services should remain separate components.
- **No mandatory Python runtime for core package management.** The native package manager is planned as a Rust program with declarative recipes, USE-like feature selection, source builds, binary packages, caches, sandboxing, and transactions.
- **Source configurable without being source only.** Locally built packages and downloaded binary packages should share the same installation format and transaction path.
- **Compatibility as a first-class architecture concern.** Native, Unix/POSIX, modern Windows, and retro DOS/Windows environments should be possible without turning the kernel into a clone of another OS.
- **Reuse our existing graphical stack.** [Glasswyrm](https://github.com/JTM-rootstorm/glasswyrm) is the intended compositor/window-system foundation and [Prismdrake Desktop Environment](https://github.com/JTM-rootstorm/prismdrake-de) is the intended desktop environment once their Rust ports and platform separation are ready.

## Planned system shape

```text
Applications
    |
    +-- Native Wyrmroot software
    +-- Unix / POSIX software
    +-- Windows compatibility
    +-- Retro DOS / Win16 / Win9x compatibility
    |
Wyrmroot userspace services
    |
Deepwyrm kernel
    |
hardware
```

The kernel should provide general primitives; Wyrmroot userspace turns those primitives into recognizable operating-system environments.

## Boot architecture

Wyrmroot deliberately does **not** plan to recreate systemd as a monolithic dependency.

The intended boot path is:

```text
UEFI firmware
    |
Wyrmroot EFI loader
    |
Deepwyrm
    |
minimal PID 1
    |
one-shot bootstrap runner
    |
service supervisor
    |
service dependency controller
    |
login / user session
```

Each layer has one job:

- **EFI loader:** load the kernel, initial userspace image, configuration, and boot metadata.
- **PID 1:** maintain the minimum root userspace process, reap children, coordinate shutdown, and provide rescue fallback.
- **Bootstrap runner:** perform the one-time transition from a freshly started kernel into the installed system.
- **Supervisor:** keep selected long-running processes alive.
- **Service controller:** resolve normal service dependencies and policy.

A software service manager should not need to know how UEFI found the kernel.

## Package-management direction

Wyrmroot's native package system is planned around the useful ideas of Gentoo and pkgsrc without requiring Portage or Python.

Expected properties include:

- declarative package recipes, likely TOML-based
- USE-like optional feature selection
- conditional dependencies
- slots / parallel ABI versions where useful
- first-class source builds
- first-class binary packages and caches
- sandboxed build phases
- transactional installs and upgrades
- build/host/target awareness from the beginning
- profiles for minimal, developer, server, desktop, and other system roles
- tooling to import or translate packaging knowledge from projects such as Gentoo rather than executing ebuilds as the native package format

Everything installed onto the normal system, including base components, should ultimately be representable as packages.

## Compatibility direction

Wyrmroot is intended to support several distinct compatibility families over time:

### Unix / POSIX

A conventional Unix-like environment for porting existing open-source software and providing familiar shell, filesystem, process, and networking behavior.

### Modern Windows

A Windows/NT personality designed around observable API and object semantics rather than copied Windows implementation details. Wine and other clean-room/open-source compatibility work may provide useful components and behavioral references.

### Retro Windows and DOS

Long-term targets include DOS 7.x-era software, Win16, and Windows 9x software, with **Windows 98 SE** intended as an important frozen reference target. Difficult software may run through tightly integrated emulation or compatibility capsules while ordinary applications increasingly use native compatibility layers.

Compatibility research should use public documentation, independently written probes, clean-room behavioral contracts, and legally obtained reference systems. Microsoft implementation code or leaked source is not part of the development model.

## Graphics and desktop

The planned graphical stack is:

```text
Prismdrake Desktop Environment
            |
           Qt
            |
Glasswyrm-native platform integration
            |
        Glasswyrm
            |
Wyrmroot graphics / input services
            |
         Deepwyrm
```

Before native Wyrmroot graphics work becomes a major focus, the current Glasswyrm and Prismdrake Rust rewrites should reach functional parity and their Linux-specific dependencies should be pushed behind explicit platform interfaces.

Linux support for both projects should remain available as a reference and development environment.

## Early roadmap

The initial Wyrmroot target is deliberately text-first:

1. boot Deepwyrm through UEFI/QEMU
2. establish memory management, processes, IPC, timers, and basic devices
3. start minimal userspace and PID 1
4. mount/use a real filesystem
5. provide a TTY and native shell
6. add the initial package manager and base package set
7. add networking and remote development access where practical
8. reach a self-hosting development environment
9. only then begin native Glasswyrm bring-up
10. bring Prismdrake across after the graphics path is stable

A successful early system should be able to reach something conceptually like:

```console
wyrmroot login: root
$ pkg install git
$ cargo build
$ ./hello
```

before the project spends substantial effort on a polished desktop.

## Related projects

- [Deepwyrm](https://github.com/JTM-rootstorm/deepwyrm) - Wyrmroot kernel
- [Glasswyrm](https://github.com/JTM-rootstorm/glasswyrm) - compositor/window-system project intended for native Wyrmroot support
- [Prismdrake Desktop Environment](https://github.com/JTM-rootstorm/prismdrake-de) - intended Wyrmroot desktop environment

## License

Wyrmroot is licensed under the **GNU General Public License v3.0**.
