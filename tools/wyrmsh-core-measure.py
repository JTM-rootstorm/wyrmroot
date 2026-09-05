#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Pinned, host-only E2 fixed-state and LLVM per-frame measurement.

Owns all compiler flags and outputs. Never builds or executes a guest target.
Use a fresh output path directly beneath the repository's .tmp directory.
"""

import argparse
import hashlib
import json
from pathlib import Path
import stat
import subprocess
import tomllib

REPO = Path(__file__).resolve().parent.parent
READOBJ = Path('/usr/lib/llvm/22/bin/llvm-readobj')
# Same accepted LLVM identity used by tools/xtask/src/wyr1b.rs.
READOBJ_SHA = '8074c683dc2c5bfebd5e68245b9d435a3a44ff7e232f20b6a1d01a22f5d7caf8'


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def regular(path, unique=True):
    info = path.lstat()
    if path.resolve() != path or not stat.S_ISREG(info.st_mode) or (unique and info.st_nlink != 1):
        raise ValueError(f'expected regular resolved file: {path}')


def run(command, output, env, name, timeout=60):
    result = subprocess.run([str(arg) for arg in command], cwd=REPO, env=env,
                            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, timeout=timeout, check=False)
    (output / f'{name}.stdout').write_bytes(result.stdout)
    (output / f'{name}.stderr').write_bytes(result.stderr)
    if result.returncode:
        raise RuntimeError(f'{name} exited {result.returncode}; see {output}')
    return result.stdout


def frames(value):
    found = []
    if isinstance(value, dict):
        if 'Functions' in value and 'Size' in value:
            size = value['Size']
            size = int(size, 0) if isinstance(size, str) else size
            if not isinstance(size, int) or size < 0:
                raise ValueError('invalid frame size')
            found.extend({'function': name, 'bytes': size} for name in value['Functions'])
        for child in value.values():
            found.extend(frames(child))
    elif isinstance(value, list):
        for child in value:
            found.extend(frames(child))
    return found


def main():
    arguments = argparse.ArgumentParser(description=__doc__)
    arguments.add_argument('output', type=Path)
    output = arguments.parse_args().output.absolute()
    if output.resolve() != output or output.parent != REPO / '.tmp' or output.exists():
        raise ValueError('output must be a fresh resolved direct child of repository .tmp')
    if output.parent.resolve() != output.parent:
        raise ValueError('unresolved output parent')
    identity = tomllib.loads((REPO / 'toolchain/host-rust-toolchain.toml').read_text())
    manifest_path = REPO.parent / 'artifacts/toolchains/accepted/RUST-WYR0-I-B-SYSROOTS-007/manifest.toml'
    manifest_sha = 'cc78368219552cce8fdaad38ab419040cab945fe175aa774d6dca51eece84fd2'
    regular(manifest_path)
    if digest(manifest_path) != manifest_sha:
        raise ValueError('accepted compiler manifest mismatch')
    accepted = tomllib.loads(manifest_path.read_text())
    toolchain = manifest_path.parent / accepted['toolchain_directory']
    if toolchain.resolve() != toolchain:
        raise ValueError('accepted toolchain path changed')
    admitted = {}
    for key in ['rustc', 'rustc_driver', 'llvm', 'host_std', 'host_core',
                'host_proc_macro', 'host_compiler_builtins']:
        item = accepted['artifacts'][key]
        path = manifest_path.parent / item['path']
        regular(path)
        if not path.is_relative_to(toolchain) or digest(path) != item['sha256']:
            raise ValueError(f'accepted host component mismatch: {key}')
        admitted[path] = item['sha256']
    rustc = manifest_path.parent / accepted['artifacts']['rustc']['path']
    regular(READOBJ)
    if digest(READOBJ) != READOBJ_SHA:
        raise ValueError('LLVM tool identity mismatch')
    output.mkdir()
    temporary = output / 'tmp'
    temporary.mkdir()
    env = {'PATH': '/usr/lib/llvm/22/bin:/usr/bin:/bin', 'TMPDIR': str(temporary),
           'LC_ALL': 'C', 'WYRMROOT_PINNED_TARGET_DIR': str(output / 'cargo-target')}
    run([REPO / 'tools/pinned-cargo', 'check', '--locked', '--offline',
         '-p', 'wyrmroot-wyrmsh-core', '--lib'], output, env, 'pinned-preflight')
    version = run([rustc, '-vV'], output, env, 'rustc-version').decode()
    if 'host: x86_64-unknown-linux-gnu' not in version or accepted['source_commit'] not in version:
        raise ValueError('measurement requires exact pinned x86_64 Linux host compiler')
    sysroot = run([rustc, '--print=sysroot'], output, env, 'sysroot').decode().strip()
    libdir = run([rustc, '--print=target-libdir', '--target=x86_64-unknown-linux-gnu'],
                 output, env, 'host-libdir').decode().strip()
    if Path(sysroot) != toolchain or Path(libdir) != toolchain / 'lib/rustlib/x86_64-unknown-linux-gnu/lib':
        raise ValueError('accepted host sysroot mismatch')
    llvm_version = run([READOBJ, '--version'], output, env, 'llvm-version').decode()
    if 'LLVM version 22.1.8' not in llvm_version:
        raise ValueError('LLVM version mismatch')
    flags = ['--edition=2024', '--target=x86_64-unknown-linux-gnu',
             '-Copt-level=2', '-Ccodegen-units=1', '-Cpanic=abort',
             '-Cembed-bitcode=no', '-Zemit-stack-sizes',
             '--remap-path-prefix', f'{REPO}=/wyrmroot']
    source = REPO / 'crates/wyrmroot-wyrmsh-core/src/lib.rs'
    fixture = REPO / 'tools/wyrmsh-core-measure.rs'
    source_paths = sorted(source.parent.rglob('*.rs')) + [
        fixture, Path(__file__).resolve(), source.parent.parent / 'Cargo.toml',
        REPO / 'toolchain/host-rust-toolchain.toml']
    for path in source_paths:
        regular(path)
    source_hashes = {str(p.relative_to(REPO)): digest(p) for p in source_paths}
    run([rustc, *flags, '--crate-name=wyrmroot_wyrmsh_core', '--crate-type=rlib',
         '--emit=link,obj', '--out-dir', output, source], output, env, 'compile-core')
    library = output / 'libwyrmroot_wyrmsh_core.rlib'
    binary = output / 'wyrmsh_core_measure'
    # LLVM/Clang are explicit host tools; the fixture is not a guest ELF.
    linker = Path('/usr/lib/llvm/22/bin/clang').resolve()
    regular(linker, unique=False)
    lld = Path('/usr/lib/llvm/22/bin/ld.lld').resolve()
    regular(lld, unique=False)
    link_tools = {linker: '02ee323c47e4647fec0ecafe250d96597d41826a56507fb2d6fcc553393d5d7c',
                  lld: 'fe90dca7f3c3703b8313e74d4c97602250a43effbcb1a52d75a35c71eb88048a'}
    if any(digest(path) != value for path, value in link_tools.items()):
        raise ValueError('host linker identity mismatch')
    run([rustc, *flags, '--crate-name=wyrmsh_core_measure', '--emit=link,obj',
         f'-Clinker={linker}', '-Clink-arg=-fuse-ld=lld', '--extern',
         f'wyrmroot_wyrmsh_core={library}', '--out-dir', output, fixture],
        output, env, 'compile-fixture')
    artifacts = {name: digest(output / name) for name in
                 ['libwyrmroot_wyrmsh_core.rlib', 'wyrmroot_wyrmsh_core.o',
                  'wyrmsh_core_measure', 'wyrmsh_core_measure.o']}
    all_frames = []
    for name in ['wyrmroot_wyrmsh_core.o', 'wyrmsh_core_measure.o']:
        data = run([READOBJ, '--elf-output-style=JSON', '--stack-sizes', '--demangle',
                    output / name], output, env, f'stack-{name}')
        selected = frames(json.loads(data))
        if not selected:
            raise ValueError(f'no named stack metadata in {name}')
        all_frames.extend(selected)
    if not any('measurement_entry' in item['function'] for item in all_frames):
        raise ValueError('measurement entry frame missing')
    sizes = json.loads(run([binary], output, env, 'exercise'))
    for name, expected in artifacts.items():
        if digest(output / name) != expected:
            raise ValueError(f'artifact changed during measurement: {name}')
    if (digest(manifest_path) != manifest_sha or digest(READOBJ) != READOBJ_SHA
            or any(digest(path) != value for path, value in (admitted | link_tools).items())):
        raise ValueError('tool identity changed during measurement')
    if any(digest(REPO / name) != value for name, value in source_hashes.items()):
        raise ValueError('source changed during measurement')
    report = {'kind': 'wyrmsh-e2-host-memory-v1', 'sizes': sizes,
              'test_rustc_commit': identity['rustc_commit'],
              'measurement_rustc_commit': accepted['source_commit'], 'rustc_sha256': digest(rustc),
              'accepted_manifest_sha256': manifest_sha,
              'llvm_readobj_sha256': READOBJ_SHA, 'host_linker_sha256': digest(linker), 'host_lld_sha256': digest(lld),
              'flags': flags, 'artifacts': artifacts,
              'sources': source_hashes,
              'frames': sorted(all_frames, key=lambda item: (-item['bytes'], item['function'])),
              'nonclaims': 'Host fixed state, per-frame metadata and bounded exercise only; '
                           'not an exhaustive aggregate call-chain or native E6 shell stack proof.'}
    (output / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'sizes': sizes, 'maximum_named_frame': report['frames'][0],
                      'report': str(output / 'report.json')}, indent=2))


if __name__ == '__main__':
    main()
