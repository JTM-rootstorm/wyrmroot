//! `xtask dev-boot`: the development-tier boot (root `CLAUDE.md` §9).
//!
//! Builds the current normal product from the committed Wyrmroot and Deepwyrm
//! HEADs with the same producer as `wyr1f prepare --scenario normal`, then boots
//! it in local QEMU on the canonical q35/OVMF arguments. COM1 (kernel log) goes
//! to a file; COM2 (the `wyrmsh` console) is the terminal, so the system can be
//! used directly. Ctrl-D at an empty prompt shuts the system down.
//!
//! `--check` drives COM2 instead, over two boots of the same disks. The
//! first waits for the prompt and lists `services` until the boot-disk
//! driver's `device.block.virtio0` (root `STORAGE_PLAN.md` W2; it publishes
//! only after DMA reads of block 0 through its virtqueue), the data disk's
//! `device.block.virtio1`, `volume.boot0`, `volume.root0` and `system.vfs`
//! (W6, W7) are all published; lists `/` until ext4d's root (with its
//! `lost+found`) is mounted there; lists `/boot/EFI/WYRMROOT` and `cat`s its
//! README through vfsd, fat32d and blockmgr; runs the idle-BSP probe
//! `bin/hello close-spin` three times while the system is quiet, after
//! which the first boot's report must show an owed-work wake for each run
//! that spun on an AP, and its longest finalize gap is reported (Deepwyrm
//! DW2 §10.19, `memory.rs`); runs `bin/hello touch-loop 64 20`, which
//! times a first touch of an on-demand page, and requires the kernel's
//! `faults`, `faults-fast` and `faults-shared` lines together to count its
//! pages (DW2 M8 §13.5, `touch.rs`) and its `fault-ahead` line to count at
//! least half of them as committed ahead of a stream (DW2 M8b §15.6 step
//! 2), then
//! `bin/hello touch-loop 64 20 committed`, which commits each object before
//! touching it, and requires the kernel's `faults-shared` line to count at
//! least half its pages as served with the paging lock shared (DW2 M8b
//! §15.2 step 1); spawns two
//! `bin/cpu-hog` jobs,
//! which hold their own FP registers and FS base while they preempt each
//! other; runs `bin/hello` with its on-demand MemoryObject probe, which must
//! pass and then end in `resource-policy` once its page quota is spent
//! (Deepwyrm DW2 M6); runs DW2 M5's memory probes (`memory.rs`), whose
//! kernel step report the first boot's COM1 log must then carry; runs
//! `bin/hello` (a shell job under its TaskGroup limits) and the
//! same ELF from the ESP to their output and the next prompt (with `--sdk`,
//! also the SDK's programs); terminates the hogs and requires each to have
//! been still running; then writes a
//! file and makes a directory on the root (W7) and shuts down with Ctrl-D.
//! The second boot `cat`s the file back, removes it, under `--smp` runs
//! `touch-loop` three at once and requires its faults counted, then three
//! at once again with every job `committed` and requires its shared faults
//! counted, and shuts down; its fault (each with its parts line),
//! shared-fault, fault-pass, commit-ahead, stream, lock, lock-hold
//! (`p-held`, any number), usage-check, commit-step and admission-wait lines
//! are printed.
//! Each boot's step report must carry `faults-shared`,
//! `fault-declines-shared`, `fault-ahead` and `streams` lines that parse,
//! and each boot prints the frames committed ahead and their mean. Each boot must end with the kernel's power-off line on its
//! COM1 log, and its step report must carry `records-dropped=0`, a
//! `usage-check` line with TaskGroups compared and no mismatch (DW2 M8
//! §13.12 part a) and an `admission-waits` line, whatever its counts (DW2
//! M8 §13.12 part b). That is the smoke check for development commits.
//!
//! `--icount` is a measurement mode: QEMU runs with `-icount shift=0`, so
//! guest time advances by one nanosecond per guest instruction and the
//! kernel's clock counts instructions. The `[steps]` report then counts guest
//! instructions per step, independent of host load and of how TCG chains its
//! translations. QEMU runs every vCPU on one thread under `-icount`, so the
//! check waits four times as long ([`Patience`]), and its pass line ends in
//! `icount=1`. In every mode the check prints each call's mean step from the
//! report's `call-total-us` and `call-steps` lines ([`step_means`]), in
//! microseconds, or under `--icount` in thousands of guest instructions.
//!
//! `--kvm` is the timing mode: QEMU runs the guest under KVM (`-accel kvm`,
//! `-cpu host,migratable=no,+invtsc`), so the kernel's step times are real
//! time on the host CPU, under virtualization; the guest sees the host's
//! invariant TSC, which QEMU exposes only to a non-migratable guest. The
//! emulated VT-d's interrupt remapping needs the split irqchip there
//! (`-machine q35,kernel-irqchip=split`). The check refuses to start unless
//! `/dev/kvm` opens read-write, keeps the base waits, prints the step means
//! in nanoseconds and ends its pass line in `kvm=1`.
//! The kernel reports totals in whole microseconds, so a nanosecond mean
//! (`call-total-us * 1000 / call-steps`) is exact only to that.
//!
//! The persistent root is a second, writable virtio disk at 00:02.0: a copy
//! of the product's empty ext4 `root.img`. `--check` makes a fresh copy per
//! run; an interactive run keeps one at `OS-Project/.tmp/dev-boot/root.img`
//! across runs.
//!
//! Nothing here is milestone evidence. It writes no request, receipt or result
//! a gate could consume, and its output under `OS-Project/.tmp/dev-boot/` is
//! disposable.

use std::{
    fs,
    io::{Read, Write},
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Child, ChildStdin, Command},
    sync::{Arc, Mutex},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use crate::{error::Failure, product, tasks};

mod memory;
mod qemu;
mod shell;
mod touch;

use qemu::{boot_once, create_root_disk, kvm_access, qemu_arguments};
use shell::{END_OF_INPUT, PROMPT, Shell, contains, spawn_job, strip_escapes, wait_until};

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct DevBoot {
    pub(crate) check: bool,
    pub(crate) smp: bool,
    pub(crate) clock: Clock,
    pub(crate) deep_repository: Option<String>,
    /// A built Wyrmroot SDK (`wyrmroot-sdk/out`) whose test programs go on
    /// the ESP and, under `--check`, run (root `TOOLCHAIN_PLAN.md` step 2).
    pub(crate) sdk: Option<String>,
}

/// What the guest's clock measures, which QEMU's accelerator decides.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) enum Clock {
    /// QEMU's emulator (TCG): guest time follows the host loosely.
    #[default]
    Emulated,
    /// QEMU's `-icount shift=0`: guest time counts guest instructions.
    Icount,
    /// KVM: the guest runs on the host CPU, so its time is real time.
    Kvm,
}

/// The device KVM is opened through.
const KVM_DEVICE: &str = "/dev/kvm";

const CHECK_TIMEOUT: Duration = Duration::from_secs(180);
const POWER_OFF: &[u8] = b"no process remains; powering off";
/// The kernel's record that every CPU runs with SMEP and SMAP (Deepwyrm
/// DW2 M2): the guest CPU has both, so the kernel must have turned them on.
const SUPERVISOR_PROTECTIONS_ON: &[u8] = b"[DW0][INFO][cpu] smep and smap on";
/// Every service the storage spine publishes (root `STORAGE_PLAN.md` W2-W7).
const SERVICES: [&[u8]; 5] = [
    b"service name=device.block.virtio0 ",
    b"service name=device.block.virtio1 ",
    b"service name=volume.boot0 ",
    b"service name=volume.root0 ",
    b"service name=system.vfs ",
];
/// The ESP read back through vfsd, fat32d and blockmgr.
const ESP_LISTING: [&[u8]; 2] = [b"bootstrap.elf\r\n", b"README.TXT\r\n"];
const ESP_README: &[u8] = b"This is the Wyrmroot EFI System Partition.";
const JOB_OUTPUT: &[u8] = b"hello from native stdout";
/// The SDK's test programs (`wyrmroot-sdk/programs`, on the ESP as
/// [`crate::product::SDK_FILES`]): each command and the line it must print
/// before exiting normally with status 0. They run while the CPU hogs preempt
/// them, so a C program's SSE state is witnessed across preemption, and each
/// disk request crosses ext4d, blockmgr and virtio-blkd under load: without
/// Deepwyrm's D8 (a Thread that blocks keeps its unused quantum) every hop
/// waits out a time slice and SQLite's test does not finish in time.
const SDK_RUNS: [(&str, &[u8]); 7] = [
    (
        "run /boot/EFI/WYRMROOT/SDKHELLO.ELF",
        b"hello from musl: 1 argument, 6*7=42, pi=3.14159, pages=2048",
    ),
    // zlib's own test/example.c, with its gzip file on the root filesystem.
    (
        "run /boot/EFI/WYRMROOT/ZEXAMPLE.ELF /zlib-example.gz",
        b"inflate with dictionary: hello, hello!",
    ),
    // The Lua interpreter running `wyrmroot-sdk/programs/test.lua`.
    (
        "run /boot/EFI/WYRMROOT/LUA.ELF /boot/EFI/WYRMROOT/TEST.LUA",
        b"lua tests passed: ",
    ),
    // The sqlite3 shell, then `wyrmroot-sdk/programs/sqlite-test.c`, which
    // removes its own database.
    ("run /boot/EFI/WYRMROOT/SQLITE3.ELF -version", b"3.54.1 "),
    (
        "run /boot/EFI/WYRMROOT/SQLTEST.ELF",
        b"sqlite tests passed: ",
    ),
    // DW2 M5 probe 16: one 256 MiB malloc and more than 16 MiB of small
    // ones, past the old ceiling; then every mapping slot spent, which
    // `mmap` and a split `munmap` report as ENOMEM.
    (
        "run /boot/EFI/WYRMROOT/MEMTEST.ELF",
        b"memory tests passed: large=256MiB",
    ),
    (
        "run /boot/EFI/WYRMROOT/MEMTEST.ELF slots",
        b"mmap=ENOMEM split=ENOMEM",
    ),
];
/// Files the SDK programs leave on the root filesystem.
const SDK_LEFTOVERS: [&str; 1] = ["/zlib-example.gz"];
/// Services and mounts come up beside the shell, so their checks are retried.
const ATTEMPTS: usize = 20;
/// How much longer the check waits under `--icount`, where QEMU runs every
/// vCPU on one thread and counts instructions exactly.
const ICOUNT_PATIENCE: u32 = 4;
/// The calls the kernel's step report times in steps, in its order.
const STEP_CALLS: [&str; 9] = [
    "map", "unmap", "protect", "fill", "commit", "create", "teardown", "release", "finalize",
];

/// How long a check waits on the guest: the boot's deadline and the number
/// of attempts of every loop that polls it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Patience {
    timeout: Duration,
    attempts: usize,
}

impl Patience {
    /// The base waits, or under `--icount` [`ICOUNT_PATIENCE`] times them.
    /// KVM is faster than the emulator, so it keeps the base waits.
    fn new(clock: Clock) -> Self {
        let factor = if clock == Clock::Icount {
            ICOUNT_PATIENCE
        } else {
            1
        };
        Self {
            timeout: CHECK_TIMEOUT * factor,
            attempts: ATTEMPTS * factor as usize,
        }
    }
}

/// What the first boot writes and the second reads back.
const PERSISTED_PATH: &str = "/persist.txt";

pub(crate) fn run(boot: &DevBoot) -> Result<String, Failure> {
    if boot.clock == Clock::Kvm {
        kvm_access(Path::new(KVM_DEVICE))?;
    }
    let repository = tasks::repository_root()?;
    let project = tasks::canonical_project_root(&repository)?;
    let deep = boot
        .deep_repository
        .as_ref()
        .map_or_else(|| project.join("deepwyrm"), PathBuf::from);
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| Failure::task("system clock is before the Unix epoch"))?
        .as_nanos();
    let root = project
        .join(".tmp")
        .join("dev-boot")
        .join(format!("{unique}"));
    fs::create_dir_all(&root)
        .map_err(|error| Failure::task(format!("could not create dev-boot root: {error}")))?;
    let product = root.join("product");
    let sdk = boot.sdk.as_ref().map(PathBuf::from);
    product::build(&product, &deep, sdk.as_deref(), product::DEV_BOOT_PLATFORM)?;

    // The product's firmware vars are sealed read-only; the run gets its own copy.
    let vars = root.join("OVMF_VARS.fd");
    fs::copy(product.join("artifacts/OVMF_VARS.fd"), &vars)
        .map_err(|error| Failure::task(format!("could not copy OVMF vars: {error}")))?;
    fs::set_permissions(&vars, fs::Permissions::from_mode(0o600))
        .map_err(|error| Failure::task(format!("could not open OVMF vars copy: {error}")))?;
    let com1 = root.join("com1.log");
    let root_disk = if boot.check {
        root.join(product::ROOT_DISK_NAME)
    } else {
        project
            .join(".tmp")
            .join("dev-boot")
            .join(product::ROOT_DISK_NAME)
    };
    if !root_disk.exists() {
        create_root_disk(&product, &root_disk)?;
    }
    let args = qemu_arguments(boot.smp, boot.clock, &product, &vars, &com1, &root_disk);

    if boot.check {
        let reboot = root.join("com1-reboot.log");
        let second = qemu_arguments(boot.smp, boot.clock, &product, &vars, &reboot, &root_disk);
        check(
            &[(&args, &com1), (&second, &reboot)],
            &root,
            unique,
            sdk.is_some(),
            boot.clock,
            boot.smp,
        )
    } else {
        eprintln!(
            "dev-boot: {} (Ctrl-D at the prompt shuts down)",
            root.display()
        );
        let status = Command::new("qemu-system-x86_64")
            .args(&args)
            .status()
            .map_err(|error| Failure::task(format!("could not launch QEMU: {error}")))?;
        Ok(format!(
            "DEV_BOOT_EXITED status={status} com1={}\n",
            com1.display()
        ))
    }
}

/// Boots twice on the same disks: the first boot writes, the second reads.
fn check(
    boots: &[(&Vec<String>, &PathBuf); 2],
    root: &Path,
    unique: u128,
    sdk: bool,
    clock: Clock,
    smp: bool,
) -> Result<String, Failure> {
    let started = Instant::now();
    let patience = Patience::new(clock);
    let token = format!("dev-boot persisted {unique}");
    let mut spins = Vec::new();
    let first = boot_once(
        boots[0].0,
        boots[0].1,
        &root.join("com2.log"),
        patience,
        |shell| first_boot(shell, &token, sdk, &mut spins),
    );
    first?;
    // The kernel's step report from the first boot, which ran the probes.
    let log = fs::read(boots[0].1).map_err(|error| Failure::task(format!("COM1 log: {error}")))?;
    let steps = memory::steps_report(&log).map_err(|reason| {
        Failure::task(format!(
            "dev-boot check: {reason}; see {}",
            boots[0].1.display()
        ))
    })?;
    for line in &steps {
        eprintln!("dev-boot: kernel steps {line}");
    }
    for line in step_means(&steps, clock) {
        eprintln!("dev-boot: {line}");
    }
    // The idle-BSP probe: each run that spun on an AP had the kernel wake
    // the idle BSP for its owed work (DW2 §10.19); the gap is reported.
    eprintln!("dev-boot: {}", memory::close_spin_summary(&steps, &spins));
    let wakes = memory::owed_wakes(&steps, &spins).map_err(|reason| {
        Failure::task(format!(
            "dev-boot check: {reason}; see {}",
            boots[0].1.display()
        ))
    })?;
    eprintln!("dev-boot: {wakes}");
    // The fragmented-guest probe's object landed in many runs (DW2 §12.10).
    let runs = memory::backing_runs(&steps).map_err(|reason| {
        Failure::task(format!(
            "dev-boot check: {reason}; see {}",
            boots[0].1.display()
        ))
    })?;
    eprintln!("dev-boot: fragmented object {runs}");
    // The first allocation hold takes few runs, and one hold of the runtime
    // lock runs one finalize step (DW2 §12.11).
    let alloc = memory::backing_alloc(&steps).map_err(|reason| {
        Failure::task(format!(
            "dev-boot check: {reason}; see {}",
            boots[0].1.display()
        ))
    })?;
    eprintln!("dev-boot: first allocation hold {alloc}");
    let finalize = memory::finalize_hold(&steps).map_err(|reason| {
        Failure::task(format!(
            "dev-boot check: {reason}; see {}",
            boots[0].1.display()
        ))
    })?;
    eprintln!("dev-boot: {finalize}");
    // A first touch's time in the kernel (DW2 M8 §13.5): the faults the
    // first boot's `touch-loop` took, under the main lock and fast (DW2 M8
    // §13.16), and where their time went.
    let first_touch =
        touch::first_touch(&steps, Some(touch::TOUCH_LOOP_PAGES)).map_err(|reason| {
            Failure::task(format!(
                "dev-boot check: {reason}; see {}",
                boots[0].1.display()
            ))
        })?;
    for line in first_touch {
        eprintln!("dev-boot: {line}");
    }
    // The committed run's touches, of pages already committed, are served
    // with the paging lock shared (DW2 M8b §15.2 step 1): most of them must
    // be counted so, and their mean is printed. Why some shared serves fell
    // back must be reported, whatever its count.
    let shared = touch::shared_faults(&steps, Some(touch::SHARED_LEAST)).map_err(|reason| {
        Failure::task(format!(
            "dev-boot check: {reason}; see {}",
            boots[0].1.display()
        ))
    })?;
    if let Some(line) = shared {
        eprintln!("dev-boot: {line}");
    }
    touch::fault_declines_shared(&steps).map_err(|reason| {
        Failure::task(format!(
            "dev-boot check: {reason}; see {}",
            boots[0].1.display()
        ))
    })?;
    // The ordinary run is a forward stream, so the kernel committed ahead
    // of it (DW2 M8b §15.6 step 2): most of its pages must have been taken
    // so, and the `streams` line must be there.
    let ahead = touch::fault_ahead(&steps, Some(touch::AHEAD_LEAST)).map_err(|reason| {
        Failure::task(format!(
            "dev-boot check: {reason}; see {}",
            boots[0].1.display()
        ))
    })?;
    if let Some(line) = ahead {
        eprintln!("dev-boot: {line}");
    }
    touch::streams(&steps).map_err(|reason| {
        Failure::task(format!(
            "dev-boot check: {reason}; see {}",
            boots[0].1.display()
        ))
    })?;
    // Alone, most of `touch-loop`'s faults are served fast (DW2 M8 §13.16).
    touch::fast_share(&steps).map_err(|reason| {
        Failure::task(format!(
            "dev-boot check: {reason}; see {}",
            boots[0].1.display()
        ))
    })?;
    // The fast serve's windows and why it declined faults (DW2 M8 §13.16):
    // the `fault-windows` and `fault-declines` lines must be there (they are
    // printed with the other step-report lines); their counts are not
    // checked.
    touch::fault_windows(&steps).map_err(|reason| {
        Failure::task(format!(
            "dev-boot check: {reason}; see {}",
            boots[0].1.display()
        ))
    })?;
    touch::fault_declines(&steps).map_err(|reason| {
        Failure::task(format!(
            "dev-boot check: {reason}; see {}",
            boots[0].1.display()
        ))
    })?;
    // The creates, commits and faults the kernel held until owed work could
    // admit them (DW2 M8 §13.12 part b): the line must be there (it is
    // printed with the other step-report lines); its counts depend on
    // timing.
    touch::admission_waits(&steps).map_err(|reason| {
        Failure::task(format!(
            "dev-boot check: {reason}; see {}",
            boots[0].1.display()
        ))
    })?;
    let second = boot_once(
        boots[1].0,
        boots[1].1,
        &root.join("com2-reboot.log"),
        patience,
        |shell| second_boot(shell, &token, smp),
    );
    second?;
    // The second boot's faults and lock waits: under `--smp`, three
    // `touch-loop` jobs at once; otherwise little.
    let log = fs::read(boots[1].1).map_err(|error| Failure::task(format!("COM1 log: {error}")))?;
    let lines = touch::report_lines(&log);
    for line in touch::second_boot_lines(&lines) {
        eprintln!("dev-boot: kernel steps (second boot) {line}");
    }
    touch::admission_waits(&lines).map_err(|reason| {
        Failure::task(format!(
            "dev-boot check: second boot: {reason}; see {}",
            boots[1].1.display()
        ))
    })?;
    touch::fault_windows(&lines).map_err(|reason| {
        Failure::task(format!(
            "dev-boot check: second boot: {reason}; see {}",
            boots[1].1.display()
        ))
    })?;
    touch::fault_declines(&lines).map_err(|reason| {
        Failure::task(format!(
            "dev-boot check: second boot: {reason}; see {}",
            boots[1].1.display()
        ))
    })?;
    let first_touch =
        touch::first_touch(&lines, smp.then_some(touch::TOUCH_LOOP_PAGES)).map_err(|reason| {
            Failure::task(format!(
                "dev-boot check: second boot: {reason}; see {}",
                boots[1].1.display()
            ))
        })?;
    for line in first_touch {
        eprintln!("dev-boot: (second boot) {line}");
    }
    let shared =
        touch::shared_faults(&lines, smp.then_some(touch::SHARED_LEAST)).map_err(|reason| {
            Failure::task(format!(
                "dev-boot check: second boot: {reason}; see {}",
                boots[1].1.display()
            ))
        })?;
    if let Some(line) = shared {
        eprintln!("dev-boot: (second boot) {line}");
    }
    touch::fault_declines_shared(&lines).map_err(|reason| {
        Failure::task(format!(
            "dev-boot check: second boot: {reason}; see {}",
            boots[1].1.display()
        ))
    })?;
    let ahead = touch::fault_ahead(&lines, None).map_err(|reason| {
        Failure::task(format!(
            "dev-boot check: second boot: {reason}; see {}",
            boots[1].1.display()
        ))
    })?;
    if let Some(line) = ahead {
        eprintln!("dev-boot: (second boot) {line}");
    }
    touch::streams(&lines).map_err(|reason| {
        Failure::task(format!(
            "dev-boot check: second boot: {reason}; see {}",
            boots[1].1.display()
        ))
    })?;
    Ok(pass_line(started.elapsed().as_secs(), root, clock))
}

/// The check's result line; under `--icount` or `--kvm` it says so, so the
/// result cannot be taken for one of the emulator's.
fn pass_line(seconds: u64, root: &Path, clock: Clock) -> String {
    format!(
        "DEV_BOOT_CHECK_PASS seconds={seconds} root={}{}\n",
        root.display(),
        match clock {
            Clock::Emulated => "",
            Clock::Icount => " icount=1",
            Clock::Kvm => " kvm=1",
        }
    )
}

/// Each timed call's mean step from the kernel's step report (`lines`, as
/// [`memory::steps_report`] returns them): `call-total-us / call-steps`.
/// Under `--icount` a guest microsecond is a thousand guest instructions, so
/// the unit is `kinstr` and a line before says so. Under `--kvm` steps are
/// short real time, so the unit is `ns` (`call-total-us * 1000 /
/// call-steps`, exact only to the kernel's whole-microsecond totals) and a
/// line before says so. A call with no steps is left out; without both
/// source lines there is nothing to print.
fn step_means(lines: &[String], clock: Clock) -> Vec<String> {
    let source = |prefix: &str| lines.iter().find_map(|line| line.strip_prefix(prefix));
    let (Some(steps), Some(totals)) = (source("call-steps "), source("call-total-us ")) else {
        return Vec::new();
    };
    let field = |line: &str, call: &str| {
        line.split_whitespace()
            .find_map(|part| part.strip_prefix(call)?.strip_prefix('='))
            .and_then(|value| value.parse::<u64>().ok())
    };
    let scale: u128 = if clock == Clock::Kvm { 1000 } else { 1 };
    let means: Vec<String> = STEP_CALLS
        .iter()
        .filter_map(|call| {
            let count = field(steps, call).filter(|&count| count != 0)?;
            let total = field(totals, call)?;
            Some(format!(
                "{call}={}",
                u128::from(total) * scale / u128::from(count)
            ))
        })
        .collect();
    let mut out = Vec::with_capacity(2);
    match clock {
        Clock::Emulated => {}
        Clock::Icount => out.push(
            "icount: guest time counts instructions (1 ns each); \
             step times are thousands of guest instructions"
                .to_owned(),
        ),
        Clock::Kvm => out
            .push("kvm: step times are real time on the host CPU, under virtualization".to_owned()),
    }
    let unit = match clock {
        Clock::Emulated => "us",
        Clock::Icount => "kinstr",
        Clock::Kvm => "ns",
    };
    out.push(format!("step means {unit} {}", means.join(" ")));
    out
}

/// Everything the first boot checks, ending with the persistent write;
/// `spins` gets the idle-BSP probe's runs.
fn first_boot(
    shell: &mut Shell<'_>,
    token: &str,
    sdk: bool,
    spins: &mut Vec<memory::Spin>,
) -> Result<(), Failure> {
    shell.retry("services", "every storage service published", |output| {
        SERVICES.iter().all(|service| contains(output, service))
    })?;
    shell.retry("ls /", "ext4d's root mounted at /", |output| {
        contains(output, b"lost+found/\r\n") && contains(output, b"boot/\r\n")
    })?;
    shell.retry("ls /boot/EFI/WYRMROOT", "the ESP listed", |output| {
        ESP_LISTING.iter().all(|line| contains(output, line))
    })?;
    shell.expect("cat /boot/EFI/WYRMROOT/README.TXT", ESP_README)?;
    // Init read the free count on the root group and planned the jobs'
    // memory; in this 2 GiB guest the product's cap binds (DW2 §10.3 item 7).
    let budget = format!(
        "memory source=capped fallback=none job-budget-kib={}",
        crate::product::DEV_BOOT_PLATFORM.job_memory_bytes_max / 1024
    );
    shell.expect("memory", budget.as_bytes())?;
    // The idle-BSP probe (DW2 §10.19), while nothing else runs and nothing
    // is owed yet: the shell waits on the job, so the BSP is idle unless
    // the job is on it.
    *spins = memory::close_spin(shell)?;
    // A first touch timed with one job (DW2 M8 §13.5), still quiet; then
    // the same with each object committed first, so its touches are served
    // with the paging lock shared (DW2 M8b §15.2 step 1).
    touch::single(shell)?;
    touch::single_committed(shell)?;
    // Two hogs hold their own FP registers and FS base and preempt each
    // other (and everything else) until they are terminated; a hog that saw
    // its state change, or did not start from the initial FP state, exits on
    // its own instead (Deepwyrm D1, D2).
    let hogs = [
        spawn_job(shell, "bin/cpu-hog")?,
        spawn_job(shell, "bin/cpu-hog")?,
    ];
    shell.expect("run bin/hello", JOB_OUTPUT)?;
    // An on-demand MemoryObject end to end (Deepwyrm DW2 M6): served page
    // faults, a syscall filling a page in, a commit; then a touch with the
    // job's page quota spent, which must end the job, not the system.
    run_sdk(shell, &[("run bin/hello on-demand", b"on-demand ok")])?;
    shell.expect(
        "run bin/hello on-demand-exhaust",
        b"classification=resource-policy",
    )?;
    // DW2 M5's memory probes (§10.5 probes 12-15), with the hogs running.
    memory::probes(shell)?;
    // The same `hello` from the ESP: init reads the ELF through vfsd and
    // fat32d instead of bootfs.
    shell.expect("run /boot/EFI/WYRMROOT/HELLO.ELF", JOB_OUTPUT)?;
    if sdk {
        // Static C programs built against the SDK: musl over the POSIX
        // layer, started from the ESP like the hello above.
        run_sdk(shell, &SDK_RUNS)?;
        // Touching past the job's budget ends it on the touch (DW2 §10.1).
        shell.expect(
            "run /boot/EFI/WYRMROOT/MEMTEST.ELF over",
            b"classification=resource-policy",
        )?;
        for path in SDK_LEFTOVERS {
            shell.quiet(&format!("rm {path}"))?;
        }
    }
    for job in hogs {
        // A hog that already exited makes this `invalid-state`; `wait` then
        // shows its exit code.
        shell.run(&format!("terminate {job}"))?;
        // Terminated from outside (the process, or its whole TaskGroup,
        // depending on which the request reaches first): never a normal
        // exit, which is how a hog reports a witness failure.
        let output = shell.run(&format!("wait {job}"))?;
        let ended = [b"authorized".as_slice(), b"task-group-teardown"]
            .iter()
            .any(|class| {
                contains(
                    &output,
                    &[
                        format!("job result job={job} classification=").as_bytes(),
                        class,
                    ]
                    .concat(),
                )
            });
        if !ended {
            return Err(Failure::task(format!(
                "dev-boot check: hog job {job} was not still running: {:?}{}",
                String::from_utf8_lossy(&output),
                memory::said(&output)
            )));
        }
    }
    // The fragmented-guest probe (DW2 §12.10, part 1) needs all three of
    // the shell's job slots, so it runs once the hogs have ended.
    memory::fragmented(shell)?;
    shell.quiet(&format!("write {PERSISTED_PATH} {token}"))?;
    shell.quiet("mkdir /home")?;
    shell.expect(&format!("cat {PERSISTED_PATH}"), token.as_bytes())?;
    shell.expect("ls /", b"home/\r\n")
}

/// Runs SDK programs, each of which must print its line and end in a normal
/// exit with status 0.
fn run_sdk(shell: &mut Shell<'_>, runs: &[(&str, &[u8])]) -> Result<(), Failure> {
    for (command, expected) in runs {
        let output = shell.run(command)?;
        if !contains(&output, expected)
            || !contains(&output, b"classification=normal application=0 ")
        {
            return Err(Failure::task(format!(
                "dev-boot check: `{command}` printed {:?}{}",
                String::from_utf8_lossy(&output),
                memory::said(&output)
            )));
        }
    }
    Ok(())
}

/// The second boot reads the first boot's file back and removes it; under
/// `--smp` it then times a first touch with three jobs at once (DW2 M8
/// §13.5), and once those have ended and usage is back, with three
/// committed jobs at once (DW2 M8b §15.2 step 1).
fn second_boot(shell: &mut Shell<'_>, token: &str, smp: bool) -> Result<(), Failure> {
    let command = format!("cat {PERSISTED_PATH}");
    shell.retry(&command, "the file written before the reboot", |output| {
        contains(output, token.as_bytes())
    })?;
    shell.quiet(&format!("rm {PERSISTED_PATH}"))?;
    let listing = shell.run("ls /")?;
    if contains(&listing, b"persist.txt") || !contains(&listing, b"home/\r\n") {
        return Err(Failure::task("dev-boot check: rm or mkdir did not persist"));
    }
    if smp {
        touch::three_at_once(shell, &touch::THREE_AT_ONCE)?;
        touch::three_at_once(shell, &touch::THREE_AT_ONCE_COMMITTED)?;
    }
    Ok(())
}

fn drive(
    child: &mut Child,
    input: &mut ChildStdin,
    com1: &Path,
    com2: &Arc<Mutex<Vec<u8>>>,
    patience: Patience,
    script: impl FnOnce(&mut Shell<'_>) -> Result<(), Failure>,
) -> Result<(), Failure> {
    let deadline = Instant::now() + patience.timeout;
    let mut stdout = child
        .stdout
        .take()
        .ok_or_else(|| Failure::task("QEMU COM2 is not piped"))?;
    let sink = Arc::clone(com2);
    thread::spawn(move || {
        let mut buffer = [0_u8; 4096];
        while let Ok(read) = stdout.read(&mut buffer) {
            if read == 0 {
                break;
            }
            if let Ok(mut com2) = sink.lock() {
                com2.extend_from_slice(&buffer[..read]);
            }
        }
    });
    let mut exited = || {
        child
            .try_wait()
            .map_err(|error| Failure::task(format!("could not wait for QEMU: {error}")))
    };
    let prompt = Arc::clone(com2);
    wait_until(deadline, "the wyrmsh prompt on COM2", &mut exited, || {
        Ok(prompt
            .lock()
            .map(|com2| contains(&com2, PROMPT))
            .unwrap_or(false))
    })?;
    script(&mut Shell {
        input,
        com2,
        deadline,
        patience,
        exited: &mut exited,
    })?;
    input
        .write_all(&[END_OF_INPUT])
        .map_err(|error| Failure::task(format!("could not send Ctrl-D: {error}")))?;
    // Here QEMU is meant to exit, so its exit is what is waited for.
    wait_until(
        deadline,
        "QEMU to exit after Ctrl-D",
        || Ok(None),
        || exited().map(|status| status.is_some()),
    )?;
    let log = fs::read(com1).map_err(|error| Failure::task(format!("COM1 log: {error}")))?;
    if !contains(&log, POWER_OFF) {
        return Err(Failure::task(format!(
            "dev-boot check: QEMU exited without the kernel power-off line; see {}",
            com1.display()
        )));
    }
    if !contains(&log, SUPERVISOR_PROTECTIONS_ON) {
        return Err(Failure::task(format!(
            "dev-boot check: the kernel did not report SMEP and SMAP on; see {}",
            com1.display()
        )));
    }
    stack_marks_fit(&log).map_err(|reason| {
        Failure::task(format!("dev-boot check: {reason}; see {}", com1.display()))
    })?;
    // No kernel record was lost to a contended writer (DW2 M8 §13.4 item
    // 4). Both boots power off through the kernel's step report, the
    // second with all-zero counts, so both carry the line.
    memory::records_dropped(&log).map_err(|reason| {
        Failure::task(format!("dev-boot check: {reason}; see {}", com1.display()))
    })?;
    // Every live TaskGroup's kept usage matches a scan at power-off (DW2 M8
    // §13.12 part a). The kernel prints the line in both boots' step reports.
    memory::usage_check(&log).map_err(|reason| {
        Failure::task(format!("dev-boot check: {reason}; see {}", com1.display()))
    })?;
    Ok(())
}

/// The kernel stack classes whose measured high-water marks the kernel logs at
/// power-off (Deepwyrm `stack_watermark`, DW2 M5 §10.2 item 2).
const STACK_CLASSES: [&str; 5] = ["thread", "privilege-entry", "reaper", "ist", "ap-bootstrap"];

/// Every stack class is reported, and each deepest mark leaves a quarter of
/// its usable size spare, the margin `xtask kernel-check` holds the static
/// bound to.
fn stack_marks_fit(log: &[u8]) -> Result<(), String> {
    let text = String::from_utf8_lossy(log);
    for class in STACK_CLASSES {
        let prefix = format!("[stack] class={class} ");
        let line = text
            .lines()
            .find_map(|line| line.split_once(&prefix).map(|(_, rest)| rest))
            .ok_or_else(|| format!("the kernel logged no stack mark for {class}"))?;
        let field = |name: &str| {
            line.split_whitespace()
                .find_map(|part| part.strip_prefix(name)?.strip_prefix('='))
                .and_then(|value| value.parse::<u64>().ok())
                .ok_or_else(|| format!("the {class} stack mark has no {name}: {line}"))
        };
        let (deepest, usable) = (field("deepest")?, field("usable")?);
        if usable == 0 || deepest.saturating_mul(4) > usable.saturating_mul(3) {
            return Err(format!(
                "the {class} stack reached {deepest} of {usable} bytes, past three quarters"
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stack_marks_must_all_be_logged_and_leave_a_quarter_spare() {
        let good = "[DW0][INFO][stack] class=thread deepest=195416 usable=524288\n\
                    [DW0][INFO][stack] class=privilege-entry deepest=83720 usable=262144\n\
                    [DW0][INFO][stack] class=reaper deepest=118040 usable=262144\n\
                    [DW0][INFO][stack] class=ist deepest=0 usable=16384\n\
                    [DW0][INFO][stack] class=ap-bootstrap deepest=0 usable=65536\n";
        assert_eq!(stack_marks_fit(good.as_bytes()), Ok(()));

        let missing = good.replace("class=reaper", "class=other");
        assert!(
            stack_marks_fit(missing.as_bytes())
                .unwrap_err()
                .contains("reaper")
        );

        // Exactly three quarters passes; one byte more fails.
        let edge = good.replace("deepest=195416", "deepest=393216");
        assert_eq!(stack_marks_fit(edge.as_bytes()), Ok(()));
        let over = good.replace("deepest=195416", "deepest=393217");
        assert!(
            stack_marks_fit(over.as_bytes())
                .unwrap_err()
                .contains("thread")
        );

        let garbled = good.replace("usable=16384", "usable=x");
        assert!(
            stack_marks_fit(garbled.as_bytes())
                .unwrap_err()
                .contains("ist")
        );
        assert!(stack_marks_fit(b"").is_err());
    }

    #[test]
    fn patience_is_the_base_waits_or_four_times_them_under_icount() {
        assert_eq!(
            Patience::new(Clock::Emulated),
            Patience {
                timeout: Duration::from_secs(180),
                attempts: 20
            }
        );
        assert_eq!(
            Patience::new(Clock::Icount),
            Patience {
                timeout: Duration::from_secs(720),
                attempts: 80
            }
        );
    }

    const STEP_LINES: [&str; 3] = [
        "stops-between-steps map=1 unmap=0 protect=0 fill=0 commit=0 create=0",
        "call-steps map=4 unmap=3 protect=0 fill=243437 commit=7 create=3665 teardown=526 \
         release=255 finalize=5432",
        "call-total-us map=8306099 unmap=1182542 protect=0 fill=3907919 commit=5281586 \
         create=7050383 teardown=50469 release=592 finalize=3402532",
    ];

    fn step_lines() -> Vec<String> {
        STEP_LINES.iter().map(|line| (*line).to_owned()).collect()
    }

    #[test]
    fn step_means_divide_each_total_by_its_steps_and_leave_out_idle_calls() {
        assert_eq!(
            step_means(&step_lines(), Clock::Emulated),
            [
                "step means us map=2076524 unmap=394180 fill=16 commit=754512 create=1923 \
              teardown=95 release=2 finalize=626"
            ]
        );
    }

    #[test]
    fn under_icount_step_means_are_thousands_of_instructions() {
        assert_eq!(
            step_means(&step_lines(), Clock::Icount),
            [
                "icount: guest time counts instructions (1 ns each); \
                 step times are thousands of guest instructions",
                "step means kinstr map=2076524 unmap=394180 fill=16 commit=754512 create=1923 \
                 teardown=95 release=2 finalize=626"
            ]
        );
    }

    #[test]
    fn step_means_need_both_source_lines() {
        for missing in ["call-steps ", "call-total-us "] {
            let lines: Vec<String> = step_lines()
                .into_iter()
                .filter(|line| !line.starts_with(missing))
                .collect();
            for clock in [Clock::Emulated, Clock::Icount, Clock::Kvm] {
                assert!(step_means(&lines, clock).is_empty(), "{missing}");
            }
        }
        assert!(step_means(&[], Clock::Icount).is_empty());
        assert!(step_means(&[], Clock::Kvm).is_empty());
    }

    #[test]
    fn under_kvm_step_means_are_nanoseconds_of_real_time() {
        assert_eq!(
            step_means(&step_lines(), Clock::Kvm),
            [
                "kvm: step times are real time on the host CPU, under virtualization",
                "step means ns map=2076524750 unmap=394180666 fill=16053 commit=754512285 \
                 create=1923706 teardown=95948 release=2321 finalize=626386"
            ]
        );
        // A total far past any microsecond count still scales without
        // overflowing.
        let huge = [
            "call-steps fill=1".to_owned(),
            format!("call-total-us fill={}", u64::MAX),
        ];
        assert_eq!(
            step_means(&huge, Clock::Kvm)[1],
            format!("step means ns fill={}", u128::from(u64::MAX) * 1000)
        );
    }

    #[test]
    fn the_pass_line_marks_an_icount_or_kvm_result() {
        let root = Path::new("/t/run");
        assert_eq!(
            pass_line(42, root, Clock::Emulated),
            "DEV_BOOT_CHECK_PASS seconds=42 root=/t/run\n"
        );
        assert_eq!(
            pass_line(42, root, Clock::Icount),
            "DEV_BOOT_CHECK_PASS seconds=42 root=/t/run icount=1\n"
        );
        assert_eq!(
            pass_line(42, root, Clock::Kvm),
            "DEV_BOOT_CHECK_PASS seconds=42 root=/t/run kvm=1\n"
        );
    }

    #[test]
    fn kvm_keeps_the_base_waits() {
        assert_eq!(Patience::new(Clock::Kvm), Patience::new(Clock::Emulated));
    }
}
