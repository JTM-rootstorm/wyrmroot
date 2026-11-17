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
//! DW2 §10.19, `memory.rs`); spawns two `bin/cpu-hog` jobs,
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
//! The second boot `cat`s the file back, removes it and shuts down. Each
//! boot must end with the kernel's power-off line on its COM1 log. That is the smoke check for development commits.
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
    process::{Child, ChildStdin, Command, ExitStatus, Stdio},
    sync::{Arc, Mutex},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use crate::{error::Failure, product, tasks};

mod memory;

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

/// The same memory and CPU counts as the F matrix's default and SMP profiles.
const MEMORY_MIB: u32 = 2048;
const SMP_VCPUS: u32 = 4;
const CHECK_TIMEOUT: Duration = Duration::from_secs(180);
const PROMPT: &[u8] = b"wyrmsh> ";
const END_OF_INPUT: u8 = 0x04;
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

/// Fails unless KVM's device at `device` opens read-write, as QEMU needs.
fn kvm_access(device: &Path) -> Result<(), Failure> {
    fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(device)
        .map(drop)
        .map_err(|error| {
            Failure::task(format!(
                "dev-boot --kvm: cannot open {} read-write ({error}); if you were \
                 just added to group kvm, run the command through \
                 `sg kvm -c '...'` or start a new login session",
                device.display()
            ))
        })
}

/// A writable copy of the product's empty root disk at `path`.
fn create_root_disk(product: &Path, path: &Path) -> Result<(), Failure> {
    let failed = |what: String| {
        Failure::task(format!(
            "could not make the root disk {}: {what}",
            path.display()
        ))
    };
    let mut source = fs::File::open(product.join("artifacts").join(product::ROOT_DISK_NAME))
        .map_err(|error| failed(error.to_string()))?;
    let mut copy = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| failed(error.to_string()))?;
    std::io::copy(&mut source, &mut copy).map_err(|error| failed(error.to_string()))?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .map_err(|error| failed(error.to_string()))
}

fn qemu_arguments(
    smp: bool,
    clock: Clock,
    product: &Path,
    vars: &Path,
    com1: &Path,
    root_disk: &Path,
) -> Vec<String> {
    let vcpus = if smp { SMP_VCPUS } else { 1 };
    let kvm = clock == Clock::Kvm;
    let mut args: Vec<String> = Vec::new();
    if kvm {
        args.extend(["-accel".into(), "kvm".into()]);
    }
    args.extend([
        "-machine".into(),
        // Under KVM the emulated VT-d's interrupt remapping needs the
        // split irqchip: QEMU refuses `intremap=on` with the in-kernel one.
        if kvm {
            "q35,kernel-irqchip=split".into()
        } else {
            "q35".into()
        },
        "-m".into(),
        format!("{MEMORY_MIB}M"),
        "-smp".into(),
        vcpus.to_string(),
        // The default TCG model lacks what large-memory support relies on:
        // 1 GiB pages for the kernel's direct map, SMEP and SMAP
        // (Deepwyrm DW2 M2). Under KVM the guest has the host's CPU,
        // with its invariant TSC shown (QEMU shows it only to a guest
        // marked not migratable), so the kernel can time steps by the TSC.
        "-cpu".into(),
        if kvm {
            "host,migratable=no,+invtsc".into()
        } else {
            "qemu64,+pdpe1gb,+smep,+smap".into()
        },
        "-nodefaults".into(),
        "-display".into(),
        "none".into(),
        // A monitor socket beside COM1, so a failed check can record where
        // every CPU was before QEMU is killed.
        "-monitor".into(),
        format!("unix:{},server,nowait", monitor_socket(com1).display()),
        "-no-reboot".into(),
        "-drive".into(),
        format!(
            "if=pflash,format=raw,readonly=on,file={}",
            product.join("artifacts/OVMF_CODE.fd").display()
        ),
        "-drive".into(),
        format!("if=pflash,format=raw,file={}", vars.display()),
        // VT-d, so the kernel can confine device DMA (root `STORAGE_PLAN.md`).
        // Interrupt remapping too: without it the kernel admits no bus
        // mastering, since a device could forge interrupts by DMA.
        "-device".into(),
        "intel-iommu,intremap=on".into(),
        // A modern-only virtio disk whose DMA goes through the IOMMU.
        "-drive".into(),
        format!(
            "if=none,id=esp,format=raw,readonly=on,file={}",
            product.join("artifacts").join(product::ESP_NAME).display()
        ),
        "-device".into(),
        format!(
            "virtio-blk-pci,drive=esp,addr={:#x},disable-legacy=on,iommu_platform=on",
            product::BOOT_DISK_PCI_ADDRESS >> 3
        ),
        // The writable data disk with the persistent root (W7).
        "-drive".into(),
        format!("if=none,id=root,format=raw,file={}", root_disk.display()),
        "-device".into(),
        format!(
            "virtio-blk-pci,drive=root,addr={:#x},disable-legacy=on,iommu_platform=on",
            product::DATA_DISK_PCI_ADDRESS >> 3
        ),
        "-serial".into(),
        format!("file:{}", com1.display()),
    ]);
    // The second ISA serial port is COM2, where the product runs `wyrmsh`.
    args.extend(["-serial".into(), "stdio".into()]);
    if clock == Clock::Icount {
        // One guest instruction is one nanosecond of guest time; `sleep`
        // stays on, so an idle guest's clock follows real time.
        args.extend(["-icount".into(), "shift=0".into()]);
    }
    args
}

/// Boots twice on the same disks: the first boot writes, the second reads.
fn check(
    boots: &[(&Vec<String>, &PathBuf); 2],
    root: &Path,
    unique: u128,
    sdk: bool,
    clock: Clock,
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
    let second = boot_once(
        boots[1].0,
        boots[1].1,
        &root.join("com2-reboot.log"),
        patience,
        |shell| second_boot(shell, &token),
    );
    second?;
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
                "dev-boot check: hog job {job} was not still running: {:?}",
                String::from_utf8_lossy(&output)
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
                "dev-boot check: `{command}` printed {:?}",
                String::from_utf8_lossy(&output)
            )));
        }
    }
    Ok(())
}

/// The second boot reads the first boot's file back and removes it.
fn second_boot(shell: &mut Shell<'_>, token: &str) -> Result<(), Failure> {
    let command = format!("cat {PERSISTED_PATH}");
    shell.retry(&command, "the file written before the reboot", |output| {
        contains(output, token.as_bytes())
    })?;
    shell.quiet(&format!("rm {PERSISTED_PATH}"))?;
    let listing = shell.run("ls /")?;
    if contains(&listing, b"persist.txt") || !contains(&listing, b"home/\r\n") {
        return Err(Failure::task("dev-boot check: rm or mkdir did not persist"));
    }
    Ok(())
}

/// The shell console of one boot.
struct Shell<'a> {
    input: &'a mut ChildStdin,
    com2: &'a Arc<Mutex<Vec<u8>>>,
    deadline: Instant,
    patience: Patience,
    /// Whether QEMU has exited, and how; every wait checks it.
    exited: &'a mut dyn FnMut() -> Result<Option<ExitStatus>, Failure>,
}

impl Shell<'_> {
    /// How many times a loop that polls the guest tries before it fails.
    const fn attempts(&self) -> usize {
        self.patience.attempts
    }

    fn length(&self) -> usize {
        self.com2.lock().map(|com2| com2.len()).unwrap_or(0)
    }

    /// Sends `command` and returns everything up to the next prompt.
    fn run(&mut self, command: &str) -> Result<Vec<u8>, Failure> {
        let before = self.length();
        self.input
            .write_all(format!("{command}\r").as_bytes())
            .map_err(|error| Failure::task(format!("could not send `{command}`: {error}")))?;
        let echo = command.as_bytes().to_vec();
        let com2 = Arc::clone(self.com2);
        // The command's output and the next prompt may arrive in one read.
        wait_until(
            self.deadline,
            &format!("the prompt after `{command}`"),
            &mut *self.exited,
            || {
                Ok(com2
                    .lock()
                    .map(|com2| {
                        com2.get(before..)
                            .is_some_and(|tail| contains(tail, &echo) && ends_with_prompt(tail))
                    })
                    .unwrap_or(false))
            },
        )?;
        Ok(self
            .com2
            .lock()
            .map(|com2| com2.get(before..).unwrap_or_default().to_vec())
            .unwrap_or_default())
    }

    /// Runs `command`, which must print `needle`.
    fn expect(&mut self, command: &str, needle: &[u8]) -> Result<(), Failure> {
        let output = self.run(command)?;
        if contains(&output, needle) {
            Ok(())
        } else {
            Err(Failure::task(format!(
                "dev-boot check: `{command}` printed {:?}",
                String::from_utf8_lossy(&output)
            )))
        }
    }

    /// Runs `command`, which must print nothing but its echo and the prompt.
    fn quiet(&mut self, command: &str) -> Result<(), Failure> {
        let output = self.run(command)?;
        let echo = command.as_bytes();
        let rest = output
            .windows(echo.len())
            .position(|window| window == echo)
            .map_or(&output[..], |at| &output[at + echo.len()..]);
        let text = String::from_utf8_lossy(&strip_escapes(rest)).into_owned();
        if text.split_whitespace().collect::<Vec<_>>() != ["wyrmsh>"] {
            return Err(Failure::task(format!(
                "dev-boot check: `{command}` printed {text:?}"
            )));
        }
        Ok(())
    }

    /// Runs `command` until `done` holds for its output.
    fn retry(
        &mut self,
        command: &str,
        what: &str,
        done: impl Fn(&[u8]) -> bool,
    ) -> Result<(), Failure> {
        for _ in 0..self.attempts() {
            if done(&self.run(command)?) {
                return Ok(());
            }
            if Instant::now() >= self.deadline {
                break;
            }
            thread::sleep(Duration::from_millis(500));
        }
        Err(Failure::task(format!(
            "dev-boot check: `{command}` never showed {what}"
        )))
    }
}

/// One boot: waits for the prompt, runs `script`, shuts down with Ctrl-D and
/// requires the power-off line on `com1`. The shell transcript is kept at
/// `transcript`.
fn boot_once(
    args: &[String],
    com1: &Path,
    transcript: &Path,
    patience: Patience,
    script: impl FnOnce(&mut Shell<'_>) -> Result<(), Failure>,
) -> Result<(), Failure> {
    // QEMU's own complaints, kept beside COM1 for a failed check.
    let stderr = com1.with_extension("qemu-stderr.log");
    let mut child = Command::new("qemu-system-x86_64")
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(fs::File::create(&stderr).map_or_else(|_| Stdio::null(), Stdio::from))
        .spawn()
        .map_err(|error| Failure::task(format!("could not launch QEMU: {error}")))?;
    let com2 = Arc::new(Mutex::new(Vec::new()));
    // COM2's input is held apart from the child, so the waits can ask the
    // child whether QEMU has exited while the shell writes to it; it stays
    // open until QEMU has been stopped.
    let mut input = child.stdin.take();
    let mut result = match &mut input {
        Some(input) => drive(&mut child, input, com1, &com2, patience, script),
        None => Err(Failure::task("QEMU COM2 input is not piped")),
    };
    if let Err(failure) = &mut result {
        let socket = monitor_socket(com1);
        if !record_cpu_state(&socket, &com1.with_extension("cpu-state.txt")) {
            eprintln!(
                "dev-boot: CPU state not recorded: QEMU's monitor at {} was gone",
                socket.display()
            );
        }
        let _ = child.kill();
        let _ = child.wait();
        if let Some(tail) = fs::read(&stderr).ok().as_deref().and_then(stderr_tail) {
            failure.message = format!(
                "{}\nQEMU stderr ({}):\n{tail}",
                failure.message,
                stderr.display()
            );
        }
    }
    // Keep the shell transcript beside COM1 so a failed check can be read.
    if let Ok(com2) = com2.lock() {
        let _ = fs::write(transcript, &*com2);
    }
    result
}

/// The QEMU monitor socket of the boot whose COM1 log is `com1`.
fn monitor_socket(com1: &Path) -> PathBuf {
    com1.with_extension("monitor")
}

/// The end of QEMU's stderr for a failure message: at most the last
/// [`STDERR_TAIL_LINES`] lines of its last [`STDERR_TAIL_BYTES`] bytes, or
/// `None` when it said nothing.
fn stderr_tail(bytes: &[u8]) -> Option<String> {
    let mut start = bytes.len().saturating_sub(STDERR_TAIL_BYTES);
    // Start on a character, not inside one.
    while bytes.get(start).is_some_and(|byte| byte & 0xc0 == 0x80) {
        start += 1;
    }
    let text = String::from_utf8_lossy(&bytes[start..]);
    let text = text.trim_end();
    if text.trim().is_empty() {
        return None;
    }
    let lines: Vec<&str> = text.lines().collect();
    let keep = lines.len().saturating_sub(STDERR_TAIL_LINES);
    Some(lines[keep..].join("\n"))
}

/// How much of QEMU's stderr a failure message shows.
const STDERR_TAIL_LINES: usize = 10;
const STDERR_TAIL_BYTES: usize = 2000;

/// Stops the guest and writes, from QEMU's monitor at `socket`, every
/// CPU's registers and the top of its stack, the interrupt controllers, and
/// the shell UART's (COM2) registers to `output`. Best effort: a failed
/// check is reported either way. Returns whether the monitor was reached.
fn record_cpu_state(socket: &Path, output: &Path) -> bool {
    let Ok(mut monitor) = std::os::unix::net::UnixStream::connect(socket) else {
        return false;
    };
    let _ = monitor.set_read_timeout(Some(Duration::from_millis(500)));
    let mut state = Vec::new();
    let read_all = |monitor: &mut std::os::unix::net::UnixStream, state: &mut Vec<u8>| {
        let mut buffer = [0_u8; 65536];
        while let Ok(read) = monitor.read(&mut buffer) {
            if read == 0 {
                break;
            }
            state.extend_from_slice(&buffer[..read]);
        }
    };
    let send =
        |monitor: &mut std::os::unix::net::UnixStream, state: &mut Vec<u8>, command: &str| {
            let sent = monitor.write_all(format!("{command}\n").as_bytes()).is_ok();
            read_all(monitor, state);
            sent
        };
    read_all(&mut monitor, &mut state);
    for command in [
        "stop",
        "info status",
        "info cpus",
        "info registers -a",
        "info pic",
        "info lapic",
        "info irq",
        // COM2 at 0x2f8: IER, LSR, MSR, then IIR last, since reading IIR
        // clears a pending transmit interrupt.
        "i /b 0x2f9",
        "i /b 0x2fd",
        "i /b 0x2fe",
        "i /b 0x2fa",
    ] {
        if !send(&mut monitor, &mut state, command) {
            break;
        }
    }
    let registers = String::from_utf8_lossy(&state).into_owned();
    for (cpu, stack) in registers
        .split("RSP=")
        .skip(1)
        .filter_map(|tail| tail.get(..16))
        .enumerate()
    {
        let _ = send(&mut monitor, &mut state, &format!("cpu {cpu}"));
        let _ = send(&mut monitor, &mut state, &format!("x /128gx 0x{stack}"));
    }
    let _ = fs::write(output, strip_escapes(&state));
    true
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

/// Polls `done` until it holds. Fails at `deadline`, or as soon as
/// `exited` reports that QEMU has exited, since then nothing more will come.
fn wait_until(
    deadline: Instant,
    what: &str,
    mut exited: impl FnMut() -> Result<Option<ExitStatus>, Failure>,
    mut done: impl FnMut() -> Result<bool, Failure>,
) -> Result<(), Failure> {
    while !done()? {
        if let Some(status) = exited()? {
            // Output QEMU wrote just before exiting may have landed since.
            if done()? {
                break;
            }
            return Err(Failure::task(format!(
                "dev-boot check: QEMU exited ({}) while waiting for {what}",
                exit_description(status)
            )));
        }
        if Instant::now() >= deadline {
            return Err(Failure::task(format!(
                "dev-boot check timed out waiting for {what}"
            )));
        }
        thread::sleep(Duration::from_millis(100));
    }
    Ok(())
}

/// `status 0`, or `signal 9` for a QEMU that was killed.
fn exit_description(status: ExitStatus) -> String {
    use std::os::unix::process::ExitStatusExt;
    match (status.code(), status.signal()) {
        (Some(code), _) => format!("status {code}"),
        (None, Some(signal)) => format!("signal {signal}"),
        (None, None) => status.to_string(),
    }
}

/// `bytes` without ANSI control sequences (`ESC [` ... final byte).
fn strip_escapes(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == 0x1b && bytes.get(index + 1) == Some(&b'[') {
            index += 2;
            while index < bytes.len() && !(0x40..=0x7e).contains(&bytes[index]) {
                index += 1;
            }
            index += 1;
        } else {
            out.push(bytes[index]);
            index += 1;
        }
    }
    out
}

/// Whether `output` ends at a fresh prompt.
fn ends_with_prompt(output: &[u8]) -> bool {
    output.ends_with(PROMPT)
}

/// Spawns a background job and returns the id the shell printed.
fn spawn_job(shell: &mut Shell<'_>, path: &str) -> Result<u64, Failure> {
    let output = shell.run(&format!("spawn {path}"))?;
    spawned_job_id(&output).ok_or_else(|| {
        Failure::task(format!(
            "dev-boot check: `spawn {path}` printed {:?}",
            String::from_utf8_lossy(&output)
        ))
    })
}

fn spawned_job_id(output: &[u8]) -> Option<u64> {
    const PREFIX: &[u8] = b"spawn job=";
    let at = output
        .windows(PREFIX.len())
        .position(|window| window == PREFIX)?;
    let digits: Vec<u8> = output[at + PREFIX.len()..]
        .iter()
        .copied()
        .take_while(u8::is_ascii_digit)
        .collect();
    std::str::from_utf8(&digits).ok()?.parse().ok()
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn exit_status(code: i32) -> ExitStatus {
        use std::os::unix::process::ExitStatusExt;
        ExitStatus::from_raw(code << 8)
    }

    #[test]
    fn a_wait_fails_at_once_when_qemu_has_exited() {
        let started = Instant::now();
        let failure = wait_until(
            started + Duration::from_secs(60),
            "the wyrmsh prompt on COM2",
            || Ok(Some(exit_status(0))),
            || Ok(false),
        )
        .unwrap_err();
        assert_eq!(
            failure.message,
            "dev-boot check: QEMU exited (status 0) while waiting for the wyrmsh prompt on COM2"
        );
        assert!(started.elapsed() < Duration::from_secs(5));
    }

    #[test]
    fn a_killed_qemu_is_reported_by_its_signal() {
        use std::os::unix::process::ExitStatusExt;
        assert_eq!(exit_description(ExitStatus::from_raw(9)), "signal 9");
        assert_eq!(exit_description(exit_status(1)), "status 1");
    }

    #[test]
    fn a_wait_on_a_running_qemu_still_times_out() {
        let failure = wait_until(
            Instant::now() + Duration::from_millis(250),
            "the prompt after `ls /`",
            || Ok(None),
            || Ok(false),
        )
        .unwrap_err();
        assert_eq!(
            failure.message,
            "dev-boot check timed out waiting for the prompt after `ls /`"
        );
    }

    #[test]
    fn a_wait_that_completes_succeeds_whatever_qemu_does_after() {
        // QEMU exits once the third poll has seen the prompt.
        let polls = std::cell::Cell::new(0);
        wait_until(
            Instant::now() + Duration::from_secs(60),
            "the wyrmsh prompt on COM2",
            || Ok((polls.get() >= 3).then(|| exit_status(0))),
            || {
                polls.set(polls.get() + 1);
                Ok(polls.get() >= 3)
            },
        )
        .unwrap();
        assert_eq!(polls.get(), 3);
        // The output QEMU wrote just before exiting still counts.
        let seen = std::cell::Cell::new(false);
        wait_until(
            Instant::now() + Duration::from_secs(60),
            "QEMU's last line",
            || {
                seen.set(true);
                Ok(Some(exit_status(0)))
            },
            || Ok(seen.get()),
        )
        .unwrap();
    }

    #[test]
    fn the_stderr_tail_is_empty_short_or_the_last_ten_lines() {
        assert_eq!(stderr_tail(b""), None);
        assert_eq!(stderr_tail(b"\n  \n"), None);
        assert_eq!(
            stderr_tail(b"qemu: terminating on signal 15\n").as_deref(),
            Some("qemu: terminating on signal 15")
        );
        let long: String = (1..=25).map(|line| format!("line {line}\n")).collect();
        let expected: Vec<String> = (16..=25).map(|line| format!("line {line}")).collect();
        assert_eq!(stderr_tail(long.as_bytes()), Some(expected.join("\n")));
        let wide = format!("{}\nlast\n", "x".repeat(5000));
        let tail = stderr_tail(wide.as_bytes()).unwrap();
        assert!(tail.len() <= STDERR_TAIL_BYTES);
        assert!(tail.ends_with("\nlast"));
        let multibyte = "é".repeat(1500);
        let tail = stderr_tail(multibyte.as_bytes()).unwrap();
        assert!(tail.len() <= STDERR_TAIL_BYTES && tail.chars().all(|c| c == 'é'));
    }

    #[test]
    fn spawned_job_ids_are_read_from_the_shell_echo() {
        assert_eq!(
            spawned_job_id(b"spawn bin/cpu-hog\r\nspawn job=12\r\nwyrmsh> "),
            Some(12)
        );
        assert_eq!(spawned_job_id(b"spawn job=\r\n"), None);
        assert_eq!(spawned_job_id(b"spawn: capacity\r\n"), None);
    }

    #[test]
    fn the_shell_console_is_the_second_serial_port_after_the_kernel_log() {
        let args = qemu_arguments(
            false,
            Clock::Emulated,
            Path::new("/p"),
            Path::new("/v.fd"),
            Path::new("/c1.log"),
            Path::new("/r.img"),
        );
        let serials: Vec<&str> = args
            .windows(2)
            .filter(|pair| pair[0] == "-serial")
            .map(|pair| pair[1].as_str())
            .collect();
        assert_eq!(serials, ["file:/c1.log", "stdio"]);
        assert!(args.iter().any(|arg| arg.ends_with("/p/artifacts/esp.img")));
        assert!(!args.iter().any(|arg| arg.contains("isa-debug-exit")));
    }

    #[test]
    fn the_esp_is_a_modern_virtio_disk_behind_the_iommu() {
        let args = qemu_arguments(
            false,
            Clock::Emulated,
            Path::new("/p"),
            Path::new("/v"),
            Path::new("/c"),
            Path::new("/r.img"),
        );
        let devices: Vec<&str> = args
            .windows(2)
            .filter(|pair| pair[0] == "-device")
            .map(|pair| pair[1].as_str())
            .collect();
        assert_eq!(
            devices,
            [
                "intel-iommu,intremap=on",
                "virtio-blk-pci,drive=esp,addr=0x1,disable-legacy=on,iommu_platform=on",
                "virtio-blk-pci,drive=root,addr=0x2,disable-legacy=on,iommu_platform=on"
            ]
        );
        assert!(!args.iter().any(|arg| arg.starts_with("if=virtio")));
        // The ESP is read-only; the root disk is not.
        assert!(
            args.iter()
                .any(|arg| arg.starts_with("if=none,id=esp,format=raw,readonly=on,"))
        );
        assert!(
            args.iter()
                .any(|arg| arg == "if=none,id=root,format=raw,file=/r.img")
        );
    }

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
    fn escapes_are_stripped_from_the_transcript() {
        assert_eq!(
            strip_escapes(b"\r\n\x1b[2Kwyrmsh> "),
            b"\r\nwyrmsh> ".to_vec()
        );
        assert_eq!(strip_escapes(b"a\x1b[1;31mb"), b"ab".to_vec());
    }

    #[test]
    fn the_guest_cpu_has_gigabyte_pages_smep_and_smap() {
        let args = qemu_arguments(
            false,
            Clock::Emulated,
            Path::new("product"),
            Path::new("vars"),
            Path::new("com1"),
            Path::new("root"),
        );
        let cpu = args
            .windows(2)
            .find(|pair| pair[0] == "-cpu")
            .map(|pair| pair[1].clone())
            .expect("a CPU model is chosen");
        for feature in ["+pdpe1gb", "+smep", "+smap"] {
            assert!(
                cpu.split(',').any(|part| part == feature),
                "{feature} in {cpu}"
            );
        }
    }

    #[test]
    fn icount_adds_shift_zero_and_changes_nothing_else() {
        for smp in [false, true] {
            let arguments = |clock| {
                qemu_arguments(
                    smp,
                    clock,
                    Path::new("/p"),
                    Path::new("/v"),
                    Path::new("/c"),
                    Path::new("/r.img"),
                )
            };
            let (plain, counted) = (arguments(Clock::Emulated), arguments(Clock::Icount));
            assert!(!plain.iter().any(|arg| arg == "-icount"));
            let at = counted
                .iter()
                .position(|arg| arg == "-icount")
                .expect("-icount is passed");
            assert_eq!(counted.get(at + 1).map(String::as_str), Some("shift=0"));
            assert_eq!(counted.iter().filter(|arg| *arg == "-icount").count(), 1);
            let mut rest = counted.clone();
            rest.drain(at..at + 2);
            assert_eq!(rest, plain);
        }
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
    fn kvm_adds_the_accelerator_host_cpu_and_split_irqchip_and_changes_nothing_else() {
        for smp in [false, true] {
            let arguments = |clock| {
                qemu_arguments(
                    smp,
                    clock,
                    Path::new("/p"),
                    Path::new("/v"),
                    Path::new("/c"),
                    Path::new("/r.img"),
                )
            };
            let (plain, kvm) = (arguments(Clock::Emulated), arguments(Clock::Kvm));
            // Without KVM the list is exactly today's.
            let vcpus = if smp { "4" } else { "1" };
            let expected: Vec<String> = [
                "-machine",
                "q35",
                "-m",
                "2048M",
                "-smp",
                vcpus,
                "-cpu",
                "qemu64,+pdpe1gb,+smep,+smap",
                "-nodefaults",
                "-display",
                "none",
                "-monitor",
                "unix:/c.monitor,server,nowait",
                "-no-reboot",
                "-drive",
                "if=pflash,format=raw,readonly=on,file=/p/artifacts/OVMF_CODE.fd",
                "-drive",
                "if=pflash,format=raw,file=/v",
                "-device",
                "intel-iommu,intremap=on",
                "-drive",
                "if=none,id=esp,format=raw,readonly=on,file=/p/artifacts/esp.img",
                "-device",
                "virtio-blk-pci,drive=esp,addr=0x1,disable-legacy=on,iommu_platform=on",
                "-drive",
                "if=none,id=root,format=raw,file=/r.img",
                "-device",
                "virtio-blk-pci,drive=root,addr=0x2,disable-legacy=on,iommu_platform=on",
                "-serial",
                "file:/c",
                "-serial",
                "stdio",
            ]
            .iter()
            .map(|arg| (*arg).to_owned())
            .collect();
            assert_eq!(plain, expected);
            // Under KVM: the accelerator first, the split irqchip, the host
            // CPU in place of the TCG model, and nothing else changed.
            let mut changed = expected.clone();
            changed[1] = "q35,kernel-irqchip=split".into();
            changed[7] = "host,migratable=no,+invtsc".into();
            changed.splice(0..0, ["-accel".to_owned(), "kvm".to_owned()]);
            assert_eq!(kvm, changed);
            assert!(!kvm.iter().any(|arg| arg.starts_with("qemu64")));
            assert!(!kvm.iter().any(|arg| arg == "-icount"));
        }
    }

    #[test]
    fn kvm_is_refused_unless_its_device_opens_read_write() {
        let failure = kvm_access(Path::new("/nonexistent/kvm")).unwrap_err();
        assert!(
            failure.message.contains("/nonexistent/kvm"),
            "{}",
            failure.message
        );
        assert!(
            failure.message.contains("read-write"),
            "{}",
            failure.message
        );
        assert!(failure.message.contains("sg kvm -c"), "{}", failure.message);
        assert!(
            failure.message.contains("new login session"),
            "{}",
            failure.message
        );
        // A device that opens read-write is accepted.
        assert!(kvm_access(Path::new("/dev/null")).is_ok());
    }

    #[test]
    fn kvm_keeps_the_base_waits() {
        assert_eq!(Patience::new(Clock::Kvm), Patience::new(Clock::Emulated));
    }

    #[test]
    fn smp_uses_the_f_matrix_cpu_count() {
        let args = qemu_arguments(
            true,
            Clock::Emulated,
            Path::new("/p"),
            Path::new("/v"),
            Path::new("/c"),
            Path::new("/r.img"),
        );
        let smp = args
            .windows(2)
            .find(|pair| pair[0] == "-smp")
            .map(|pair| pair[1].clone());
        assert_eq!(smp.as_deref(), Some("4"));
    }
}
