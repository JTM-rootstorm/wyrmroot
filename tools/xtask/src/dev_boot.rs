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
//! README through vfsd, fat32d and blockmgr; spawns two `bin/cpu-hog` jobs,
//! which hold their own FP registers and FS base while they preempt each
//! other; runs `bin/hello` (a shell job under its TaskGroup limits) and the
//! same ELF from the ESP to their output and the next prompt (with `--sdk`,
//! also the SDK's programs); terminates the hogs and requires each to have
//! been still running; then writes a
//! file and makes a directory on the root (W7) and shuts down with Ctrl-D.
//! The second boot `cat`s the file back, removes it and shuts down. Each
//! boot must end with the kernel's power-off line on its COM1 log. That is the smoke check for development commits.
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
    process::{Child, Command, Stdio},
    sync::{Arc, Mutex},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use crate::{error::Failure, product, tasks};

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct DevBoot {
    pub(crate) check: bool,
    pub(crate) smp: bool,
    pub(crate) deep_repository: Option<String>,
    /// A built Wyrmroot SDK (`wyrmroot-sdk/out`) whose test programs go on
    /// the ESP and, under `--check`, run (root `TOOLCHAIN_PLAN.md` step 2).
    pub(crate) sdk: Option<String>,
}

/// The same memory and CPU counts as the F matrix's default and SMP profiles.
const MEMORY_MIB: u32 = 2048;
const SMP_VCPUS: u32 = 4;
const CHECK_TIMEOUT: Duration = Duration::from_secs(180);
const PROMPT: &[u8] = b"wyrmsh> ";
const END_OF_INPUT: u8 = 0x04;
const POWER_OFF: &[u8] = b"no process remains; powering off";
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
const SDK_RUNS: [(&str, &[u8]); 5] = [
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
];
/// Files the SDK programs leave on the root filesystem.
const SDK_LEFTOVERS: [&str; 1] = ["/zlib-example.gz"];
/// Services and mounts come up beside the shell, so their checks are retried.
const ATTEMPTS: usize = 20;
/// What the first boot writes and the second reads back.
const PERSISTED_PATH: &str = "/persist.txt";

pub(crate) fn run(boot: &DevBoot) -> Result<String, Failure> {
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
    product::build(&product, &deep, sdk.as_deref())?;

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
    let args = qemu_arguments(boot.smp, &product, &vars, &com1, &root_disk);

    if boot.check {
        let reboot = root.join("com1-reboot.log");
        let second = qemu_arguments(boot.smp, &product, &vars, &reboot, &root_disk);
        check(
            &[(&args, &com1), (&second, &reboot)],
            &root,
            unique,
            sdk.is_some(),
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
    product: &Path,
    vars: &Path,
    com1: &Path,
    root_disk: &Path,
) -> Vec<String> {
    let vcpus = if smp { SMP_VCPUS } else { 1 };
    let mut args: Vec<String> = vec![
        "-machine".into(),
        "q35".into(),
        "-m".into(),
        format!("{MEMORY_MIB}M"),
        "-smp".into(),
        vcpus.to_string(),
        // The default TCG model lacks what large-memory support relies on:
        // 1 GiB pages for the kernel's direct map, SMEP and SMAP
        // (Deepwyrm DW2 M2).
        "-cpu".into(),
        "qemu64,+pdpe1gb,+smep,+smap".into(),
        "-nodefaults".into(),
        "-display".into(),
        "none".into(),
        "-monitor".into(),
        "none".into(),
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
    ];
    // The second ISA serial port is COM2, where the product runs `wyrmsh`.
    args.extend(["-serial".into(), "stdio".into()]);
    args
}

/// Boots twice on the same disks: the first boot writes, the second reads.
fn check(
    boots: &[(&Vec<String>, &PathBuf); 2],
    root: &Path,
    unique: u128,
    sdk: bool,
) -> Result<String, Failure> {
    let started = Instant::now();
    let token = format!("dev-boot persisted {unique}");
    let first = boot_once(boots[0].0, boots[0].1, &root.join("com2.log"), |shell| {
        first_boot(shell, &token, sdk)
    });
    first?;
    let second = boot_once(
        boots[1].0,
        boots[1].1,
        &root.join("com2-reboot.log"),
        |shell| second_boot(shell, &token),
    );
    second?;
    Ok(format!(
        "DEV_BOOT_CHECK_PASS seconds={} root={}\n",
        started.elapsed().as_secs(),
        root.display()
    ))
}

/// Everything the first boot checks, ending with the persistent write.
fn first_boot(shell: &mut Shell<'_>, token: &str, sdk: bool) -> Result<(), Failure> {
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
    // Two hogs hold their own FP registers and FS base and preempt each
    // other (and everything else) until they are terminated; a hog that saw
    // its state change, or did not start from the initial FP state, exits on
    // its own instead (Deepwyrm D1, D2).
    let hogs = [
        spawn_job(shell, "bin/cpu-hog")?,
        spawn_job(shell, "bin/cpu-hog")?,
    ];
    shell.expect("run bin/hello", JOB_OUTPUT)?;
    // The same `hello` from the ESP: init reads the ELF through vfsd and
    // fat32d instead of bootfs.
    shell.expect("run /boot/EFI/WYRMROOT/HELLO.ELF", JOB_OUTPUT)?;
    if sdk {
        // Static C programs built against the SDK: musl over the POSIX
        // layer, started from the ESP like the hello above.
        run_sdk(shell, &SDK_RUNS)?;
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
    input: &'a mut std::process::ChildStdin,
    com2: &'a Arc<Mutex<Vec<u8>>>,
    deadline: Instant,
}

impl Shell<'_> {
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
        for _ in 0..ATTEMPTS {
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
    script: impl FnOnce(&mut Shell<'_>) -> Result<(), Failure>,
) -> Result<(), Failure> {
    let mut child = Command::new("qemu-system-x86_64")
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|error| Failure::task(format!("could not launch QEMU: {error}")))?;
    let com2 = Arc::new(Mutex::new(Vec::new()));
    let result = drive(&mut child, com1, &com2, script);
    if result.is_err() {
        let _ = child.kill();
        let _ = child.wait();
    }
    // Keep the shell transcript beside COM1 so a failed check can be read.
    if let Ok(com2) = com2.lock() {
        let _ = fs::write(transcript, &*com2);
    }
    result
}

fn drive(
    child: &mut Child,
    com1: &Path,
    com2: &Arc<Mutex<Vec<u8>>>,
    script: impl FnOnce(&mut Shell<'_>) -> Result<(), Failure>,
) -> Result<(), Failure> {
    let deadline = Instant::now() + CHECK_TIMEOUT;
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
    let prompt = Arc::clone(com2);
    wait_until(deadline, "the wyrmsh prompt on COM2", || {
        Ok(prompt
            .lock()
            .map(|com2| contains(&com2, PROMPT))
            .unwrap_or(false))
    })?;
    let input = child
        .stdin
        .as_mut()
        .ok_or_else(|| Failure::task("QEMU COM2 input is not piped"))?;
    script(&mut Shell {
        input,
        com2,
        deadline,
    })?;
    let input = child
        .stdin
        .as_mut()
        .ok_or_else(|| Failure::task("QEMU COM2 input is not piped"))?;
    input
        .write_all(&[END_OF_INPUT])
        .map_err(|error| Failure::task(format!("could not send Ctrl-D: {error}")))?;
    wait_until(deadline, "QEMU to exit after Ctrl-D", || {
        child
            .try_wait()
            .map(|status| status.is_some())
            .map_err(|error| Failure::task(format!("could not wait for QEMU: {error}")))
    })?;
    let log = fs::read(com1).map_err(|error| Failure::task(format!("COM1 log: {error}")))?;
    if !contains(&log, POWER_OFF) {
        return Err(Failure::task(format!(
            "dev-boot check: QEMU exited without the kernel power-off line; see {}",
            com1.display()
        )));
    }
    Ok(())
}

fn wait_until(
    deadline: Instant,
    what: &str,
    mut done: impl FnMut() -> Result<bool, Failure>,
) -> Result<(), Failure> {
    while !done()? {
        if Instant::now() >= deadline {
            return Err(Failure::task(format!(
                "dev-boot check timed out waiting for {what}"
            )));
        }
        thread::sleep(Duration::from_millis(100));
    }
    Ok(())
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
    fn smp_uses_the_f_matrix_cpu_count() {
        let args = qemu_arguments(
            true,
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
