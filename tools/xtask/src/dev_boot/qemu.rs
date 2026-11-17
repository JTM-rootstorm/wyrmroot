//! Starting and observing the machine for `xtask dev-boot`: QEMU's
//! arguments, the root disk, KVM's device, one boot of a check, and what a
//! failed boot leaves behind (QEMU's stderr and the CPUs' state).

use std::{
    fs,
    io::{Read, Write},
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Command, ExitStatus, Stdio},
    sync::{Arc, Mutex},
    time::Duration,
};

use super::{
    Clock, Patience, drive,
    shell::{Shell, strip_escapes},
};
use crate::{error::Failure, product};

/// The same memory and CPU counts as the F matrix's default and SMP profiles.
const MEMORY_MIB: u32 = 2048;

const SMP_VCPUS: u32 = 4;

/// Fails unless KVM's device at `device` opens read-write, as QEMU needs.
pub(super) fn kvm_access(device: &Path) -> Result<(), Failure> {
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
pub(super) fn create_root_disk(product: &Path, path: &Path) -> Result<(), Failure> {
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

pub(super) fn qemu_arguments(
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

/// One boot: waits for the prompt, runs `script`, shuts down with Ctrl-D and
/// requires the power-off line on `com1`. The shell transcript is kept at
/// `transcript`.
pub(super) fn boot_once(
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

/// `status 0`, or `signal 9` for a QEMU that was killed.
pub(super) fn exit_description(status: ExitStatus) -> String {
    use std::os::unix::process::ExitStatusExt;
    match (status.code(), status.signal()) {
        (Some(code), _) => format!("status {code}"),
        (None, Some(signal)) => format!("signal {signal}"),
        (None, None) => status.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn exit_status(code: i32) -> ExitStatus {
        use std::os::unix::process::ExitStatusExt;
        ExitStatus::from_raw(code << 8)
    }

    #[test]
    fn a_killed_qemu_is_reported_by_its_signal() {
        use std::os::unix::process::ExitStatusExt;
        assert_eq!(exit_description(ExitStatus::from_raw(9)), "signal 9");
        assert_eq!(exit_description(exit_status(1)), "status 1");
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
