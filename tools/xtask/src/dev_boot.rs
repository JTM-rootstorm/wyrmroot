//! `xtask dev-boot`: the development-tier boot (root `CLAUDE.md` §9).
//!
//! Builds the current normal product from the committed Wyrmroot and Deepwyrm
//! HEADs with the same producer as `wyr1f prepare --scenario normal`, then boots
//! it in local QEMU on the canonical q35/OVMF arguments. COM1 (kernel log) goes
//! to a file; COM2 (the `wyrmsh` console) is the terminal, so the system can be
//! used directly. Ctrl-D at an empty prompt shuts the system down.
//!
//! `--check` drives COM2 instead: it waits for the prompt, runs `bin/hello`
//! (a shell job under its TaskGroup limits) to its output and the next
//! prompt, sends Ctrl-D, and
//! requires the kernel's power-off line on COM1. That is the smoke check for
//! development commits.
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
}

/// The same memory and CPU counts as the F matrix's default and SMP profiles.
const MEMORY_MIB: u32 = 2048;
const SMP_VCPUS: u32 = 4;
const CHECK_TIMEOUT: Duration = Duration::from_secs(180);
const PROMPT: &[u8] = b"wyrmsh> ";
const END_OF_INPUT: u8 = 0x04;
const POWER_OFF: &[u8] = b"no process remains; powering off";
/// One shell job, run under its TaskGroup limits, before shutting down.
const JOB_COMMAND: &[u8] = b"run bin/hello\r";
const JOB_OUTPUT: &[u8] = b"hello from native stdout";

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
    product::build(&product, &deep)?;

    // The product's firmware vars are sealed read-only; the run gets its own copy.
    let vars = root.join("OVMF_VARS.fd");
    fs::copy(product.join("artifacts/OVMF_VARS.fd"), &vars)
        .map_err(|error| Failure::task(format!("could not copy OVMF vars: {error}")))?;
    fs::set_permissions(&vars, fs::Permissions::from_mode(0o600))
        .map_err(|error| Failure::task(format!("could not open OVMF vars copy: {error}")))?;
    let com1 = root.join("com1.log");
    let args = qemu_arguments(boot.smp, &product, &vars, &com1);

    if boot.check {
        check(&args, &com1, &root)
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

fn qemu_arguments(smp: bool, product: &Path, vars: &Path, com1: &Path) -> Vec<String> {
    let vcpus = if smp { SMP_VCPUS } else { 1 };
    let mut args: Vec<String> = vec![
        "-machine".into(),
        "q35".into(),
        "-m".into(),
        format!("{MEMORY_MIB}M"),
        "-smp".into(),
        vcpus.to_string(),
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
        "-device".into(),
        "intel-iommu".into(),
        // A modern-only virtio disk whose DMA goes through the IOMMU.
        "-drive".into(),
        format!(
            "if=none,id=esp,format=raw,readonly=on,file={}",
            product.join("artifacts").join(product::ESP_NAME).display()
        ),
        "-device".into(),
        "virtio-blk-pci,drive=esp,disable-legacy=on,iommu_platform=on".into(),
        "-serial".into(),
        format!("file:{}", com1.display()),
    ];
    // The second ISA serial port is COM2, where the product runs `wyrmsh`.
    args.extend(["-serial".into(), "stdio".into()]);
    args
}

fn check(args: &[String], com1: &Path, root: &Path) -> Result<String, Failure> {
    let mut child = Command::new("qemu-system-x86_64")
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|error| Failure::task(format!("could not launch QEMU: {error}")))?;
    let result = drive(&mut child, com1);
    if result.is_err() {
        let _ = child.kill();
        let _ = child.wait();
    }
    result.map(|elapsed| {
        format!(
            "DEV_BOOT_CHECK_PASS seconds={} root={}\n",
            elapsed.as_secs(),
            root.display()
        )
    })
}

fn drive(child: &mut Child, com1: &Path) -> Result<Duration, Failure> {
    let started = Instant::now();
    let deadline = started + CHECK_TIMEOUT;
    let com2 = Arc::new(Mutex::new(Vec::new()));
    let mut stdout = child
        .stdout
        .take()
        .ok_or_else(|| Failure::task("QEMU COM2 is not piped"))?;
    let sink = Arc::clone(&com2);
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
    let seen = |needle: &'static [u8], after: usize| {
        let com2 = Arc::clone(&com2);
        move || {
            Ok(com2
                .lock()
                .map(|com2| com2.get(after..).is_some_and(|tail| contains(tail, needle)))
                .unwrap_or(false))
        }
    };
    let length = || com2.lock().map(|com2| com2.len()).unwrap_or(0);
    wait_until(deadline, "the wyrmsh prompt on COM2", seen(PROMPT, 0))?;
    let input = child
        .stdin
        .as_mut()
        .ok_or_else(|| Failure::task("QEMU COM2 input is not piped"))?;
    let before_job = length();
    input
        .write_all(JOB_COMMAND)
        .map_err(|error| Failure::task(format!("could not send the job command: {error}")))?;
    wait_until(
        deadline,
        "bin/hello output on COM2",
        seen(JOB_OUTPUT, before_job),
    )?;
    let after_job = length();
    wait_until(
        deadline,
        "the prompt after bin/hello",
        seen(PROMPT, after_job),
    )?;
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
    Ok(started.elapsed())
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

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_shell_console_is_the_second_serial_port_after_the_kernel_log() {
        let args = qemu_arguments(
            false,
            Path::new("/p"),
            Path::new("/v.fd"),
            Path::new("/c1.log"),
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
        let args = qemu_arguments(false, Path::new("/p"), Path::new("/v"), Path::new("/c"));
        let devices: Vec<&str> = args
            .windows(2)
            .filter(|pair| pair[0] == "-device")
            .map(|pair| pair[1].as_str())
            .collect();
        assert_eq!(
            devices,
            [
                "intel-iommu",
                "virtio-blk-pci,drive=esp,disable-legacy=on,iommu_platform=on"
            ]
        );
        assert!(!args.iter().any(|arg| arg.starts_with("if=virtio")));
    }

    #[test]
    fn smp_uses_the_f_matrix_cpu_count() {
        let args = qemu_arguments(true, Path::new("/p"), Path::new("/v"), Path::new("/c"));
        let smp = args
            .windows(2)
            .find(|pair| pair[0] == "-smp")
            .map(|pair| pair[1].clone());
        assert_eq!(smp.as_deref(), Some("4"));
    }
}
