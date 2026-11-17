//! The serial shell session of a `dev-boot --check` boot: commands sent to
//! `wyrmsh` on COM2 and their output read back up to the next prompt.

use std::{
    io::Write,
    process::{ChildStdin, ExitStatus},
    sync::{Arc, Mutex},
    thread,
    time::{Duration, Instant},
};

use super::{Patience, memory, qemu::exit_description};
use crate::error::Failure;

pub(super) const PROMPT: &[u8] = b"wyrmsh> ";
pub(super) const END_OF_INPUT: u8 = 0x04;

/// The shell console of one boot.
pub(super) struct Shell<'a> {
    pub(super) input: &'a mut ChildStdin,
    pub(super) com2: &'a Arc<Mutex<Vec<u8>>>,
    pub(super) deadline: Instant,
    pub(super) patience: Patience,
    /// Whether QEMU has exited, and how; every wait checks it.
    pub(super) exited: &'a mut dyn FnMut() -> Result<Option<ExitStatus>, Failure>,
}

impl Shell<'_> {
    /// How many times a loop that polls the guest tries before it fails.
    pub(super) const fn attempts(&self) -> usize {
        self.patience.attempts
    }

    fn length(&self) -> usize {
        self.com2.lock().map(|com2| com2.len()).unwrap_or(0)
    }

    /// Sends `command` and returns everything up to the next prompt.
    pub(super) fn run(&mut self, command: &str) -> Result<Vec<u8>, Failure> {
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
    pub(super) fn expect(&mut self, command: &str, needle: &[u8]) -> Result<(), Failure> {
        let output = self.run(command)?;
        if contains(&output, needle) {
            Ok(())
        } else {
            Err(Failure::task(format!(
                "dev-boot check: `{command}` printed {:?}{}",
                String::from_utf8_lossy(&output),
                memory::said(&output)
            )))
        }
    }

    /// Runs `command`, which must print nothing but its echo and the prompt.
    pub(super) fn quiet(&mut self, command: &str) -> Result<(), Failure> {
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
    pub(super) fn retry(
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

/// Polls `done` until it holds. Fails at `deadline`, or as soon as
/// `exited` reports that QEMU has exited, since then nothing more will come.
pub(super) fn wait_until(
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

/// `bytes` without ANSI control sequences (`ESC [` ... final byte).
pub(super) fn strip_escapes(bytes: &[u8]) -> Vec<u8> {
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
pub(super) fn spawn_job(shell: &mut Shell<'_>, path: &str) -> Result<u64, Failure> {
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

pub(super) fn contains(haystack: &[u8], needle: &[u8]) -> bool {
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
    fn spawned_job_ids_are_read_from_the_shell_echo() {
        assert_eq!(
            spawned_job_id(b"spawn bin/cpu-hog\r\nspawn job=12\r\nwyrmsh> "),
            Some(12)
        );
        assert_eq!(spawned_job_id(b"spawn job=\r\n"), None);
        assert_eq!(spawned_job_id(b"spawn: capacity\r\n"), None);
    }

    #[test]
    fn escapes_are_stripped_from_the_transcript() {
        assert_eq!(
            strip_escapes(b"\r\n\x1b[2Kwyrmsh> "),
            b"\r\nwyrmsh> ".to_vec()
        );
        assert_eq!(strip_escapes(b"a\x1b[1;31mb"), b"ab".to_vec());
    }
}
