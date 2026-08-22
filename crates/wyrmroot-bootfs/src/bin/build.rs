use std::env;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use wyrmroot_bootfs::builder::{Builder, FileMode};

const MAX_INPUT_BYTES: u64 = 16 * 1024 * 1024;

fn main() {
    if let Err(error) = run() {
        eprintln!("bootfs build failed: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let mut arguments = env::args_os().skip(1);
    let init0_path = required_path(&mut arguments, "init0 ELF")?;
    let hello_path = required_path(&mut arguments, "hello ELF")?;
    let output_path = required_path(&mut arguments, "output bootfs")?;
    if arguments.next().is_some() {
        return Err("usage: wyrmroot-bootfs-build <init0-elf> <hello-elf> <output>".into());
    }

    let init0 = read_artifact(&init0_path, "init0 ELF")?;
    let hello = read_artifact(&hello_path, "hello ELF")?;
    let mut builder = Builder::new();
    builder
        .add(b"system/init0", &init0, FileMode::Executable)
        .map_err(|error| format!("could not add init0: {error:?}"))?;
    builder
        .add(b"bin/hello", &hello, FileMode::Executable)
        .map_err(|error| format!("could not add hello: {error:?}"))?;
    let archive = builder
        .build()
        .map_err(|error| format!("could not encode archive: {error:?}"))?;

    if fs::symlink_metadata(&output_path).is_ok() {
        return Err(format!("output already exists: {}", output_path.display()));
    }
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&output_path)
        .map_err(|error| format!("could not open {}: {error}", output_path.display()))?;
    output
        .write_all(&archive)
        .map_err(|error| format!("could not write {}: {error}", output_path.display()))?;
    output
        .sync_all()
        .map_err(|error| format!("could not sync {}: {error}", output_path.display()))?;
    Ok(())
}

fn required_path(
    arguments: &mut impl Iterator<Item = std::ffi::OsString>,
    label: &str,
) -> Result<PathBuf, String> {
    arguments.next().map(PathBuf::from).ok_or_else(|| {
        format!("missing {label}; usage: wyrmroot-bootfs-build <init0-elf> <hello-elf> <output>")
    })
}

fn read_artifact(path: &Path, label: &str) -> Result<Vec<u8>, String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("could not inspect {label} {}: {error}", path.display()))?;
    if !metadata.file_type().is_file() || metadata.len() == 0 || metadata.len() > MAX_INPUT_BYTES {
        return Err(format!(
            "{label} must be a nonempty regular file no larger than {MAX_INPUT_BYTES} bytes"
        ));
    }
    fs::read(path).map_err(|error| format!("could not read {label} {}: {error}", path.display()))
}
