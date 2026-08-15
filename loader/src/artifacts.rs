//! Deterministic WYR0 boot-artifact locations and presence validation.
//!
//! This module performs no firmware or filesystem I/O. It validates host-provided artifact
//! bytes before a later UEFI implementation assigns storage and BootInfo ranges.

#![allow(dead_code)]

/// Canonical directory on the EFI System Partition.
pub const ARTIFACT_ROOT: &str = "/EFI/Wyrmroot";
pub const KERNEL_PATH: &str = "/EFI/Wyrmroot/deepwyrm.elf";
pub const BOOTSTRAP_PATH: &str = "/EFI/Wyrmroot/bootstrap.elf";
pub const BOOTFS_PATH: &str = "/EFI/Wyrmroot/bootfs.img";

/// Host-testable artifact inputs. Firmware loading is intentionally outside this boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ArtifactInputs<'a> {
    pub kernel: Option<&'a [u8]>,
    pub bootstrap: Option<&'a [u8]>,
    pub bootfs: Option<&'a [u8]>,
}

/// Validated artifact references in canonical order.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ArtifactSet<'a> {
    pub kernel: &'a [u8],
    pub bootstrap: &'a [u8],
    pub bootfs: &'a [u8],
}

impl<'a> ArtifactInputs<'a> {
    /// Require all three principal artifacts and reject missing or zero-length inputs.
    pub fn validate(self) -> Result<ArtifactSet<'a>, ArtifactError> {
        let kernel = self.kernel.ok_or(ArtifactError::MissingKernel)?;
        if kernel.is_empty() {
            return Err(ArtifactError::EmptyKernel);
        }
        let bootstrap = self.bootstrap.ok_or(ArtifactError::MissingBootstrap)?;
        if bootstrap.is_empty() {
            return Err(ArtifactError::EmptyBootstrap);
        }
        let bootfs = self.bootfs.ok_or(ArtifactError::MissingBootfs)?;
        if bootfs.is_empty() {
            return Err(ArtifactError::EmptyBootfs);
        }
        Ok(ArtifactSet {
            kernel,
            bootstrap,
            bootfs,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ArtifactError {
    MissingKernel,
    MissingBootstrap,
    MissingBootfs,
    EmptyKernel,
    EmptyBootstrap,
    EmptyBootfs,
}
