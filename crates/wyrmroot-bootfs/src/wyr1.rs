//! Deterministic WYR1-A bootfs product construction.
//!
//! WYR0 content admission remains in [`crate::content`].  This module is a
//! separate, fixed product surface: callers provide the exact immutable bytes
//! selected by the integration request and the builder emits the eight
//! canonical WYR1 entries in the existing `cpio newc` format.

#![cfg(feature = "builder")]

extern crate alloc;

use alloc::vec::Vec;

use crate::{
    builder::{BuildError, Builder, FileMode},
    launch_policy::{
        JOB_V2_PROFILE_ID, LaunchPolicy, WYRMSH_PATH as POLICY_WYRMSH_PATH, WYRMSH_PROFILE_ID,
    },
};
use wyrmroot_device_proto::{Manifest as DeviceManifest, manifest::ContentIdentity};

/// Permanent supervisor executable.
pub const INIT_PATH: &str = "system/init";
pub const REGISTRYD_PATH: &str = "system/registryd";
pub const DEVMGR_PATH: &str = "system/devmgr";
/// Retained immutable UART source; WYR1-A does not activate it.
pub const UART16550D_PATH: &str = "system/uart16550d";
pub const CONSOLED_PATH: &str = "system/consoled";
pub const WYRMSH_PATH: &str = "system/wyrmsh";
pub const CPU_HOG_PATH: &str = "bin/cpu-hog";
pub const E7_EXIT_NONZERO_PATH: &str = "test/wyr1-e/exit-nonzero";
pub const E7_FAULT_PATH: &str = "test/wyr1-e/fault";
pub const E7_MALFORMED_ELF_PATH: &str = "test/wyr1-e/malformed-elf";
pub const E8_RECOVERY_TRIGGER_PATH: &str = "test/wyr1-e/recovery-trigger";
pub const E8_STDOUT_PRESSURE_PATH: &str = "test/wyr1-e/stdout-pressure";
pub const E7_MALFORMED_ELF: &[u8] = b"WYR1-E7 malformed ELF\n";
pub const RRC_MANIFEST_PATH: &str = "system/bootstrap/rrc-a-v1";
pub const GATE_CONFIG_PATH: &str = "system/bootstrap/wyr1-a-gate-v1";
pub const LAUNCH_POLICY_PATH: &str = "system/bootstrap/launch-policy-v1";
pub const WYR1_B_GATE_PATH: &str = "system/bootstrap/wyr1-b-gate-v1";
/// Distinct WYR1-C product marker. This is deliberately separate from the
/// retained WYR1-A gate and WYR1-B gate entries.
pub const WYR1_C_MARKER_PATH: &str = "system/bootstrap/wyr1-c-gate-v1";
/// Fixed immutable WRDM v1 entry consumed by the resident device coordinator.
pub const WYR1_C_DEVICE_MANIFEST_PATH: &str = "system/bootstrap/wyr1-c-device-manifest-v1";
/// Short aliases for callers that name the two C1 product-surface entries by
/// their protocol/product role.
pub const WYR1_C_GATE_PATH: &str = WYR1_C_MARKER_PATH;
pub const WRDM_PATH: &str = WYR1_C_DEVICE_MANIFEST_PATH;
/// Exact, fixed content of the WYR1-C1 product marker entry.
pub const WYR1_C1_MARKER: &[u8] = b"WYR1-C1";
pub const HELLO_PATH: &str = "bin/hello";
pub const WYR1_B_PUBLISHER_PATH: &str = "test/wyr1-b/publisher";
pub const WYR1_B_CLIENT_PATH: &str = "test/wyr1-b/client";

/// Canonical WYR1-A role paths, in product order.
pub const ROLE_PATHS: [&str; 5] = [
    REGISTRYD_PATH,
    DEVMGR_PATH,
    UART16550D_PATH,
    CONSOLED_PATH,
    WYRMSH_PATH,
];

/// One explicitly supplied immutable WYR1 artifact.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Artifact<'a> {
    pub path: &'static str,
    pub bytes: &'a [u8],
    pub executable: bool,
}

impl<'a> Artifact<'a> {
    pub const fn executable(path: &'static str, bytes: &'a [u8]) -> Self {
        Self {
            path,
            bytes,
            executable: true,
        }
    }

    pub const fn read_only(path: &'static str, bytes: &'a [u8]) -> Self {
        Self {
            path,
            bytes,
            executable: false,
        }
    }
}

/// Exact eight-entry WYR1-A bootfs input.  Artifact hashes are intentionally
/// computed by the host receipt layer over these same byte slices; this crate
/// never derives identity from host metadata.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Product<'a> {
    pub init: &'a [u8],
    pub registryd: &'a [u8],
    pub devmgr: &'a [u8],
    pub uart16550d: &'a [u8],
    pub consoled: &'a [u8],
    pub wyrmsh: &'a [u8],
    pub rrc_manifest: &'a [u8],
    pub gate_config: &'a [u8],
}

impl<'a> Product<'a> {
    pub const fn artifacts(self) -> [Artifact<'a>; 8] {
        [
            Artifact::executable(INIT_PATH, self.init),
            Artifact::executable(REGISTRYD_PATH, self.registryd),
            Artifact::executable(DEVMGR_PATH, self.devmgr),
            Artifact::executable(UART16550D_PATH, self.uart16550d),
            Artifact::executable(CONSOLED_PATH, self.consoled),
            Artifact::executable(WYRMSH_PATH, self.wyrmsh),
            Artifact::read_only(RRC_MANIFEST_PATH, self.rrc_manifest),
            Artifact::read_only(GATE_CONFIG_PATH, self.gate_config),
        ]
    }
}

/// Build the exact WYR1 product archive.  The existing builder sorts paths,
/// fixes metadata, and rejects duplicate/invalid entries, so WYR0 archive
/// bytes and limits remain unchanged.
pub fn build(product: Product<'_>) -> Result<Vec<u8>, BuildError> {
    let mut builder = Builder::new();
    for artifact in product.artifacts() {
        if artifact.bytes.is_empty() {
            return Err(BuildError::EmptyArtifact);
        }
        builder.add(
            artifact.path.as_bytes(),
            artifact.bytes,
            if artifact.executable {
                FileMode::Executable
            } else {
                FileMode::ReadOnly
            },
        )?;
    }
    builder.build()
}

/// Exact WYR1-B product inputs. Gate publisher/client binaries are explicit
/// test content and do not enter the RRC-A manifest.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProductB<'a> {
    pub base: Product<'a>,
    pub launch_policy: &'a [u8],
    pub gate_config: &'a [u8],
    pub hello: &'a [u8],
    pub publisher: &'a [u8],
    pub client: &'a [u8],
}

impl<'a> ProductB<'a> {
    pub fn artifacts(self) -> [Artifact<'a>; 13] {
        let base = self.base.artifacts();
        [
            base[0],
            base[1],
            base[2],
            base[3],
            base[4],
            base[5],
            base[6],
            base[7],
            Artifact::read_only(LAUNCH_POLICY_PATH, self.launch_policy),
            Artifact::read_only(WYR1_B_GATE_PATH, self.gate_config),
            Artifact::executable(HELLO_PATH, self.hello),
            Artifact::executable(WYR1_B_PUBLISHER_PATH, self.publisher),
            Artifact::executable(WYR1_B_CLIENT_PATH, self.client),
        ]
    }
}

pub fn build_b(product: ProductB<'_>) -> Result<Vec<u8>, BuildError> {
    let mut builder = Builder::new();
    for artifact in product.artifacts() {
        if artifact.bytes.is_empty() {
            return Err(BuildError::EmptyArtifact);
        }
        builder.add(
            artifact.path.as_bytes(),
            artifact.bytes,
            if artifact.executable {
                FileMode::Executable
            } else {
                FileMode::ReadOnly
            },
        )?;
    }
    builder.build()
}

/// Exact WYR1-C1 product inputs. The base retains the complete WYR1-A
/// closure; the marker identifies this product generation and the final
/// read-only entry is the canonical WRDM v1 device-role manifest.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProductC1<'a> {
    pub base: Product<'a>,
    pub marker: &'a [u8],
    pub device_manifest: &'a [u8],
    /// Independently supplied content identity of `system/uart16550d`.
    ///
    /// The product producer derives this from the same immutable artifact
    /// identity used in the WRRM role record.  `build_c1` deliberately does
    /// not parse WRRM: `wyrmroot-rrc-manifest` already owns that format and
    /// depends on this crate for archive paths, so making bootfs parse WRRM
    /// would create a dependency cycle.  This value is the bounded, explicit
    /// cross-bind between the canonical WRDM role and that producer-owned
    /// WRRM validation.
    pub expected_uart16550d_identity: [u8; 32],
}

impl<'a> ProductC1<'a> {
    pub fn artifacts(self) -> [Artifact<'a>; 10] {
        let base = self.base.artifacts();
        [
            base[0],
            base[1],
            base[2],
            base[3],
            base[4],
            base[5],
            base[6],
            base[7],
            Artifact::read_only(WYR1_C_MARKER_PATH, self.marker),
            Artifact::read_only(WYR1_C_DEVICE_MANIFEST_PATH, self.device_manifest),
        ]
    }
}

/// Build the deterministic WYR1-C1 archive.
///
/// This admits only the exact product marker and a structurally valid,
/// canonical q35 COM2 WRDM role whose driver identity equals the independently
/// supplied UART artifact identity.  Exact WRRM structural/profile validation
/// remains owned by the RRC manifest product producer; see
/// [`ProductC1::expected_uart16550d_identity`].
pub fn build_c1(product: ProductC1<'_>) -> Result<Vec<u8>, BuildError> {
    validate_c1_product(product)?;
    let mut builder = Builder::new();
    for artifact in product.artifacts() {
        if artifact.bytes.is_empty() {
            return Err(BuildError::EmptyArtifact);
        }
        builder.add(
            artifact.path.as_bytes(),
            artifact.bytes,
            if artifact.executable {
                FileMode::Executable
            } else {
                FileMode::ReadOnly
            },
        )?;
    }
    builder.build()
}

/// Exact WYR1-C6 archive extension.  It deliberately retains the C1 base
/// entries and adds the selector-bound, read-only C6 gate as a distinct
/// bootstrap input; C1 and C2 builders therefore remain byte-for-byte
/// unchanged.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProductC6<'a> {
    pub base: ProductC1<'a>,
    pub gate: &'a [u8],
}

pub const WYR1_C6_GATE_PATH: &str = "system/bootstrap/wyr1-c6-gate-v1";

pub fn build_c6(product: ProductC6<'_>) -> Result<Vec<u8>, BuildError> {
    validate_c1_product(product.base)?;
    if product.gate.is_empty() {
        return Err(BuildError::EmptyArtifact);
    }
    let mut builder = Builder::new();
    for artifact in product.base.artifacts() {
        builder.add(
            artifact.path.as_bytes(),
            artifact.bytes,
            if artifact.executable {
                FileMode::Executable
            } else {
                FileMode::ReadOnly
            },
        )?;
    }
    builder.add(
        WYR1_C6_GATE_PATH.as_bytes(),
        product.gate,
        FileMode::ReadOnly,
    )?;
    builder.build()
}

/// Selector-31 E3A extends the retained C1 production closure with one
/// explicitly test-only RegistryClient actor. The actor is not a WRRM role
/// and cannot displace or alias any member of [`ROLE_PATHS`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProductE3A<'a> {
    pub base: ProductC1<'a>,
    pub gate: &'a [u8],
    pub raw_com2_probe: &'a [u8],
}

pub const DW1_E3A_GATE_PATH: &str = "system/bootstrap/dw1-e3a-gate-v1";
pub const DW1_E3A_COM2_PROBE_PATH: &str = "test/dw1e3/com2-probe";
/// Selector-32 native console-stream acceptance inputs.  This product is
/// separate from selector 31: it carries no DWE3 probe and cannot silently
/// inherit selector-31 evidence semantics.
pub const WYR1_D5_GATE_PATH: &str = "system/bootstrap/wyr1-d5-gate-v1";
pub const CONSOLE_ECHO_PATH: &str = "bin/console-echo";

pub fn build_e3a(product: ProductE3A<'_>) -> Result<Vec<u8>, BuildError> {
    validate_c1_product(product.base)?;
    if product.gate.is_empty() || product.raw_com2_probe.is_empty() {
        return Err(BuildError::EmptyArtifact);
    }
    let mut builder = Builder::new();
    for artifact in product.base.artifacts() {
        builder.add(
            artifact.path.as_bytes(),
            artifact.bytes,
            if artifact.executable {
                FileMode::Executable
            } else {
                FileMode::ReadOnly
            },
        )?;
    }
    builder.add(
        DW1_E3A_GATE_PATH.as_bytes(),
        product.gate,
        FileMode::ReadOnly,
    )?;
    builder.add(
        DW1_E3A_COM2_PROBE_PATH.as_bytes(),
        product.raw_com2_probe,
        FileMode::Executable,
    )?;
    builder.build()
}

/// Exact selector-32 extension of the retained production device closure.
/// `base.base.consoled` is the real console service selected by the producer;
/// the acceptance client is explicit non-role content and therefore cannot
/// displace any canonical WRRM role.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProductD5<'a> {
    pub base: ProductC1<'a>,
    pub gate: &'a [u8],
    pub launch_policy: &'a [u8],
    pub console_echo: &'a [u8],
}

pub fn build_d5(product: ProductD5<'_>) -> Result<Vec<u8>, BuildError> {
    validate_c1_product(product.base)?;
    if product.gate.is_empty()
        || product.launch_policy.is_empty()
        || product.console_echo.is_empty()
    {
        return Err(BuildError::EmptyArtifact);
    }
    let mut builder = Builder::new();
    for artifact in product.base.artifacts() {
        builder.add(
            artifact.path.as_bytes(),
            artifact.bytes,
            if artifact.executable {
                FileMode::Executable
            } else {
                FileMode::ReadOnly
            },
        )?;
    }
    builder.add(
        WYR1_D5_GATE_PATH.as_bytes(),
        product.gate,
        FileMode::ReadOnly,
    )?;
    builder.add(
        LAUNCH_POLICY_PATH.as_bytes(),
        product.launch_policy,
        FileMode::ReadOnly,
    )?;
    builder.add(
        CONSOLE_ECHO_PATH.as_bytes(),
        product.console_echo,
        FileMode::Executable,
    )?;
    builder.build()
}

/// Exact normal WYR1-E product. It extends the reached C1 recovery closure
/// with the immutable WRJP 1.1 policy and the one normal shell-approved
/// payload. Selector-33 test actors remain outside this product.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProductE6<'a> {
    pub base: ProductC1<'a>,
    pub launch_policy: &'a [u8],
    pub hello: &'a [u8],
    /// Producer-computed identity of `base.base.wyrmsh`, independently bound
    /// to the WRRM role and WRJP shell entry by the E6 product producer.
    pub expected_wyrmsh_identity: [u8; 32],
    /// Producer-computed identity of `hello`, bound to the WRJP JobV2 entry.
    pub expected_hello_identity: [u8; 32],
}

impl<'a> ProductE6<'a> {
    /// The exact normal E6 archive has seven executables and five read-only
    /// manifest/policy inputs.
    pub fn artifacts(self) -> [Artifact<'a>; 12] {
        let base = self.base.artifacts();
        [
            base[0],
            base[1],
            base[2],
            base[3],
            base[4],
            base[5],
            base[6],
            base[7],
            base[8],
            base[9],
            Artifact::read_only(LAUNCH_POLICY_PATH, self.launch_policy),
            Artifact::executable(HELLO_PATH, self.hello),
        ]
    }
}

/// Builds the deterministic normal WYR1-E archive after validating the
/// retained C1 policy and the exact two-entry WRJP 1.1 admission set.
pub fn build_e6(product: ProductE6<'_>) -> Result<Vec<u8>, BuildError> {
    validate_e6_product(product)?;
    let mut builder = Builder::new();
    for artifact in product.artifacts() {
        if artifact.bytes.is_empty() {
            return Err(BuildError::EmptyArtifact);
        }
        builder.add(
            artifact.path.as_bytes(),
            artifact.bytes,
            if artifact.executable {
                FileMode::Executable
            } else {
                FileMode::ReadOnly
            },
        )?;
    }
    builder.build()
}

fn validate_e6_product(product: ProductE6<'_>) -> Result<(), BuildError> {
    validate_c1_product(product.base)?;
    if product.launch_policy.is_empty() || product.hello.is_empty() {
        return Err(BuildError::EmptyArtifact);
    }
    if product.expected_wyrmsh_identity == [0; 32] {
        return Err(BuildError::E6WyrmshIdentityMismatch);
    }
    if product.expected_hello_identity == [0; 32] {
        return Err(BuildError::E6HelloIdentityMismatch);
    }
    let policy = LaunchPolicy::parse(product.launch_policy)
        .map_err(|_| BuildError::InvalidE6LaunchPolicy)?;
    if policy.version_minor() != 1 || policy.len() != 2 {
        return Err(BuildError::InvalidE6LaunchPolicy);
    }
    let hello = policy
        .find(HELLO_PATH)
        .ok_or(BuildError::InvalidE6LaunchPolicy)?;
    let wyrmsh = policy
        .find(POLICY_WYRMSH_PATH)
        .ok_or(BuildError::InvalidE6LaunchPolicy)?;
    if hello.startup_abi != 2
        || hello.profile_id != JOB_V2_PROFILE_ID
        || hello.allow_no_streams
        || !hello.allow_three_streams
        || wyrmsh.startup_abi != 2
        || wyrmsh.profile_id != WYRMSH_PROFILE_ID
        || wyrmsh.allow_no_streams
        || !wyrmsh.allow_three_streams
    {
        return Err(BuildError::InvalidE6LaunchPolicy);
    }
    if wyrmsh.content_sha256 != product.expected_wyrmsh_identity {
        return Err(BuildError::E6WyrmshIdentityMismatch);
    }
    if hello.content_sha256 != product.expected_hello_identity {
        return Err(BuildError::E6HelloIdentityMismatch);
    }
    Ok(())
}

/// Exact selector-33 WYR1-E product. It preserves the production recovery
/// closure and adds only the four explicitly admitted interactive-test
/// fixtures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProductE7<'a> {
    pub base: ProductC1<'a>,
    pub launch_policy: &'a [u8],
    pub hello: &'a [u8],
    pub cpu_hog: &'a [u8],
    pub exit_nonzero: &'a [u8],
    pub fault: &'a [u8],
    pub malformed_elf: &'a [u8],
    pub expected_wyrmsh_identity: [u8; 32],
    pub expected_hello_identity: [u8; 32],
    pub expected_cpu_hog_identity: [u8; 32],
    pub expected_exit_nonzero_identity: [u8; 32],
    pub expected_fault_identity: [u8; 32],
    pub expected_malformed_elf_identity: [u8; 32],
}

impl<'a> ProductE7<'a> {
    /// Seven production executables, four selector fixtures, and the five
    /// immutable manifest/policy inputs inherited from the E6 shape.
    pub fn artifacts(self) -> [Artifact<'a>; 16] {
        let base = self.base.artifacts();
        [
            base[0],
            base[1],
            base[2],
            base[3],
            base[4],
            base[5],
            base[6],
            base[7],
            base[8],
            base[9],
            Artifact::read_only(LAUNCH_POLICY_PATH, self.launch_policy),
            Artifact::executable(HELLO_PATH, self.hello),
            Artifact::executable(CPU_HOG_PATH, self.cpu_hog),
            Artifact::executable(E7_EXIT_NONZERO_PATH, self.exit_nonzero),
            Artifact::executable(E7_FAULT_PATH, self.fault),
            Artifact::executable(E7_MALFORMED_ELF_PATH, self.malformed_elf),
        ]
    }
}

/// Builds the deterministic selector-33 archive after validating its exact
/// six-entry WRJP 1.1 admission set and four frozen fixtures.
pub fn build_e7(product: ProductE7<'_>) -> Result<Vec<u8>, BuildError> {
    validate_e7_product(product)?;
    let mut builder = Builder::new();
    for artifact in product.artifacts() {
        if artifact.bytes.is_empty() {
            return Err(BuildError::EmptyArtifact);
        }
        builder.add(
            artifact.path.as_bytes(),
            artifact.bytes,
            if artifact.executable {
                FileMode::Executable
            } else {
                FileMode::ReadOnly
            },
        )?;
    }
    builder.build()
}

fn validate_e7_product(product: ProductE7<'_>) -> Result<(), BuildError> {
    validate_c1_product(product.base)?;
    if product.launch_policy.is_empty()
        || product.hello.is_empty()
        || product.cpu_hog.is_empty()
        || product.exit_nonzero.is_empty()
        || product.fault.is_empty()
    {
        return Err(BuildError::EmptyArtifact);
    }
    if product.malformed_elf != E7_MALFORMED_ELF {
        return Err(BuildError::InvalidE7MalformedElf);
    }
    let expected = [
        product.expected_wyrmsh_identity,
        product.expected_hello_identity,
        product.expected_cpu_hog_identity,
        product.expected_exit_nonzero_identity,
        product.expected_fault_identity,
        product.expected_malformed_elf_identity,
    ];
    if expected.contains(&[0; 32]) {
        return Err(BuildError::E7ArtifactIdentityMismatch);
    }
    let policy = LaunchPolicy::parse(product.launch_policy)
        .map_err(|_| BuildError::InvalidE7LaunchPolicy)?;
    if policy.version_minor() != 1 || policy.len() != 6 {
        return Err(BuildError::InvalidE7LaunchPolicy);
    }
    let entries = [
        (
            POLICY_WYRMSH_PATH,
            product.expected_wyrmsh_identity,
            WYRMSH_PROFILE_ID,
            false,
            true,
        ),
        (
            HELLO_PATH,
            product.expected_hello_identity,
            JOB_V2_PROFILE_ID,
            false,
            true,
        ),
        (
            CPU_HOG_PATH,
            product.expected_cpu_hog_identity,
            JOB_V2_PROFILE_ID,
            true,
            false,
        ),
        (
            E7_EXIT_NONZERO_PATH,
            product.expected_exit_nonzero_identity,
            JOB_V2_PROFILE_ID,
            false,
            true,
        ),
        (
            E7_FAULT_PATH,
            product.expected_fault_identity,
            JOB_V2_PROFILE_ID,
            false,
            true,
        ),
        (
            E7_MALFORMED_ELF_PATH,
            product.expected_malformed_elf_identity,
            JOB_V2_PROFILE_ID,
            false,
            true,
        ),
    ];
    for (path, identity, profile, no_streams, three_streams) in entries {
        let entry = policy.find(path).ok_or(BuildError::InvalidE7LaunchPolicy)?;
        if entry.startup_abi != 2
            || entry.profile_id != profile
            || entry.allow_no_streams != no_streams
            || entry.allow_three_streams != three_streams
            || entry.content_sha256 != identity
        {
            return Err(BuildError::E7ArtifactIdentityMismatch);
        }
    }
    Ok(())
}

/// Additive selector-33 WYR1-E8 product. The E7 grammar and product type stay
/// frozen; E8 carries its own eight-entry policy and two additional actors.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProductE8<'a> {
    pub base: ProductC1<'a>,
    pub launch_policy: &'a [u8],
    pub hello: &'a [u8],
    pub cpu_hog: &'a [u8],
    pub exit_nonzero: &'a [u8],
    pub fault: &'a [u8],
    pub malformed_elf: &'a [u8],
    pub recovery_trigger: &'a [u8],
    pub stdout_pressure: &'a [u8],
    pub expected_wyrmsh_identity: [u8; 32],
    pub expected_hello_identity: [u8; 32],
    pub expected_cpu_hog_identity: [u8; 32],
    pub expected_exit_nonzero_identity: [u8; 32],
    pub expected_fault_identity: [u8; 32],
    pub expected_malformed_elf_identity: [u8; 32],
    pub expected_recovery_trigger_identity: [u8; 32],
    pub expected_stdout_pressure_identity: [u8; 32],
}

impl<'a> ProductE8<'a> {
    /// The exact E7 archive shape plus the recovery trigger and stdout-pressure
    /// executables admitted only by the additive E8 policy.
    pub fn artifacts(self) -> [Artifact<'a>; 18] {
        let base = self.base.artifacts();
        [
            base[0],
            base[1],
            base[2],
            base[3],
            base[4],
            base[5],
            base[6],
            base[7],
            base[8],
            base[9],
            Artifact::read_only(LAUNCH_POLICY_PATH, self.launch_policy),
            Artifact::executable(HELLO_PATH, self.hello),
            Artifact::executable(CPU_HOG_PATH, self.cpu_hog),
            Artifact::executable(E7_EXIT_NONZERO_PATH, self.exit_nonzero),
            Artifact::executable(E7_FAULT_PATH, self.fault),
            Artifact::executable(E7_MALFORMED_ELF_PATH, self.malformed_elf),
            Artifact::executable(E8_RECOVERY_TRIGGER_PATH, self.recovery_trigger),
            Artifact::executable(E8_STDOUT_PRESSURE_PATH, self.stdout_pressure),
        ]
    }
}

/// Builds the deterministic E8 archive after validating its exact eight-entry
/// WRJP 1.1 policy and all inherited and current fixture identities.
pub fn build_e8(product: ProductE8<'_>) -> Result<Vec<u8>, BuildError> {
    validate_e8_product(product)?;
    let mut builder = Builder::new();
    for artifact in product.artifacts() {
        if artifact.bytes.is_empty() {
            return Err(BuildError::EmptyArtifact);
        }
        builder.add(
            artifact.path.as_bytes(),
            artifact.bytes,
            if artifact.executable {
                FileMode::Executable
            } else {
                FileMode::ReadOnly
            },
        )?;
    }
    builder.build()
}

fn validate_e8_product(product: ProductE8<'_>) -> Result<(), BuildError> {
    validate_c1_product(product.base)?;
    if product.launch_policy.is_empty()
        || product.hello.is_empty()
        || product.cpu_hog.is_empty()
        || product.exit_nonzero.is_empty()
        || product.fault.is_empty()
        || product.recovery_trigger.is_empty()
        || product.stdout_pressure.is_empty()
    {
        return Err(BuildError::EmptyArtifact);
    }
    if product.malformed_elf != E7_MALFORMED_ELF {
        return Err(BuildError::InvalidE8MalformedElf);
    }
    let expected = [
        product.expected_wyrmsh_identity,
        product.expected_hello_identity,
        product.expected_cpu_hog_identity,
        product.expected_exit_nonzero_identity,
        product.expected_fault_identity,
        product.expected_malformed_elf_identity,
        product.expected_recovery_trigger_identity,
        product.expected_stdout_pressure_identity,
    ];
    if expected.contains(&[0; 32]) {
        return Err(BuildError::E8ArtifactIdentityMismatch);
    }
    let policy = LaunchPolicy::parse(product.launch_policy)
        .map_err(|_| BuildError::InvalidE8LaunchPolicy)?;
    if policy.version_minor() != 1 || policy.len() != 8 {
        return Err(BuildError::InvalidE8LaunchPolicy);
    }
    let entries = [
        (
            POLICY_WYRMSH_PATH,
            product.expected_wyrmsh_identity,
            WYRMSH_PROFILE_ID,
            false,
            true,
        ),
        (
            HELLO_PATH,
            product.expected_hello_identity,
            JOB_V2_PROFILE_ID,
            false,
            true,
        ),
        (
            CPU_HOG_PATH,
            product.expected_cpu_hog_identity,
            JOB_V2_PROFILE_ID,
            true,
            false,
        ),
        (
            E7_EXIT_NONZERO_PATH,
            product.expected_exit_nonzero_identity,
            JOB_V2_PROFILE_ID,
            false,
            true,
        ),
        (
            E7_FAULT_PATH,
            product.expected_fault_identity,
            JOB_V2_PROFILE_ID,
            false,
            true,
        ),
        (
            E7_MALFORMED_ELF_PATH,
            product.expected_malformed_elf_identity,
            JOB_V2_PROFILE_ID,
            false,
            true,
        ),
        (
            E8_RECOVERY_TRIGGER_PATH,
            product.expected_recovery_trigger_identity,
            JOB_V2_PROFILE_ID,
            false,
            true,
        ),
        (
            E8_STDOUT_PRESSURE_PATH,
            product.expected_stdout_pressure_identity,
            JOB_V2_PROFILE_ID,
            false,
            true,
        ),
    ];
    for (path, identity, profile, no_streams, three_streams) in entries {
        let entry = policy.find(path).ok_or(BuildError::InvalidE8LaunchPolicy)?;
        if entry.startup_abi != 2
            || entry.profile_id != profile
            || entry.allow_no_streams != no_streams
            || entry.allow_three_streams != three_streams
            || entry.content_sha256 != identity
        {
            return Err(BuildError::E8ArtifactIdentityMismatch);
        }
    }
    Ok(())
}

fn validate_c1_product(product: ProductC1<'_>) -> Result<(), BuildError> {
    if product.marker != WYR1_C1_MARKER {
        return Err(BuildError::WrongC1Marker);
    }
    if product
        .expected_uart16550d_identity
        .iter()
        .all(|byte| *byte == 0)
    {
        return Err(BuildError::C1DriverIdentityMismatch);
    }
    let manifest = DeviceManifest::parse(product.device_manifest)
        .map_err(|_| BuildError::InvalidC1DeviceManifest)?;
    manifest
        .match_com2(ContentIdentity(product.expected_uart16550d_identity))
        .map_err(|error| match error {
            wyrmroot_device_proto::ManifestError::WrongContentIdentity => {
                BuildError::C1DriverIdentityMismatch
            }
            _ => BuildError::InvalidC1DeviceManifest,
        })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::archive::Archive;
    use crate::launch_policy::{LaunchPolicyEntry, encode_wyrmsh};
    use alloc::vec;

    const UART_IDENTITY: [u8; 32] = [0xa1; 32];

    fn c1_base() -> Product<'static> {
        Product {
            init: b"init",
            registryd: b"registry",
            devmgr: b"devmgr",
            uart16550d: b"uart",
            consoled: b"console",
            wyrmsh: b"shell",
            rrc_manifest: b"WRRM",
            gate_config: b"a",
        }
    }

    fn canonical_wrdm(identity: [u8; 32]) -> [u8; 176] {
        let mut bytes = [0u8; 176];
        bytes[..4].copy_from_slice(b"WRDM");
        bytes[4..6].copy_from_slice(&1u16.to_le_bytes());
        bytes[8..12].copy_from_slice(&176u32.to_le_bytes());
        bytes[12..14].copy_from_slice(&1u16.to_le_bytes());
        bytes[16..20].copy_from_slice(&1u32.to_le_bytes());
        bytes[20..24].copy_from_slice(&1u32.to_le_bytes());
        let record = 32;
        bytes[record..record + 8].copy_from_slice(&1u64.to_le_bytes());
        bytes[record + 8..record + 12].copy_from_slice(&2u32.to_le_bytes());
        bytes[record + 12..record + 16].copy_from_slice(&1u32.to_le_bytes());
        bytes[record + 16..record + 18].copy_from_slice(&0x2f8u16.to_le_bytes());
        bytes[record + 18..record + 20].copy_from_slice(&8u16.to_le_bytes());
        bytes[record + 20..record + 24].copy_from_slice(&3u32.to_le_bytes());
        bytes[record + 24..record + 26]
            .copy_from_slice(&(b"system/uart16550d".len() as u16).to_le_bytes());
        bytes[record + 28..record + 60].copy_from_slice(&identity);
        bytes[record + 60..record + 64].copy_from_slice(&1u32.to_le_bytes());
        bytes[record + 72..record + 72 + b"system/uart16550d".len()]
            .copy_from_slice(b"system/uart16550d");
        bytes
    }

    fn c1_product<'a>(
        marker: &'a [u8],
        device_manifest: &'a [u8],
        expected_uart16550d_identity: [u8; 32],
    ) -> ProductC1<'a> {
        ProductC1 {
            base: c1_base(),
            marker,
            device_manifest,
            expected_uart16550d_identity,
        }
    }

    fn e6_policy(
        wyrmsh_identity: [u8; 32],
        hello_identity: [u8; 32],
        hello_no_streams: bool,
    ) -> Vec<u8> {
        let entries = [
            LaunchPolicyEntry {
                path: HELLO_PATH,
                content_sha256: hello_identity,
                startup_abi: 2,
                profile_id: JOB_V2_PROFILE_ID,
                allow_no_streams: hello_no_streams,
                allow_three_streams: true,
            },
            LaunchPolicyEntry {
                path: WYRMSH_PATH,
                content_sha256: wyrmsh_identity,
                startup_abi: 2,
                profile_id: WYRMSH_PROFILE_ID,
                allow_no_streams: false,
                allow_three_streams: true,
            },
        ];
        let mut output = vec![0; 512];
        let used = encode_wyrmsh([0x42; 32], &entries, &mut output).unwrap();
        output.truncate(used);
        output
    }

    fn e7_policy(identities: [[u8; 32]; 6]) -> Vec<u8> {
        let entries = [
            LaunchPolicyEntry {
                path: CPU_HOG_PATH,
                content_sha256: identities[2],
                startup_abi: 2,
                profile_id: JOB_V2_PROFILE_ID,
                allow_no_streams: true,
                allow_three_streams: false,
            },
            LaunchPolicyEntry {
                path: HELLO_PATH,
                content_sha256: identities[1],
                startup_abi: 2,
                profile_id: JOB_V2_PROFILE_ID,
                allow_no_streams: false,
                allow_three_streams: true,
            },
            LaunchPolicyEntry {
                path: WYRMSH_PATH,
                content_sha256: identities[0],
                startup_abi: 2,
                profile_id: WYRMSH_PROFILE_ID,
                allow_no_streams: false,
                allow_three_streams: true,
            },
            LaunchPolicyEntry {
                path: E7_EXIT_NONZERO_PATH,
                content_sha256: identities[3],
                startup_abi: 2,
                profile_id: JOB_V2_PROFILE_ID,
                allow_no_streams: false,
                allow_three_streams: true,
            },
            LaunchPolicyEntry {
                path: E7_FAULT_PATH,
                content_sha256: identities[4],
                startup_abi: 2,
                profile_id: JOB_V2_PROFILE_ID,
                allow_no_streams: false,
                allow_three_streams: true,
            },
            LaunchPolicyEntry {
                path: E7_MALFORMED_ELF_PATH,
                content_sha256: identities[5],
                startup_abi: 2,
                profile_id: JOB_V2_PROFILE_ID,
                allow_no_streams: false,
                allow_three_streams: true,
            },
        ];
        let mut output = vec![0; 1024];
        let used = encode_wyrmsh([0x73; 32], &entries, &mut output).unwrap();
        output.truncate(used);
        output
    }

    fn e8_policy(identities: [[u8; 32]; 8]) -> Vec<u8> {
        let entries = [
            LaunchPolicyEntry {
                path: CPU_HOG_PATH,
                content_sha256: identities[2],
                startup_abi: 2,
                profile_id: JOB_V2_PROFILE_ID,
                allow_no_streams: true,
                allow_three_streams: false,
            },
            LaunchPolicyEntry {
                path: HELLO_PATH,
                content_sha256: identities[1],
                startup_abi: 2,
                profile_id: JOB_V2_PROFILE_ID,
                allow_no_streams: false,
                allow_three_streams: true,
            },
            LaunchPolicyEntry {
                path: WYRMSH_PATH,
                content_sha256: identities[0],
                startup_abi: 2,
                profile_id: WYRMSH_PROFILE_ID,
                allow_no_streams: false,
                allow_three_streams: true,
            },
            LaunchPolicyEntry {
                path: E7_EXIT_NONZERO_PATH,
                content_sha256: identities[3],
                startup_abi: 2,
                profile_id: JOB_V2_PROFILE_ID,
                allow_no_streams: false,
                allow_three_streams: true,
            },
            LaunchPolicyEntry {
                path: E7_FAULT_PATH,
                content_sha256: identities[4],
                startup_abi: 2,
                profile_id: JOB_V2_PROFILE_ID,
                allow_no_streams: false,
                allow_three_streams: true,
            },
            LaunchPolicyEntry {
                path: E7_MALFORMED_ELF_PATH,
                content_sha256: identities[5],
                startup_abi: 2,
                profile_id: JOB_V2_PROFILE_ID,
                allow_no_streams: false,
                allow_three_streams: true,
            },
            LaunchPolicyEntry {
                path: E8_RECOVERY_TRIGGER_PATH,
                content_sha256: identities[6],
                startup_abi: 2,
                profile_id: JOB_V2_PROFILE_ID,
                allow_no_streams: false,
                allow_three_streams: true,
            },
            LaunchPolicyEntry {
                path: E8_STDOUT_PRESSURE_PATH,
                content_sha256: identities[7],
                startup_abi: 2,
                profile_id: JOB_V2_PROFILE_ID,
                allow_no_streams: false,
                allow_three_streams: true,
            },
        ];
        let mut output = vec![0; 1536];
        let used = encode_wyrmsh([0x84; 32], &entries, &mut output).unwrap();
        output.truncate(used);
        output
    }

    #[test]
    fn product_is_deterministic_and_has_exact_paths() {
        let product = Product {
            init: b"init",
            registryd: b"registry",
            devmgr: b"devmgr",
            uart16550d: b"uart",
            consoled: b"console",
            wyrmsh: b"shell",
            rrc_manifest: b"WRRM",
            gate_config: b"config",
        };
        let first = build(product).unwrap();
        let second = build(product).unwrap();
        assert_eq!(first, second);
        let archive = Archive::new(&first).unwrap();
        let names: Vec<_> = archive.entries().map(|entry| entry.name()).collect();
        assert_eq!(
            names,
            vec![
                b"system/bootstrap/rrc-a-v1".as_slice(),
                b"system/bootstrap/wyr1-a-gate-v1".as_slice(),
                b"system/consoled".as_slice(),
                b"system/devmgr".as_slice(),
                b"system/init".as_slice(),
                b"system/registryd".as_slice(),
                b"system/uart16550d".as_slice(),
                b"system/wyrmsh".as_slice(),
            ]
        );
    }

    #[test]
    fn wyr1_b_adds_policy_hello_and_independent_gate_processes() {
        let base = Product {
            init: b"init",
            registryd: b"registry",
            devmgr: b"devmgr",
            uart16550d: b"uart",
            consoled: b"console",
            wyrmsh: b"shell",
            rrc_manifest: b"WRRM",
            gate_config: b"a",
        };
        let bytes = build_b(ProductB {
            base,
            launch_policy: b"WRJP",
            gate_config: b"b",
            hello: b"hello",
            publisher: b"publisher",
            client: b"client",
        })
        .unwrap();
        let archive = Archive::new(&bytes).unwrap();
        for path in [
            LAUNCH_POLICY_PATH,
            WYR1_B_GATE_PATH,
            HELLO_PATH,
            WYR1_B_PUBLISHER_PATH,
            WYR1_B_CLIENT_PATH,
        ] {
            assert!(archive.lookup(path.as_bytes()).is_ok());
        }
        assert!(
            !archive
                .lookup(LAUNCH_POLICY_PATH.as_bytes())
                .unwrap()
                .is_executable()
        );
        assert!(
            archive
                .lookup(HELLO_PATH.as_bytes())
                .unwrap()
                .is_executable()
        );
    }

    #[test]
    fn wyr1_c1_is_deterministic_and_retains_old_closure() {
        let device_manifest = canonical_wrdm(UART_IDENTITY);
        let product = c1_product(WYR1_C1_MARKER, &device_manifest, UART_IDENTITY);
        let first = build_c1(product).unwrap();
        assert_eq!(first, build_c1(product).unwrap());
        let archive = Archive::new(&first).unwrap();
        let names: Vec<_> = archive.entries().map(|entry| entry.name()).collect();
        assert_eq!(
            names,
            vec![
                b"system/bootstrap/rrc-a-v1".as_slice(),
                b"system/bootstrap/wyr1-a-gate-v1".as_slice(),
                b"system/bootstrap/wyr1-c-device-manifest-v1".as_slice(),
                b"system/bootstrap/wyr1-c-gate-v1".as_slice(),
                b"system/consoled".as_slice(),
                b"system/devmgr".as_slice(),
                b"system/init".as_slice(),
                b"system/registryd".as_slice(),
                b"system/uart16550d".as_slice(),
                b"system/wyrmsh".as_slice(),
            ]
        );
        assert!(
            !archive
                .lookup(WYR1_C_MARKER_PATH.as_bytes())
                .unwrap()
                .is_executable()
        );
        assert_eq!(
            archive
                .lookup(WYR1_C_DEVICE_MANIFEST_PATH.as_bytes())
                .unwrap()
                .data(),
            device_manifest
        );
    }

    #[test]
    fn wyr1_c1_rejects_wrong_marker_malformed_wrdm_policy_and_driver_identity() {
        let device_manifest = canonical_wrdm(UART_IDENTITY);
        assert_eq!(
            build_c1(c1_product(b"WYR1-C0", &device_manifest, UART_IDENTITY)),
            Err(BuildError::WrongC1Marker)
        );
        let mut malformed = device_manifest;
        malformed[..4].copy_from_slice(b"BAD!");
        assert_eq!(
            build_c1(c1_product(WYR1_C1_MARKER, &malformed, UART_IDENTITY)),
            Err(BuildError::InvalidC1DeviceManifest)
        );
        let mut wrong_policy = device_manifest;
        wrong_policy[32 + 16..32 + 18].copy_from_slice(&0x3f8u16.to_le_bytes());
        assert_eq!(
            build_c1(c1_product(WYR1_C1_MARKER, &wrong_policy, UART_IDENTITY)),
            Err(BuildError::InvalidC1DeviceManifest)
        );
        assert_eq!(
            build_c1(c1_product(WYR1_C1_MARKER, &device_manifest, [0xa2; 32])),
            Err(BuildError::C1DriverIdentityMismatch)
        );
        assert_eq!(
            build_c1(c1_product(WYR1_C1_MARKER, &device_manifest, [0; 32])),
            Err(BuildError::C1DriverIdentityMismatch)
        );
    }

    #[test]
    fn dw1_e3a_adds_one_test_actor_without_changing_the_five_role_inventory() {
        let device_manifest = canonical_wrdm(UART_IDENTITY);
        let bytes = build_e3a(ProductE3A {
            base: c1_product(WYR1_C1_MARKER, &device_manifest, UART_IDENTITY),
            gate: b"selector=31\npartial=true\n",
            raw_com2_probe: b"probe-elf",
        })
        .unwrap();
        let archive = Archive::new(&bytes).unwrap();
        assert_eq!(ROLE_PATHS.len(), 5);
        for path in ROLE_PATHS {
            assert!(archive.lookup(path.as_bytes()).unwrap().is_executable());
        }
        assert!(
            archive
                .lookup(DW1_E3A_COM2_PROBE_PATH.as_bytes())
                .unwrap()
                .is_executable()
        );
        assert!(
            !archive
                .lookup(DW1_E3A_GATE_PATH.as_bytes())
                .unwrap()
                .is_executable()
        );
        assert!(archive.lookup(WYR1_C6_GATE_PATH.as_bytes()).is_err());
    }

    #[test]
    fn wyr1_d5_is_distinct_from_selector31_and_admits_console_echo() {
        let device_manifest = canonical_wrdm(UART_IDENTITY);
        let product = ProductD5 {
            base: c1_product(WYR1_C1_MARKER, &device_manifest, UART_IDENTITY),
            gate: b"selector=32\nevidence=WRD1\n",
            launch_policy: b"WRJP selector32 console-echo",
            console_echo: b"console-echo-elf",
        };
        let first = build_d5(product).unwrap();
        assert_eq!(first, build_d5(product).unwrap());
        let archive = Archive::new(&first).unwrap();
        assert_eq!(archive.entries().count(), 13);
        assert!(
            archive
                .lookup(CONSOLE_ECHO_PATH.as_bytes())
                .unwrap()
                .is_executable()
        );
        assert!(
            !archive
                .lookup(WYR1_D5_GATE_PATH.as_bytes())
                .unwrap()
                .is_executable()
        );
        assert!(
            !archive
                .lookup(LAUNCH_POLICY_PATH.as_bytes())
                .unwrap()
                .is_executable()
        );
        assert!(archive.lookup(DW1_E3A_GATE_PATH.as_bytes()).is_err());
        assert!(archive.lookup(DW1_E3A_COM2_PROBE_PATH.as_bytes()).is_err());
        for path in ROLE_PATHS {
            assert!(archive.lookup(path.as_bytes()).unwrap().is_executable());
        }
    }

    #[test]
    fn wyr1_e6_builds_only_the_normal_twelve_entry_product() {
        const WYRMSH_IDENTITY: [u8; 32] = [0xe6; 32];
        const HELLO_IDENTITY: [u8; 32] = [0x10; 32];
        let device_manifest = canonical_wrdm(UART_IDENTITY);
        let policy = e6_policy(WYRMSH_IDENTITY, HELLO_IDENTITY, false);
        let product = ProductE6 {
            base: c1_product(WYR1_C1_MARKER, &device_manifest, UART_IDENTITY),
            launch_policy: &policy,
            hello: b"hello-elf",
            expected_wyrmsh_identity: WYRMSH_IDENTITY,
            expected_hello_identity: HELLO_IDENTITY,
        };

        let first = build_e6(product).unwrap();
        assert_eq!(first, build_e6(product).unwrap());
        let archive = Archive::new(&first).unwrap();
        assert_eq!(archive.entries().count(), 12);
        let executable_count = archive
            .entries()
            .filter(|entry| entry.is_executable())
            .count();
        assert_eq!(executable_count, 7);
        assert_eq!(
            archive.lookup(WYRMSH_PATH.as_bytes()).unwrap().data(),
            b"shell"
        );
        assert_eq!(
            archive.lookup(HELLO_PATH.as_bytes()).unwrap().data(),
            b"hello-elf"
        );
        assert_eq!(
            archive
                .lookup(LAUNCH_POLICY_PATH.as_bytes())
                .unwrap()
                .data(),
            policy
        );
        assert!(archive.lookup(CONSOLE_ECHO_PATH.as_bytes()).is_err());
        assert!(archive.lookup(WYR1_D5_GATE_PATH.as_bytes()).is_err());
        assert!(archive.lookup(DW1_E3A_COM2_PROBE_PATH.as_bytes()).is_err());
    }

    #[test]
    fn wyr1_e6_rejects_policy_shape_and_identity_substitution() {
        const WYRMSH_IDENTITY: [u8; 32] = [0xe6; 32];
        const HELLO_IDENTITY: [u8; 32] = [0x10; 32];
        let device_manifest = canonical_wrdm(UART_IDENTITY);
        let base = c1_product(WYR1_C1_MARKER, &device_manifest, UART_IDENTITY);
        let policy = e6_policy(WYRMSH_IDENTITY, HELLO_IDENTITY, false);
        let product = ProductE6 {
            base,
            launch_policy: &policy,
            hello: b"hello-elf",
            expected_wyrmsh_identity: WYRMSH_IDENTITY,
            expected_hello_identity: HELLO_IDENTITY,
        };

        assert_eq!(
            build_e6(ProductE6 {
                expected_wyrmsh_identity: [0; 32],
                ..product
            }),
            Err(BuildError::E6WyrmshIdentityMismatch)
        );
        assert_eq!(
            build_e6(ProductE6 {
                expected_hello_identity: [0; 32],
                ..product
            }),
            Err(BuildError::E6HelloIdentityMismatch)
        );
        assert_eq!(
            build_e6(ProductE6 {
                expected_wyrmsh_identity: [0xe7; 32],
                ..product
            }),
            Err(BuildError::E6WyrmshIdentityMismatch)
        );
        assert_eq!(
            build_e6(ProductE6 {
                expected_hello_identity: [0x11; 32],
                ..product
            }),
            Err(BuildError::E6HelloIdentityMismatch)
        );

        let no_streams = e6_policy(WYRMSH_IDENTITY, HELLO_IDENTITY, true);
        assert_eq!(
            build_e6(ProductE6 {
                launch_policy: &no_streams,
                ..product
            }),
            Err(BuildError::InvalidE6LaunchPolicy)
        );
        let historical = {
            let entries = [LaunchPolicyEntry {
                path: HELLO_PATH,
                content_sha256: HELLO_IDENTITY,
                startup_abi: 2,
                profile_id: JOB_V2_PROFILE_ID,
                allow_no_streams: false,
                allow_three_streams: true,
            }];
            let mut output = vec![0; 256];
            let used = crate::launch_policy::encode([0x42; 32], &entries, &mut output).unwrap();
            output.truncate(used);
            output
        };
        assert_eq!(
            build_e6(ProductE6 {
                launch_policy: &historical,
                ..product
            }),
            Err(BuildError::InvalidE6LaunchPolicy)
        );
    }

    #[test]
    fn wyr1_e7_adds_exactly_four_selected_fixtures() {
        let identities = [
            [0x71; 32], [0x72; 32], [0x73; 32], [0x74; 32], [0x75; 32], [0x76; 32],
        ];
        let device_manifest = canonical_wrdm(UART_IDENTITY);
        let policy = e7_policy(identities);
        let product = ProductE7 {
            base: c1_product(WYR1_C1_MARKER, &device_manifest, UART_IDENTITY),
            launch_policy: &policy,
            hello: b"hello-elf",
            cpu_hog: b"cpu-hog-elf",
            exit_nonzero: b"exit-nonzero-elf",
            fault: b"fault-elf",
            malformed_elf: E7_MALFORMED_ELF,
            expected_wyrmsh_identity: identities[0],
            expected_hello_identity: identities[1],
            expected_cpu_hog_identity: identities[2],
            expected_exit_nonzero_identity: identities[3],
            expected_fault_identity: identities[4],
            expected_malformed_elf_identity: identities[5],
        };
        let first = build_e7(product).unwrap();
        assert_eq!(first, build_e7(product).unwrap());
        let archive = Archive::new(&first).unwrap();
        assert_eq!(archive.entries().count(), 16);
        assert_eq!(
            archive
                .lookup(E7_MALFORMED_ELF_PATH.as_bytes())
                .unwrap()
                .data(),
            E7_MALFORMED_ELF
        );
        for path in [
            HELLO_PATH,
            CPU_HOG_PATH,
            E7_EXIT_NONZERO_PATH,
            E7_FAULT_PATH,
            E7_MALFORMED_ELF_PATH,
        ] {
            assert!(archive.lookup(path.as_bytes()).unwrap().is_executable());
        }
        assert!(archive.lookup(b"system/bootstrap/wyr1-e7-gate-v1").is_err());
    }

    #[test]
    fn wyr1_e7_rejects_fixture_and_policy_substitution() {
        let identities = [
            [0x71; 32], [0x72; 32], [0x73; 32], [0x74; 32], [0x75; 32], [0x76; 32],
        ];
        let device_manifest = canonical_wrdm(UART_IDENTITY);
        let policy = e7_policy(identities);
        let product = ProductE7 {
            base: c1_product(WYR1_C1_MARKER, &device_manifest, UART_IDENTITY),
            launch_policy: &policy,
            hello: b"hello-elf",
            cpu_hog: b"cpu-hog-elf",
            exit_nonzero: b"exit-nonzero-elf",
            fault: b"fault-elf",
            malformed_elf: E7_MALFORMED_ELF,
            expected_wyrmsh_identity: identities[0],
            expected_hello_identity: identities[1],
            expected_cpu_hog_identity: identities[2],
            expected_exit_nonzero_identity: identities[3],
            expected_fault_identity: identities[4],
            expected_malformed_elf_identity: identities[5],
        };
        assert_eq!(
            build_e7(ProductE7 {
                malformed_elf: b"WYR1-E7 malformed ELF",
                ..product
            }),
            Err(BuildError::InvalidE7MalformedElf)
        );
        assert_eq!(
            build_e7(ProductE7 {
                expected_fault_identity: [0; 32],
                ..product
            }),
            Err(BuildError::E7ArtifactIdentityMismatch)
        );
        let wrong_policy = e6_policy(identities[0], identities[1], false);
        assert_eq!(
            build_e7(ProductE7 {
                launch_policy: &wrong_policy,
                ..product
            }),
            Err(BuildError::InvalidE7LaunchPolicy)
        );
    }

    #[test]
    fn wyr1_e8_is_additive_and_keeps_the_e7_product_exact() {
        let identities = [
            [0x81; 32], [0x82; 32], [0x83; 32], [0x84; 32], [0x85; 32], [0x86; 32], [0x87; 32],
            [0x88; 32],
        ];
        let device_manifest = canonical_wrdm(UART_IDENTITY);
        let policy = e8_policy(identities);
        let product = ProductE8 {
            base: c1_product(WYR1_C1_MARKER, &device_manifest, UART_IDENTITY),
            launch_policy: &policy,
            hello: b"hello-elf",
            cpu_hog: b"cpu-hog-elf",
            exit_nonzero: b"exit-nonzero-elf",
            fault: b"fault-elf",
            malformed_elf: E7_MALFORMED_ELF,
            recovery_trigger: b"recovery-trigger-elf",
            stdout_pressure: b"stdout-pressure-elf",
            expected_wyrmsh_identity: identities[0],
            expected_hello_identity: identities[1],
            expected_cpu_hog_identity: identities[2],
            expected_exit_nonzero_identity: identities[3],
            expected_fault_identity: identities[4],
            expected_malformed_elf_identity: identities[5],
            expected_recovery_trigger_identity: identities[6],
            expected_stdout_pressure_identity: identities[7],
        };
        let first = build_e8(product).unwrap();
        assert_eq!(first, build_e8(product).unwrap());
        let archive = Archive::new(&first).unwrap();
        assert_eq!(archive.entries().count(), 18);
        for path in [E8_RECOVERY_TRIGGER_PATH, E8_STDOUT_PRESSURE_PATH] {
            assert!(archive.lookup(path.as_bytes()).unwrap().is_executable());
        }
        assert_eq!(LaunchPolicy::parse(&policy).unwrap().len(), 8);

        let e7_identities: [[u8; 32]; 6] = identities[..6].try_into().unwrap();
        let e7_policy = e7_policy(e7_identities);
        let e7 = build_e7(ProductE7 {
            base: c1_product(WYR1_C1_MARKER, &device_manifest, UART_IDENTITY),
            launch_policy: &e7_policy,
            hello: b"hello-elf",
            cpu_hog: b"cpu-hog-elf",
            exit_nonzero: b"exit-nonzero-elf",
            fault: b"fault-elf",
            malformed_elf: E7_MALFORMED_ELF,
            expected_wyrmsh_identity: identities[0],
            expected_hello_identity: identities[1],
            expected_cpu_hog_identity: identities[2],
            expected_exit_nonzero_identity: identities[3],
            expected_fault_identity: identities[4],
            expected_malformed_elf_identity: identities[5],
        })
        .unwrap();
        assert_eq!(Archive::new(&e7).unwrap().entries().count(), 16);
        assert!(
            Archive::new(&e7)
                .unwrap()
                .lookup(E8_RECOVERY_TRIGGER_PATH.as_bytes())
                .is_err()
        );
    }

    #[test]
    fn wyr1_e8_rejects_policy_identity_and_fixture_substitution() {
        let identities = [
            [0x81; 32], [0x82; 32], [0x83; 32], [0x84; 32], [0x85; 32], [0x86; 32], [0x87; 32],
            [0x88; 32],
        ];
        let device_manifest = canonical_wrdm(UART_IDENTITY);
        let policy = e8_policy(identities);
        let product = ProductE8 {
            base: c1_product(WYR1_C1_MARKER, &device_manifest, UART_IDENTITY),
            launch_policy: &policy,
            hello: b"hello-elf",
            cpu_hog: b"cpu-hog-elf",
            exit_nonzero: b"exit-nonzero-elf",
            fault: b"fault-elf",
            malformed_elf: E7_MALFORMED_ELF,
            recovery_trigger: b"recovery-trigger-elf",
            stdout_pressure: b"stdout-pressure-elf",
            expected_wyrmsh_identity: identities[0],
            expected_hello_identity: identities[1],
            expected_cpu_hog_identity: identities[2],
            expected_exit_nonzero_identity: identities[3],
            expected_fault_identity: identities[4],
            expected_malformed_elf_identity: identities[5],
            expected_recovery_trigger_identity: identities[6],
            expected_stdout_pressure_identity: identities[7],
        };
        assert_eq!(
            build_e8(ProductE8 {
                malformed_elf: b"WYR1-E7 malformed ELF",
                ..product
            }),
            Err(BuildError::InvalidE8MalformedElf)
        );
        assert_eq!(
            build_e8(ProductE8 {
                expected_recovery_trigger_identity: [0; 32],
                ..product
            }),
            Err(BuildError::E8ArtifactIdentityMismatch)
        );
        let wrong_policy = e7_policy(identities[..6].try_into().unwrap());
        assert_eq!(
            build_e8(ProductE8 {
                launch_policy: &wrong_policy,
                ..product
            }),
            Err(BuildError::InvalidE8LaunchPolicy)
        );
    }
}
