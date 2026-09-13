//! Reset card R1's launch policy and probe configuration.
//!
//! The RRC role graph is WYR1-C1's and is validated by
//! `wyrmroot_rrc_manifest`'s `validate_r1_product`; nothing about it is
//! restated here. What is R1-specific is the *launchable* set — which bootfs
//! paths the product's JobV2 policy admits, on which stream shape — and the one
//! configuration file that tells the supervisor which probe to launch and with
//! what topology.
//!
//! Both are small and both are exactly where reset plan §8.1's exclusions
//! become mechanical rather than conventional: a policy that admitted a shell,
//! a recovery trigger or a stdout-pressure actor would be a different product,
//! and the tests below assert the set is exactly two entries.

// The policy half is host-side product construction, because every entry needs
// a build digest; the gate half is parsed by the supervisor on the target, so it
// stays available without the builder feature.
#[cfg(feature = "builder")]
extern crate alloc;
#[cfg(feature = "builder")]
use alloc::vec::Vec;

#[cfg(feature = "builder")]
use crate::launch_policy::{JOB_V2_PROFILE_ID, LaunchPolicyEntry};
#[cfg(feature = "builder")]
use crate::wyr1::{CPU_HOG_PATH, HELLO_PATH};

/// The probe's own image. It is a resident image launched by the supervisor, not
/// a JobV2 payload, so it is deliberately absent from the policy below.
pub const R1_PROBE_PATH: &str = "system/r1-saturation-probe";

/// Configuration naming the probe and its topology. The two profile handoffs
/// differ only in this file's contents, which is what keeps the SMP and control
/// runs the same product rather than two.
pub const R1_GATE_PATH: &str = "system/bootstrap/r1-gate-v1";

/// Startup ABI every R1 payload is launched under.
pub const R1_STARTUP_ABI: u16 = 2;

/// Exactly the payloads card R1 may launch through JobV2.
pub const R1_POLICY_ENTRY_COUNT: usize = 2;

/// Builds the card's complete JobV2 policy entry set.
///
/// Both payloads are admitted **zero-stream only**, and that is deliberate
/// rather than inherited. The probe encodes every launch with `streams: false`,
/// so three-stream admission would be authority the product never exercises,
/// and card R1 has no console at all: §8.1 excludes output pressure, and §3
/// ships no `consoled` or UART driver. The hog additionally must never hold
/// stdio because it is a no-yield spinner whose handles the geometry ledger
/// sizes as Process and TaskGroup only — a saturation payload with output
/// changes what the run measures.
///
/// WYR1-B admits `bin/hello` with both shapes because its client may launch it
/// either way. Copying that here would have widened R1 for no use.
#[cfg(feature = "builder")]
#[must_use]
pub fn launch_policy_entries(
    cpu_hog_identity: [u8; 32],
    hello_identity: [u8; 32],
) -> [LaunchPolicyEntry<'static>; R1_POLICY_ENTRY_COUNT] {
    [
        LaunchPolicyEntry {
            path: CPU_HOG_PATH,
            content_sha256: cpu_hog_identity,
            startup_abi: R1_STARTUP_ABI,
            profile_id: JOB_V2_PROFILE_ID,
            allow_no_streams: true,
            allow_three_streams: false,
        },
        LaunchPolicyEntry {
            path: HELLO_PATH,
            content_sha256: hello_identity,
            startup_abi: R1_STARTUP_ABI,
            profile_id: JOB_V2_PROFILE_ID,
            allow_no_streams: true,
            allow_three_streams: false,
        },
    ]
}

/// `WRR1` probe configuration. Fixed 64 bytes, so the supervisor reads it with
/// no allocation and no length negotiation.
pub const R1_GATE_BYTES: usize = 64;
const R1_GATE_MAGIC: [u8; 4] = *b"WRR1";
const R1_GATE_MAJOR: u16 = 1;
const R1_GATE_MINOR: u16 = 0;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProbeConfiguration {
    /// Hogs to launch, one at a time.
    pub hog_count: u16,
    /// vCPUs the profile brings online, recorded so a report cannot be misread
    /// as a different topology.
    pub online_cpus: u16,
    /// Identity of the probe image the supervisor must launch.
    pub probe_identity: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GateError {
    WrongSize,
    WrongMagic,
    UnsupportedVersion,
    /// A zero count would describe a run that proves nothing.
    ZeroTopology,
    /// The probe image identity was unset.
    ZeroIdentity,
    /// Trailing bytes were not zero, so the file carries something undeclared.
    NonzeroReserved,
}

/// Encodes the probe configuration into a fixed 64-byte record.
pub fn encode_gate(
    configuration: ProbeConfiguration,
    output: &mut [u8],
) -> Result<usize, GateError> {
    if output.len() < R1_GATE_BYTES {
        return Err(GateError::WrongSize);
    }
    if configuration.hog_count == 0 || configuration.online_cpus == 0 {
        return Err(GateError::ZeroTopology);
    }
    if configuration.probe_identity == [0; 32] {
        return Err(GateError::ZeroIdentity);
    }
    let bytes = &mut output[..R1_GATE_BYTES];
    bytes.fill(0);
    bytes[..4].copy_from_slice(&R1_GATE_MAGIC);
    bytes[4..6].copy_from_slice(&R1_GATE_MAJOR.to_le_bytes());
    bytes[6..8].copy_from_slice(&R1_GATE_MINOR.to_le_bytes());
    bytes[8..10].copy_from_slice(&configuration.hog_count.to_le_bytes());
    bytes[10..12].copy_from_slice(&configuration.online_cpus.to_le_bytes());
    bytes[12..16].copy_from_slice(&(R1_GATE_BYTES as u32).to_le_bytes());
    bytes[16..48].copy_from_slice(&configuration.probe_identity);
    Ok(R1_GATE_BYTES)
}

/// Parses the probe configuration. The supervisor must not infer a topology it
/// was not given: every field is required and the reserved tail must be zero.
pub fn parse_gate(bytes: &[u8]) -> Result<ProbeConfiguration, GateError> {
    if bytes.len() != R1_GATE_BYTES {
        return Err(GateError::WrongSize);
    }
    if bytes[..4] != R1_GATE_MAGIC {
        return Err(GateError::WrongMagic);
    }
    if u16::from_le_bytes([bytes[4], bytes[5]]) != R1_GATE_MAJOR
        || u16::from_le_bytes([bytes[6], bytes[7]]) != R1_GATE_MINOR
    {
        return Err(GateError::UnsupportedVersion);
    }
    if u32::from_le_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]) as usize != R1_GATE_BYTES {
        return Err(GateError::WrongSize);
    }
    if bytes[48..].iter().any(|byte| *byte != 0) {
        return Err(GateError::NonzeroReserved);
    }
    let hog_count = u16::from_le_bytes([bytes[8], bytes[9]]);
    let online_cpus = u16::from_le_bytes([bytes[10], bytes[11]]);
    if hog_count == 0 || online_cpus == 0 {
        return Err(GateError::ZeroTopology);
    }
    let mut probe_identity = [0_u8; 32];
    probe_identity.copy_from_slice(&bytes[16..48]);
    if probe_identity == [0; 32] {
        return Err(GateError::ZeroIdentity);
    }
    Ok(ProbeConfiguration {
        hog_count,
        online_cpus,
        probe_identity,
    })
}

#[cfg(test)]
mod tests;

/// Reset card R1's complete bootfs input.
///
/// The base is WYR1-C1's, unchanged, because R1's RRC role graph is C1's: all
/// five roles are present and uart16550d, consoled and wyrmsh stay
/// non-launchable. They are in the archive because the graph says they exist,
/// not because anything starts them — §8.1's exclusions are enforced by the
/// launch policy, which admits neither.
#[cfg(feature = "builder")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProductR1<'a> {
    pub c1: crate::wyr1::ProductC1<'a>,
    pub launch_policy: &'a [u8],
    /// The `WRR1` probe configuration.
    pub gate_config: &'a [u8],
    pub probe: &'a [u8],
    pub cpu_hog: &'a [u8],
    pub hello: &'a [u8],
    /// Independently supplied content identities, on the same principle as
    /// `ProductC1::expected_uart16550d_identity`: this crate never hashes, so
    /// the producer supplies identity and the build cross-binds it against what
    /// the policy and the gate actually claim.
    pub expected_probe_identity: [u8; 32],
    pub expected_cpu_hog_identity: [u8; 32],
    pub expected_hello_identity: [u8; 32],
}

/// C1's ten entries plus the policy, the gate, and the three payloads.
#[cfg(feature = "builder")]
pub const R1_ENTRY_COUNT: usize = 15;

#[cfg(feature = "builder")]
impl<'a> ProductR1<'a> {
    pub fn artifacts(self) -> [crate::wyr1::Artifact<'a>; R1_ENTRY_COUNT] {
        use crate::wyr1::Artifact;
        let c1 = self.c1.artifacts();
        [
            c1[0],
            c1[1],
            c1[2],
            c1[3],
            c1[4],
            c1[5],
            c1[6],
            c1[7],
            c1[8],
            c1[9],
            Artifact::read_only(crate::wyr1::LAUNCH_POLICY_PATH, self.launch_policy),
            Artifact::read_only(R1_GATE_PATH, self.gate_config),
            Artifact::executable(R1_PROBE_PATH, self.probe),
            Artifact::executable(CPU_HOG_PATH, self.cpu_hog),
            Artifact::executable(HELLO_PATH, self.hello),
        ]
    }
}

/// Builds the deterministic card-R1 archive.
///
/// Beyond C1's own validation this cross-binds the three things that could
/// otherwise disagree inside one image: the policy's admitted identities against
/// the payload identities the producer supplied, the gate's probe identity
/// against the probe artifact, and the gate's topology against the two plans
/// §8.1 fixes. Each of those disagreements would produce a bootable product that
/// launches the wrong bytes or reports the wrong topology, which is exactly the
/// class of failure card R1 exists to distinguish from a scheduler result.
#[cfg(feature = "builder")]
pub fn build_r1(product: ProductR1<'_>) -> Result<Vec<u8>, crate::builder::BuildError> {
    use crate::builder::{BuildError, Builder, FileMode};

    crate::wyr1::validate_c1_product(product.c1)?;
    validate_r1_policy(product)?;
    validate_r1_gate(product)?;

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

#[cfg(feature = "builder")]
fn validate_r1_policy(product: ProductR1<'_>) -> Result<(), crate::builder::BuildError> {
    use crate::builder::BuildError;
    use crate::launch_policy::LaunchPolicy;

    for identity in [
        product.expected_cpu_hog_identity,
        product.expected_hello_identity,
    ] {
        if identity == [0; 32] {
            return Err(BuildError::R1PolicyIdentityMismatch);
        }
    }
    let policy = LaunchPolicy::parse(product.launch_policy)
        .map_err(|_| BuildError::InvalidR1LaunchPolicy)?;
    if policy.len() != R1_POLICY_ENTRY_COUNT {
        return Err(BuildError::InvalidR1LaunchPolicy);
    }
    let expected = launch_policy_entries(
        product.expected_cpu_hog_identity,
        product.expected_hello_identity,
    );
    for entry in expected {
        let observed = policy
            .find(entry.path)
            .ok_or(BuildError::InvalidR1LaunchPolicy)?;
        // The digest is checked separately from the rest of the record so a
        // substituted payload is reported as an identity mismatch rather than as
        // a malformed policy.
        if observed.content_sha256 != entry.content_sha256 {
            return Err(BuildError::R1PolicyIdentityMismatch);
        }
        if observed != entry {
            return Err(BuildError::InvalidR1LaunchPolicy);
        }
    }
    Ok(())
}

#[cfg(feature = "builder")]
fn validate_r1_gate(product: ProductR1<'_>) -> Result<(), crate::builder::BuildError> {
    use crate::builder::BuildError;

    if product.expected_probe_identity == [0; 32] {
        return Err(BuildError::R1ProbeIdentityMismatch);
    }
    let configuration =
        parse_gate(product.gate_config).map_err(|_| BuildError::InvalidR1GateConfiguration)?;
    if configuration.probe_identity != product.expected_probe_identity {
        return Err(BuildError::R1ProbeIdentityMismatch);
    }
    if !ACCEPTED_TOPOLOGIES
        .iter()
        .any(|(hogs, cpus)| *hogs == configuration.hog_count && *cpus == configuration.online_cpus)
    {
        return Err(BuildError::R1UnacceptedTopology);
    }
    Ok(())
}

/// The two plans reset plan §8.1 fixes: the four-vCPU SMP profile and its
/// one-vCPU control. A product carrying any other topology would produce a
/// report no profile handoff matches.
pub const ACCEPTED_TOPOLOGIES: [(u16, u16); 2] = [(6, 4), (3, 1)];
