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
/// The stream shapes are not cosmetic. The hog is admitted zero-stream because
/// it is a no-yield spinner with no output — the geometry ledger sizes its
/// handles as Process and TaskGroup only — and admitting it with three streams
/// would hand a saturation payload stdio it must never use. The progress child
/// is the ordinary smoke payload and keeps the three-stream shape every other
/// product gives it.
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
            allow_no_streams: false,
            allow_three_streams: true,
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
