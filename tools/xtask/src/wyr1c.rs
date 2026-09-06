//! Unnumbered, host-only WYR1-C1 product construction.
//!
//! This producer deliberately stops at immutable native artifacts, WRRM,
//! WRDM, bootfs, and a source/toolchain-bound receipt. It does not allocate a
//! guest selector, construct an ESP, or invoke QEMU/libvirt.

use std::{
    collections::{BTreeMap, BTreeSet},
    env,
    ffi::{OsStr, OsString},
    fs::{self, File},
    os::unix::fs::PermissionsExt,
    path::{Component, Path, PathBuf},
    process::{Command, Output, Stdio},
    time::{SystemTime, UNIX_EPOCH},
};

use crate::{
    error::Failure,
    metadata::BuildManifest,
    secure_fs::{InheritableDirectory, SealedFile},
    sha256,
};
use wyrmroot_bootfs::{
    archive::Archive,
    launch_policy::{
        JOB_V2_PROFILE_ID, LaunchPolicy, LaunchPolicyEntry, WYRMSH_PATH, WYRMSH_PROFILE_ID,
        encode as encode_launch_policy, encode_wyrmsh,
    },
    wyr1::{
        CONSOLE_ECHO_PATH, CPU_HOG_PATH, DW1_E3A_COM2_PROBE_PATH, DW1_E3A_GATE_PATH,
        E7_EXIT_NONZERO_PATH, E7_FAULT_PATH, E7_MALFORMED_ELF, E7_MALFORMED_ELF_PATH,
        E8_RECOVERY_TRIGGER_PATH, E8_STDOUT_PRESSURE_PATH, LAUNCH_POLICY_PATH, Product, ProductC1,
        ProductC6, ProductD5, ProductE3A, ProductE6, ProductE7, ProductE8, WYR1_C1_MARKER,
        WYR1_D5_GATE_PATH, build_c1, build_c6, build_d5, build_e3a, build_e6, build_e7, build_e8,
    },
};
use wyrmroot_device_proto::manifest::{
    ContentIdentity, HEADER_BYTES as WRDM_HEADER_BYTES, RECORD_BYTES as WRDM_RECORD_BYTES,
    encode_com2_manifest,
};
use wyrmroot_rrc_manifest::{Manifest, RoleId, StartupProfile, Wyr1eProductProfile};

const PRODUCT_KIND: &str = "wyrmroot-wyr1-c1-host-product";
const RECEIPT_KIND: &str = "wyrmroot-wyr1-c1-host-product-receipt";
const SCHEMA_VERSION: u32 = 1;
const ACCEPTED_RUST_REVISION: &str = "a92dc7f7464ad6ddfece4402bd7b86dbfa86166d";
const ACCEPTED_TOOLCHAIN_NAME: &str = "wyrmroot-1.97.1-a92dc7f7";
const NATIVE_TARGET: &str = "x86_64-unknown-wyrmroot";
const MAX_ARTIFACT_BYTES: usize = 64 * 1024 * 1024;
const MAX_BOOTFS_BYTES: usize = crate::g3_image::IMAGE_BYTES as usize;
const MAX_REPORT_BYTES: usize = 64 * 1024;
pub(crate) const GATE_CONFIG: &[u8] =
    b"schema = 1\nproduct = \"wyr1-c1-host-only\"\nselector = \"none\"\nevidence = \"not-produced\"\n";

#[derive(Clone, Copy)]
struct NativeSpec {
    label: &'static str,
    package: &'static str,
    binary: &'static str,
    features: &'static str,
    artifact: &'static str,
}

const NATIVE_SPECS: [NativeSpec; 6] = [
    NativeSpec {
        label: "system-init",
        package: "wyrmroot-system-init",
        binary: "system-init",
        features: "native-init",
        artifact: "system-init",
    },
    NativeSpec {
        label: "registryd",
        package: "wyrmroot-registryd",
        binary: "registryd",
        features: "native-registryd",
        artifact: "registryd",
    },
    NativeSpec {
        label: "devmgr",
        package: "wyrmroot-devmgr",
        binary: "devmgr",
        features: "native-devmgr",
        artifact: "devmgr",
    },
    NativeSpec {
        label: "uart16550d",
        package: "wyrmroot-wyr1-retained-stubs",
        binary: "uart16550d",
        features: "native-retained",
        artifact: "uart16550d",
    },
    NativeSpec {
        label: "consoled",
        package: "wyrmroot-wyr1-retained-stubs",
        binary: "consoled",
        features: "native-retained",
        artifact: "consoled",
    },
    NativeSpec {
        label: "wyrmsh",
        package: "wyrmroot-wyr1-retained-stubs",
        binary: "wyrmsh",
        features: "native-retained",
        artifact: "wyrmsh",
    },
];

#[allow(dead_code)] // consumed by the follow-on wyr1c6 producer command.
const C6_PRODUCT_NATIVE_SPECS: [NativeSpec; 6] = [
    NativeSpec {
        label: "system-init",
        package: "wyrmroot-system-init",
        binary: "system-init",
        features: "wyr1c6-production,wyr1c6-selector29",
        artifact: "system-init",
    },
    NativeSpec {
        label: "registryd",
        package: "wyrmroot-registryd",
        binary: "registryd",
        features: "native-registryd",
        artifact: "registryd",
    },
    NativeSpec {
        label: "devmgr",
        package: "wyrmroot-devmgr",
        binary: "devmgr",
        features: "wyr1c6-production,wyr1c6-selector29",
        artifact: "devmgr",
    },
    NativeSpec {
        label: "uart16550d",
        package: "wyrmroot-wyr1-retained-stubs",
        binary: "uart16550d",
        features: "wyr1c6-production,wyr1c6-selector29",
        artifact: "uart16550d",
    },
    NativeSpec {
        label: "consoled",
        package: "wyrmroot-wyr1-retained-stubs",
        binary: "consoled",
        features: "native-retained",
        artifact: "consoled",
    },
    NativeSpec {
        label: "wyrmsh",
        package: "wyrmroot-wyr1-retained-stubs",
        binary: "wyrmsh",
        features: "native-retained",
        artifact: "wyrmsh",
    },
];

const E3A_PRODUCT_NATIVE_SPECS: [NativeSpec; 7] = [
    NativeSpec {
        label: "system-init",
        package: "wyrmroot-system-init",
        binary: "system-init",
        features: "dw1e3-selector31",
        artifact: "system-init",
    },
    NativeSpec {
        label: "registryd",
        package: "wyrmroot-registryd",
        binary: "registryd",
        features: "native-registryd",
        artifact: "registryd",
    },
    NativeSpec {
        label: "devmgr",
        package: "wyrmroot-devmgr",
        binary: "devmgr",
        features: "dw1e3-selector31",
        artifact: "devmgr",
    },
    NativeSpec {
        label: "uart16550d",
        package: "wyrmroot-uart16550d",
        binary: "uart16550d",
        features: "dw1e3-selector31",
        artifact: "uart16550d",
    },
    NativeSpec {
        label: "consoled",
        package: "wyrmroot-wyr1-retained-stubs",
        binary: "consoled",
        features: "native-retained",
        artifact: "consoled",
    },
    NativeSpec {
        label: "wyrmsh",
        package: "wyrmroot-wyr1-retained-stubs",
        binary: "wyrmsh",
        features: "native-retained",
        artifact: "wyrmsh",
    },
    NativeSpec {
        label: "dw1e3-com2-test",
        package: "wyrmroot-dw1e3-com2-test",
        binary: "dw1e3-com2-test",
        features: "native-probe",
        artifact: "dw1e3-com2-test",
    },
];

const E3B_NATIVE_CHECK_SPECS: [NativeSpec; 8] = [
    NativeSpec {
        label: "bootstrap",
        package: "wyrmroot-bootstrap",
        binary: "wyrmroot-bootstrap",
        features: "wyr1c5-production",
        artifact: "wyrmroot-bootstrap",
    },
    E3A_PRODUCT_NATIVE_SPECS[0],
    E3A_PRODUCT_NATIVE_SPECS[1],
    E3A_PRODUCT_NATIVE_SPECS[2],
    E3A_PRODUCT_NATIVE_SPECS[3],
    E3A_PRODUCT_NATIVE_SPECS[4],
    E3A_PRODUCT_NATIVE_SPECS[5],
    E3A_PRODUCT_NATIVE_SPECS[6],
];

// Unselected WYR1-E3 adapters plus the historical selector32 compilation path.
// This gate checks native code; it does not construct a product or run a guest.
const WYR1E3_NATIVE_CHECK_SPECS: [NativeSpec; 5] = [
    NativeSpec {
        label: "system-init-shell-controller",
        package: "wyrmroot-system-init",
        binary: "system-init",
        features: "native-init,wyr1e-shell-controller",
        artifact: "system-init",
    },
    NativeSpec {
        label: "registryd-shell-preflight",
        package: "wyrmroot-registryd",
        binary: "registryd",
        features: "native-registryd",
        artifact: "registryd",
    },
    NativeSpec {
        label: "consoled-wyrmsh",
        package: "wyrmroot-consoled",
        binary: "consoled",
        features: "native-consoled,wyr1e-wyrmsh",
        artifact: "consoled",
    },
    NativeSpec {
        label: "consoled-selector32",
        package: "wyrmroot-consoled",
        binary: "consoled",
        features: "native-consoled,wyr1d-selector32",
        artifact: "consoled",
    },
    NativeSpec {
        label: "system-init-selector32",
        package: "wyrmroot-system-init",
        binary: "system-init",
        features: "wyr1d-selector32",
        artifact: "system-init",
    },
];

const WYRMSH_NATIVE_CHECK_SPECS: [NativeSpec; 1] = [NativeSpec {
    label: "wyrmsh",
    package: "wyrmroot-wyrmsh",
    binary: "wyrmsh",
    features: "native-wyrmsh",
    artifact: "wyrmsh",
}];

// The normal WYR1-E product and the historical selector-32 product are
// compiled together at the E6 join so a product-selection change cannot make
// the retained console path silently stop compiling.
const WYR1E6_NATIVE_CHECK_SPECS: [NativeSpec; 10] = [
    NativeSpec {
        label: "system-init-e6",
        package: "wyrmroot-system-init",
        binary: "system-init",
        features: "wyr1e-production",
        artifact: "system-init",
    },
    NativeSpec {
        label: "registryd-e6",
        package: "wyrmroot-registryd",
        binary: "registryd",
        features: "native-registryd",
        artifact: "registryd",
    },
    NativeSpec {
        label: "devmgr-e6",
        package: "wyrmroot-devmgr",
        binary: "devmgr",
        features: "wyr1e-production",
        artifact: "devmgr",
    },
    NativeSpec {
        label: "uart16550d-e6",
        package: "wyrmroot-uart16550d",
        binary: "uart16550d",
        features: "native-uart16550d",
        artifact: "uart16550d",
    },
    NativeSpec {
        label: "consoled-e6",
        package: "wyrmroot-consoled",
        binary: "consoled",
        features: "native-consoled,wyr1e-wyrmsh",
        artifact: "consoled",
    },
    NativeSpec {
        label: "wyrmsh-e6",
        package: "wyrmroot-wyrmsh",
        binary: "wyrmsh",
        features: "native-wyrmsh",
        artifact: "wyrmsh",
    },
    NativeSpec {
        label: "hello-e6",
        package: "wyrmroot-hello",
        binary: "wyrmroot-stream-hello",
        features: "native-stream-hello",
        artifact: "wyrmroot-stream-hello",
    },
    NativeSpec {
        label: "consoled-selector32-e6-regression",
        package: "wyrmroot-consoled",
        binary: "consoled",
        features: "native-consoled,wyr1d-selector32",
        artifact: "consoled",
    },
    NativeSpec {
        label: "system-init-selector32-e6-regression",
        package: "wyrmroot-system-init",
        binary: "system-init",
        features: "wyr1d-selector32",
        artifact: "system-init",
    },
    NativeSpec {
        label: "devmgr-selector32-e6-regression",
        package: "wyrmroot-devmgr",
        binary: "devmgr",
        features: "wyr1d-selector32",
        artifact: "devmgr",
    },
];

const WYR1E6_PRODUCT_NATIVE_SPECS: [NativeSpec; 7] = [
    NativeSpec {
        label: "system-init",
        package: "wyrmroot-system-init",
        binary: "system-init",
        features: "wyr1e-production",
        artifact: "system-init",
    },
    NativeSpec {
        label: "registryd",
        package: "wyrmroot-registryd",
        binary: "registryd",
        features: "native-registryd",
        artifact: "registryd",
    },
    NativeSpec {
        label: "devmgr",
        package: "wyrmroot-devmgr",
        binary: "devmgr",
        features: "wyr1e-production",
        artifact: "devmgr",
    },
    NativeSpec {
        label: "uart16550d",
        package: "wyrmroot-uart16550d",
        binary: "uart16550d",
        features: "native-uart16550d",
        artifact: "uart16550d",
    },
    NativeSpec {
        label: "consoled",
        package: "wyrmroot-consoled",
        binary: "consoled",
        features: "native-consoled,wyr1e-wyrmsh",
        artifact: "consoled",
    },
    NativeSpec {
        label: "wyrmsh",
        package: "wyrmroot-wyrmsh",
        binary: "wyrmsh",
        features: "native-wyrmsh",
        artifact: "wyrmsh",
    },
    NativeSpec {
        label: "hello",
        package: "wyrmroot-hello",
        binary: "wyrmroot-stream-hello",
        features: "native-stream-hello",
        artifact: "wyrmroot-stream-hello",
    },
];

const WYR1E7_SELECTED_NATIVE_SPECS: [NativeSpec; 6] = [
    NativeSpec {
        label: "system-init",
        package: "wyrmroot-system-init",
        binary: "system-init",
        features: "wyr1e-selector33",
        artifact: "system-init",
    },
    NativeSpec {
        label: "devmgr",
        package: "wyrmroot-devmgr",
        binary: "devmgr",
        features: "wyr1e-production",
        artifact: "devmgr",
    },
    NativeSpec {
        label: "hello",
        package: "wyrmroot-hello",
        binary: "wyrmroot-stream-hello",
        features: "native-stream-hello",
        artifact: "wyrmroot-stream-hello",
    },
    NativeSpec {
        label: "cpu-hog",
        package: "wyrmroot-dw1b-preemption",
        binary: "wyrmroot-job-cpu-hog",
        features: "native-job-cpu-hog",
        artifact: "wyrmroot-job-cpu-hog",
    },
    NativeSpec {
        label: "exit-nonzero",
        package: "wyrmroot-wyr1e-test-actors",
        binary: "wyrmroot-wyr1e-exit-nonzero",
        features: "native-exit-nonzero",
        artifact: "wyrmroot-wyr1e-exit-nonzero",
    },
    NativeSpec {
        label: "fault",
        package: "wyrmroot-wyr1e-test-actors",
        binary: "wyrmroot-wyr1e-fault",
        features: "native-fault",
        artifact: "wyrmroot-wyr1e-fault",
    },
];

const WYR1E8_SELECTED_NATIVE_SPECS: [NativeSpec; 10] = [
    NativeSpec {
        label: "system-init",
        package: "wyrmroot-system-init",
        binary: "system-init",
        features: "wyr1e8-selector33",
        artifact: "system-init",
    },
    NativeSpec {
        label: "devmgr",
        package: "wyrmroot-devmgr",
        binary: "devmgr",
        features: "wyr1e8-production",
        artifact: "devmgr",
    },
    NativeSpec {
        label: "uart16550d",
        package: "wyrmroot-uart16550d",
        binary: "uart16550d",
        features: "native-uart16550d",
        artifact: "uart16550d",
    },
    NativeSpec {
        label: "consoled",
        package: "wyrmroot-consoled",
        binary: "consoled",
        features: "native-consoled,wyr1e-wyrmsh,wyr1e8-recovery",
        artifact: "consoled",
    },
    NativeSpec {
        label: "hello",
        package: "wyrmroot-hello",
        binary: "wyrmroot-stream-hello",
        features: "native-stream-hello",
        artifact: "wyrmroot-stream-hello",
    },
    NativeSpec {
        label: "cpu-hog",
        package: "wyrmroot-dw1b-preemption",
        binary: "wyrmroot-job-cpu-hog",
        features: "native-job-cpu-hog",
        artifact: "wyrmroot-job-cpu-hog",
    },
    NativeSpec {
        label: "exit-nonzero",
        package: "wyrmroot-wyr1e-test-actors",
        binary: "wyrmroot-wyr1e-exit-nonzero",
        features: "native-exit-nonzero",
        artifact: "wyrmroot-wyr1e-exit-nonzero",
    },
    NativeSpec {
        label: "fault",
        package: "wyrmroot-wyr1e-test-actors",
        binary: "wyrmroot-wyr1e-fault",
        features: "native-fault",
        artifact: "wyrmroot-wyr1e-fault",
    },
    NativeSpec {
        label: "recovery-trigger",
        package: "wyrmroot-wyr1e-test-actors",
        binary: "wyrmroot-recovery-trigger",
        features: "native-recovery-trigger",
        artifact: "wyrmroot-recovery-trigger",
    },
    NativeSpec {
        label: "stdout-pressure",
        package: "wyrmroot-wyr1e-test-actors",
        binary: "wyrmroot-stdout-pressure",
        features: "native-stdout-pressure",
        artifact: "wyrmroot-stdout-pressure",
    },
];

const E3B_NATIVE_CHECK_ENVIRONMENT: [(&str, &str); 3] = [
    ("DEEPWYRM_DW1E_EVIDENCE_NONCE", "E300000000000001"),
    ("WYRMROOT_DW1E3_CHALLENGE_1_NONCE", "E300000000000002"),
    ("WYRMROOT_DW1E3_CHALLENGE_2_NONCE", "E300000000000003"),
];

const D5_PRODUCT_NATIVE_SPECS: [NativeSpec; 7] = [
    NativeSpec {
        label: "system-init",
        package: "wyrmroot-system-init",
        binary: "system-init",
        features: "wyr1d-selector32",
        artifact: "system-init",
    },
    NativeSpec {
        label: "registryd",
        package: "wyrmroot-registryd",
        binary: "registryd",
        features: "native-registryd",
        artifact: "registryd",
    },
    NativeSpec {
        label: "devmgr",
        package: "wyrmroot-devmgr",
        binary: "devmgr",
        features: "wyr1d-selector32",
        artifact: "devmgr",
    },
    NativeSpec {
        label: "uart16550d",
        package: "wyrmroot-uart16550d",
        binary: "uart16550d",
        features: "wyr1d-selector32",
        artifact: "uart16550d",
    },
    NativeSpec {
        label: "consoled",
        package: "wyrmroot-consoled",
        binary: "consoled",
        features: "native-consoled,wyr1d-selector32",
        artifact: "consoled",
    },
    NativeSpec {
        label: "wyrmsh",
        package: "wyrmroot-wyr1-retained-stubs",
        binary: "wyrmsh",
        features: "native-retained",
        artifact: "wyrmsh",
    },
    NativeSpec {
        label: "console-echo",
        package: "wyrmroot-console-echo",
        binary: "console-echo",
        features: "native-console-echo",
        artifact: "console-echo",
    },
];

const C4_NATIVE_CHECK_SPECS: [NativeSpec; 3] = [
    NativeSpec {
        label: "bootstrap-c4",
        package: "wyrmroot-bootstrap",
        binary: "wyrmroot-bootstrap",
        features: "wyr1c4-production",
        artifact: "wyrmroot-bootstrap",
    },
    NativeSpec {
        label: "system-init-c4",
        package: "wyrmroot-system-init",
        binary: "system-init",
        features: "wyr1c4-production",
        artifact: "system-init",
    },
    NativeSpec {
        label: "devmgr-c4",
        package: "wyrmroot-devmgr",
        binary: "devmgr",
        features: "wyr1c4-production",
        artifact: "devmgr",
    },
];

const C5_NATIVE_CHECK_SPECS: [NativeSpec; 4] = [
    NativeSpec {
        label: "bootstrap-c5",
        package: "wyrmroot-bootstrap",
        binary: "wyrmroot-bootstrap",
        features: "wyr1c5-production",
        artifact: "wyrmroot-bootstrap",
    },
    NativeSpec {
        label: "system-init-c5",
        package: "wyrmroot-system-init",
        binary: "system-init",
        features: "wyr1c5-production",
        artifact: "system-init",
    },
    NativeSpec {
        label: "devmgr-c5",
        package: "wyrmroot-devmgr",
        binary: "devmgr",
        features: "wyr1c5-production",
        artifact: "devmgr",
    },
    NativeSpec {
        label: "uart16550d-c5",
        package: "wyrmroot-wyr1-retained-stubs",
        binary: "uart16550d",
        features: "wyr1c5-production",
        artifact: "uart16550d",
    },
];

// C6 keeps the C5 resource-domain profile and adds only the bounded
// selector-29 restart exercise.  This list is intentionally separate from
// the C5 gate: a successful C5 build is not evidence that the C6 feature
// selection or retained driver actor was compiled.
const C6_NATIVE_CHECK_SPECS: [NativeSpec; 4] = [
    NativeSpec {
        label: "bootstrap-c6",
        package: "wyrmroot-bootstrap",
        binary: "wyrmroot-bootstrap",
        features: "wyr1c6-production",
        artifact: "wyrmroot-bootstrap",
    },
    NativeSpec {
        label: "system-init-c6",
        package: "wyrmroot-system-init",
        binary: "system-init",
        features: "wyr1c6-production,wyr1c6-selector29",
        artifact: "system-init",
    },
    NativeSpec {
        label: "devmgr-c6",
        package: "wyrmroot-devmgr",
        binary: "devmgr",
        features: "wyr1c6-production,wyr1c6-selector29",
        artifact: "devmgr",
    },
    NativeSpec {
        label: "uart16550d-c6",
        package: "wyrmroot-wyr1-retained-stubs",
        binary: "uart16550d",
        features: "wyr1c6-production,wyr1c6-selector29",
        artifact: "uart16550d",
    },
];

struct NativeArtifact {
    spec: NativeSpec,
    bytes: Vec<u8>,
    sha256: String,
    inspection: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct FrozenSnapshot {
    pub(crate) receipt: Vec<u8>,
    pub(crate) rrc_manifest: Vec<u8>,
    pub(crate) device_manifest: Vec<u8>,
    pub(crate) bootfs: Vec<u8>,
    pub(crate) artifacts: BTreeMap<String, Vec<u8>>,
    pub(crate) inspections: BTreeMap<String, Vec<u8>>,
}

/// Private output of the C6 native builder seam.  It intentionally contains
/// no receipt: C6 prepare must emit its own producer-owned source receipt
/// after staging and measuring the full selector-29 product.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct C6Snapshot {
    pub(crate) rrc_manifest: Vec<u8>,
    pub(crate) device_manifest: Vec<u8>,
    pub(crate) bootfs: Vec<u8>,
    pub(crate) artifacts: BTreeMap<String, Vec<u8>>,
    pub(crate) inspections: BTreeMap<String, Vec<u8>>,
}

/// Private selector-31 product snapshot. The seventh artifact is explicit
/// test content and remains outside the five-role WRRM inventory.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct E3ASnapshot {
    pub(crate) rrc_manifest: Vec<u8>,
    pub(crate) device_manifest: Vec<u8>,
    pub(crate) bootfs: Vec<u8>,
    pub(crate) artifacts: BTreeMap<String, Vec<u8>>,
    pub(crate) inspections: BTreeMap<String, Vec<u8>>,
}

/// Private selector-32 product snapshot.  `console-echo` is explicit
/// acceptance content outside the five-role WRRM inventory.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct D5Snapshot {
    pub(crate) rrc_manifest: Vec<u8>,
    pub(crate) device_manifest: Vec<u8>,
    pub(crate) launch_policy: Vec<u8>,
    pub(crate) bootfs: Vec<u8>,
    pub(crate) artifacts: BTreeMap<String, Vec<u8>>,
    pub(crate) inspections: BTreeMap<String, Vec<u8>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct E6Snapshot {
    pub(crate) wyrmroot_revision: String,
    pub(crate) rrc_manifest: Vec<u8>,
    pub(crate) device_manifest: Vec<u8>,
    pub(crate) launch_policy: Vec<u8>,
    pub(crate) bootfs: Vec<u8>,
    pub(crate) artifacts: BTreeMap<String, Vec<u8>>,
    pub(crate) inspections: BTreeMap<String, Vec<u8>>,
    pub(crate) stack_report: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct E7Snapshot {
    pub(crate) wyrmroot_revision: String,
    pub(crate) evidence_nonce: String,
    pub(crate) generation: [u8; 32],
    pub(crate) rrc_manifest: Vec<u8>,
    pub(crate) device_manifest: Vec<u8>,
    pub(crate) launch_policy: Vec<u8>,
    pub(crate) bootfs: Vec<u8>,
    pub(crate) artifacts: BTreeMap<String, Vec<u8>>,
    pub(crate) inspections: BTreeMap<String, Vec<u8>>,
    pub(crate) malformed_elf: Vec<u8>,
    pub(crate) stack_report: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct E8Snapshot {
    pub(crate) wyrmroot_revision: String,
    pub(crate) evidence_nonce: String,
    pub(crate) generation: [u8; 32],
    pub(crate) rrc_manifest: Vec<u8>,
    pub(crate) device_manifest: Vec<u8>,
    pub(crate) launch_policy: Vec<u8>,
    pub(crate) bootfs: Vec<u8>,
    pub(crate) artifacts: BTreeMap<String, Vec<u8>>,
    pub(crate) inspections: BTreeMap<String, Vec<u8>>,
    pub(crate) malformed_elf: Vec<u8>,
    pub(crate) stack_report: Vec<u8>,
}

pub(crate) const E6_ARTIFACT_LABELS: [&str; 7] = [
    "system-init",
    "registryd",
    "devmgr",
    "uart16550d",
    "consoled",
    "wyrmsh",
    "hello",
];

pub(crate) const E7_ARTIFACT_LABELS: [&str; 10] = [
    "system-init",
    "registryd",
    "devmgr",
    "uart16550d",
    "consoled",
    "wyrmsh",
    "hello",
    "cpu-hog",
    "exit-nonzero",
    "fault",
];

pub(crate) const E8_ARTIFACT_LABELS: [&str; 12] = [
    "system-init",
    "registryd",
    "devmgr",
    "uart16550d",
    "consoled",
    "wyrmsh",
    "hello",
    "cpu-hog",
    "exit-nonzero",
    "fault",
    "recovery-trigger",
    "stdout-pressure",
];

pub(crate) struct ValidatedFrozenProduct {
    pub(crate) wyrmroot_revision: String,
}

pub(crate) struct BuiltFrozenProduct {
    pub(crate) snapshot: FrozenSnapshot,
    pub(crate) validated: ValidatedFrozenProduct,
    pub(crate) publication: FrozenPublication,
}

pub(crate) fn run_c4_native_checks(repository: &Path) -> Result<(), Failure> {
    run_native_checks(
        repository,
        "WYR1-C4",
        "wyr1c4",
        &C4_NATIVE_CHECK_SPECS,
        &[],
        None,
    )
}

pub(crate) fn run_c5_native_checks(repository: &Path) -> Result<(), Failure> {
    run_native_checks(
        repository,
        "WYR1-C5",
        "wyr1c5",
        &C5_NATIVE_CHECK_SPECS,
        &[],
        None,
    )
}

pub(crate) fn run_c6_native_checks(repository: &Path) -> Result<(), Failure> {
    run_native_checks(
        repository,
        "WYR1-C6",
        "wyr1c6",
        &C6_NATIVE_CHECK_SPECS,
        &[],
        None,
    )
}

pub(crate) fn run_e3b_native_checks(repository: &Path) -> Result<(), Failure> {
    run_native_checks(
        repository,
        "DW1-E3B",
        "dw1e3b",
        &E3B_NATIVE_CHECK_SPECS,
        &E3B_NATIVE_CHECK_ENVIRONMENT,
        None,
    )
}

pub(crate) fn run_wyr1e3_native_checks(repository: &Path, filter: &str) -> Result<(), Failure> {
    let controller_specs = [WYR1E3_NATIVE_CHECK_SPECS[0], WYR1E3_NATIVE_CHECK_SPECS[4]];
    let specs = match filter {
        "wyr1e3-controller-native" => controller_specs.as_slice(),
        "wyr1e3-native" => WYR1E3_NATIVE_CHECK_SPECS.as_slice(),
        "wyr1e3-consoled-native" => &WYR1E3_NATIVE_CHECK_SPECS[2..4],
        "wyr1e3-registry-native" => &WYR1E3_NATIVE_CHECK_SPECS[1..2],
        _ => return Err(Failure::usage("unknown WYR1-E3 native check selection")),
    };
    run_native_checks(repository, "WYR1-E3", filter, specs, &[], None)
}

pub(crate) fn run_wyrmsh_native_checks(repository: &Path, filter: &str) -> Result<(), Failure> {
    let (phase, slug) = match filter {
        "wyr1e4-native" => ("WYR1-E4", "wyr1e4"),
        "wyr1e5-native" => ("WYR1-E5", "wyr1e5"),
        _ => return Err(Failure::usage("unknown Wyrmsh native check selection")),
    };
    run_native_checks(
        repository,
        phase,
        slug,
        &WYRMSH_NATIVE_CHECK_SPECS,
        &[],
        None,
    )
}

pub(crate) fn run_wyr1e6_native_checks(repository: &Path) -> Result<(), Failure> {
    run_native_checks(
        repository,
        "WYR1-E6",
        "wyr1e6",
        &WYR1E6_NATIVE_CHECK_SPECS,
        &[],
        None,
    )
}

pub(crate) fn run_wyr1e7_native_checks(repository: &Path) -> Result<(), Failure> {
    run_native_checks(
        repository,
        "WYR1-E7",
        "wyr1e7",
        &WYR1E7_SELECTED_NATIVE_SPECS,
        &[("WYRMROOT_WYR1E7_EVIDENCE_NONCE", "0123456789ABCDEF")],
        Some("system-init"),
    )
}

pub(crate) fn run_wyr1e8_native_checks(repository: &Path) -> Result<(), Failure> {
    run_native_checks(
        repository,
        "WYR1-E8",
        "wyr1e8",
        &WYR1E8_SELECTED_NATIVE_SPECS,
        &[("WYRMROOT_WYR1E8_EVIDENCE_NONCE", "0123456789ABCDEF")],
        Some("system-init"),
    )
}

pub(crate) fn run_wyr1e8_actor_native_checks(repository: &Path) -> Result<(), Failure> {
    run_native_checks(
        repository,
        "WYR1-E8 actors",
        "wyr1e8-actors",
        &WYR1E8_SELECTED_NATIVE_SPECS[8..],
        &[],
        None,
    )
}

fn run_native_checks(
    repository: &Path,
    phase: &str,
    slug: &str,
    specs: &[NativeSpec],
    environment: &[(&str, &str)],
    environment_label: Option<&str>,
) -> Result<(), Failure> {
    reject_ambient_build_environment(env::vars_os())?;
    let manifest = BuildManifest::load(repository)?;
    let profile = manifest.validate_loader_build_readiness(repository)?;
    let toolchain = crate::tasks::prepare_loader_toolchain(repository, &profile, &manifest)?;
    let cargo_home = crate::tasks::project_cargo_home(repository, &manifest)?;
    let project = crate::tasks::canonical_project_root(repository)?;
    let project_directory = crate::secure_fs::Directory::open_exact(&project, "OS-Project root")?;
    let tmp = match project_directory.open_child(".tmp", "project temporary root") {
        Ok(directory) => directory,
        Err(_) => project_directory.create_child(".tmp", 0o700, "project temporary root")?,
    };
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| Failure::task("system clock is before the Unix epoch"))?
        .as_nanos();
    let scratch_name = format!("{slug}-native-check-{}-{unique}", std::process::id());
    let scratch_label = format!("{phase} native-check scratch");
    let scratch = tmp.create_scratch(&scratch_name, &scratch_label)?;
    let check_result = scratch.with_inheritable_anchor(&scratch_label, |target| {
        let flags = format!(
            "{}\u{1f}-D\u{1f}warnings",
            native_remap_flags(repository, &cargo_home, target.path())?
        );
        for spec in specs {
            toolchain.accepted().verify_unchanged()?;
            target.verify_unchanged(&scratch_label)?;
            let mut command = Command::new(&toolchain.accepted().cargo);
            command
                .args([
                    "check",
                    "--offline",
                    "--locked",
                    "--target",
                    NATIVE_TARGET,
                    "--package",
                    spec.package,
                    "--bin",
                    spec.binary,
                    "--no-default-features",
                    "--features",
                    spec.features,
                ])
                .arg("--target-dir")
                .arg(target.path())
                .env("RUSTC", &toolchain.accepted().rustc)
                .env("CARGO_HOME", &cargo_home)
                .env("CARGO_ENCODED_RUSTFLAGS", &flags)
                .env("CARGO_INCREMENTAL", "0")
                .env("CARGO_NET_OFFLINE", "true")
                .env("SOURCE_DATE_EPOCH", "0")
                .env_remove("LD_AUDIT")
                .env_remove("LD_LIBRARY_PATH")
                .env_remove("LD_PRELOAD")
                .current_dir(repository)
                .stdin(Stdio::null());
            if environment_label.is_none_or(|label| label == spec.label) {
                for (name, value) in environment {
                    command.env(name, value);
                }
            } else {
                for (name, _) in environment {
                    command.env_remove(name);
                }
            }
            let status = command.status().map_err(|error| {
                Failure::task(format!("could not check {}: {error}", spec.label))
            })?;
            target.verify_unchanged(&scratch_label)?;
            if !status.success() {
                return Err(Failure::task(format!(
                    "{phase} canonical {} check failed",
                    spec.label
                )));
            }
        }
        Ok(())
    });
    let result = scratch.finish(check_result);
    toolchain.accepted().verify_unchanged()?;
    result
}

pub(crate) struct FrozenDirectories {
    pub(crate) artifacts: crate::secure_fs::Directory,
    pub(crate) inspections: crate::secure_fs::Directory,
    pub(crate) product: crate::secure_fs::Directory,
}

pub(crate) struct FrozenPublication {
    pub(crate) directories: FrozenDirectories,
    artifacts: BTreeMap<String, File>,
    inspections: BTreeMap<String, File>,
    rrc_manifest: File,
    device_manifest: File,
    bootfs: File,
    receipt: File,
}

pub(crate) fn product(output: &Path) -> Result<String, Failure> {
    reject_ambient_build_environment(env::vars_os())?;
    let repository = crate::tasks::repository_root()?;
    let project = repository
        .ancestors()
        .find(|path| path.ends_with("OS-Project"))
        .ok_or_else(|| Failure::task("WYR1-C1 source is not beneath OS-Project"))?
        .to_path_buf();
    let output = validate_fresh_output(&repository, &project, output)?;
    let parent_path = output
        .parent()
        .ok_or_else(|| Failure::task("WYR1-C1 output has no parent"))?;
    let name = output
        .file_name()
        .and_then(OsStr::to_str)
        .ok_or_else(|| Failure::task("WYR1-C1 output name is not UTF-8"))?;
    let parent = crate::secure_fs::Directory::open_exact(parent_path, "WYR1-C1 output parent")?;
    let parent_mode = parent.owned_container_mode("WYR1-C1 output parent")?;
    let output_directory = parent.create_child(name, 0o700, "WYR1-C1 output")?;
    let mut built = build_into(&output_directory)?;
    let accepted = accept_publication(
        &repository,
        &parent,
        parent_mode,
        name,
        &output_directory,
        &mut built.publication,
    )?;
    if accepted != built.snapshot {
        return Err(Failure::task(
            "WYR1-C1 accepted publication differs from the built snapshot",
        ));
    }
    Ok(format!(
        "WYR1_C1_HOST_PRODUCT_PASS product_kind={PRODUCT_KIND} selector=none evidence=not-produced wyrmroot_revision={} rust_revision={ACCEPTED_RUST_REVISION} bootfs_sha256={} receipt={}\n",
        built.validated.wyrmroot_revision,
        sha256::bytes_digest(&built.snapshot.bootfs),
        output.join("product/build-receipt.toml").display(),
    ))
}

pub(crate) fn build_into(
    output: &crate::secure_fs::Directory,
) -> Result<BuiltFrozenProduct, Failure> {
    reject_ambient_build_environment(env::vars_os())?;
    let repository = crate::tasks::repository_root()?;
    let project = repository
        .ancestors()
        .find(|path| path.ends_with("OS-Project"))
        .ok_or_else(|| Failure::task("WYR1-C1 source is not beneath OS-Project"))?
        .to_path_buf();
    let revision = clean_repository_revision(&repository)?;
    let manifest = BuildManifest::load(&repository)?;
    if manifest.rust_revision()? != ACCEPTED_RUST_REVISION
        || manifest.rust_toolchain_name()? != ACCEPTED_TOOLCHAIN_NAME
    {
        return Err(Failure::task(
            "WYR1-C1 product metadata does not name the accepted a92dc7f Rust toolchain",
        ));
    }
    let profile = manifest.validate_loader_build_readiness(&repository)?;
    let toolchain = crate::tasks::prepare_loader_toolchain(&repository, &profile, &manifest)?;
    let cargo_home = crate::tasks::project_cargo_home(&repository, &manifest)?;
    if env::var_os("CARGO_HOME").as_deref() != Some(cargo_home.as_os_str()) {
        return Err(Failure::task(
            "WYR1-C1 product requires the pinned launcher's exact CARGO_HOME",
        ));
    }

    let project_directory = crate::secure_fs::Directory::open_exact(&project, "OS-Project root")?;
    let tmp = match project_directory.open_child(".tmp", "project temporary root") {
        Ok(directory) => directory,
        Err(_) => project_directory.create_child(".tmp", 0o700, "project temporary root")?,
    };
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| Failure::task("system clock is before the Unix epoch"))?
        .as_nanos();
    let scratch_name = format!("wyr1c-build-{}-{unique}", std::process::id());
    let scratch = tmp.create_scratch(&scratch_name, "WYR1-C1 build scratch")?;
    let build_result = (|| {
        let mut artifacts = Vec::with_capacity(NATIVE_SPECS.len());
        for spec in NATIVE_SPECS {
            toolchain.accepted().verify_unchanged()?;
            let artifact = scratch.with_inheritable_anchor("WYR1-C1 build scratch", |anchor| {
                let mut artifact = build_native(
                    &repository,
                    &cargo_home,
                    toolchain.accepted(),
                    anchor,
                    spec,
                    None,
                )?;
                artifact.inspection = inspect_native(
                    &repository,
                    &artifact.bytes,
                    &artifact.sha256,
                    spec.label,
                    anchor,
                )?;
                Ok(artifact)
            })?;
            artifacts.push(artifact);
        }
        Ok::<_, Failure>(artifacts)
    })();
    let artifacts = scratch.finish(build_result)?;
    toolchain.accepted().verify_unchanged()?;
    verify_repository_revision(&repository, &revision)?;

    let product = assemble_product(&revision, &artifacts)?;
    let receipt = render_receipt(
        &revision,
        &manifest,
        toolchain.accepted(),
        &product,
        &artifacts,
    )?;
    if receipt.len() > MAX_REPORT_BYTES {
        return Err(Failure::task("WYR1-C1 receipt exceeds its fixed bound"));
    }
    let snapshot = FrozenSnapshot {
        receipt: receipt.into_bytes(),
        rrc_manifest: product.rrc_manifest,
        device_manifest: product.device_manifest,
        bootfs: product.bootfs,
        artifacts: artifacts
            .iter()
            .map(|artifact| (artifact.spec.label.to_owned(), artifact.bytes.clone()))
            .collect(),
        inspections: artifacts
            .iter()
            .map(|artifact| {
                (
                    artifact.spec.label.to_owned(),
                    artifact.inspection.as_bytes().to_vec(),
                )
            })
            .collect(),
    };
    let validated = validate_frozen_product(&repository, &snapshot)?;
    let mut publication = publish_snapshot(output, &snapshot)?;
    let published = snapshot_from_publication(&mut publication)?;
    if published != snapshot {
        return Err(Failure::task("WYR1-C1 published snapshot changed"));
    }
    validate_frozen_product(&repository, &published)?;
    verify_published_directories(output, &publication.directories)?;
    toolchain.accepted().verify_unchanged()?;
    verify_repository_revision(&repository, &revision)?;
    Ok(BuiltFrozenProduct {
        snapshot: published,
        validated,
        publication,
    })
}

/// Build the C6-native bootfs snapshot with the same accepted compiler,
/// inspection, WRRM and WRDM construction rules as C1.  Publication and VM
/// handoff remain owned by `wyr1c6`.
#[allow(dead_code)] // crate-private seam for wyr1c6::prepare.
pub(crate) fn build_c6_snapshot(nonce: &str) -> Result<C6Snapshot, Failure> {
    validate_c6_nonce(nonce)?;
    reject_ambient_build_environment(env::vars_os())?;
    let repository = crate::tasks::repository_root()?;
    let project = crate::tasks::canonical_project_root(&repository)?;
    let revision = clean_repository_revision(&repository)?;
    let manifest = BuildManifest::load(&repository)?;
    if manifest.rust_revision()? != ACCEPTED_RUST_REVISION
        || manifest.rust_toolchain_name()? != ACCEPTED_TOOLCHAIN_NAME
    {
        return Err(Failure::task(
            "WYR1-C6 product metadata does not name the accepted a92dc7f Rust toolchain",
        ));
    }
    let profile = manifest.validate_loader_build_readiness(&repository)?;
    let toolchain = crate::tasks::prepare_loader_toolchain(&repository, &profile, &manifest)?;
    let cargo_home = crate::tasks::project_cargo_home(&repository, &manifest)?;
    if env::var_os("CARGO_HOME").as_deref() != Some(cargo_home.as_os_str()) {
        return Err(Failure::task(
            "WYR1-C6 product requires the pinned launcher's exact CARGO_HOME",
        ));
    }
    toolchain.accepted().verify_unchanged()?;
    let project_directory = crate::secure_fs::Directory::open_exact(&project, "OS-Project root")?;
    let tmp = match project_directory.open_child(".tmp", "project temporary root") {
        Ok(directory) => directory,
        Err(_) => project_directory.create_child(".tmp", 0o700, "project temporary root")?,
    };
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| Failure::task("system clock is before the Unix epoch"))?
        .as_nanos();
    let scratch = tmp.create_scratch(
        &format!("wyr1c6-build-{}-{unique}", std::process::id()),
        "WYR1-C6 build scratch",
    )?;
    let result = (|| {
        let mut artifacts = Vec::with_capacity(C6_PRODUCT_NATIVE_SPECS.len());
        for spec in C6_PRODUCT_NATIVE_SPECS {
            toolchain.accepted().verify_unchanged()?;
            let artifact = scratch.with_inheritable_anchor("WYR1-C6 build scratch", |anchor| {
                let mut artifact = build_native(
                    &repository,
                    &cargo_home,
                    toolchain.accepted(),
                    anchor,
                    spec,
                    None,
                )?;
                artifact.inspection = inspect_native(
                    &repository,
                    &artifact.bytes,
                    &artifact.sha256,
                    spec.label,
                    anchor,
                )?;
                Ok(artifact)
            })?;
            artifacts.push(artifact);
        }
        let product = assemble_c6_product(&revision, &artifacts, nonce)?;
        Ok(C6Snapshot {
            rrc_manifest: product.rrc_manifest,
            device_manifest: product.device_manifest,
            bootfs: product.bootfs,
            artifacts: artifacts
                .iter()
                .map(|a| (a.spec.label.to_owned(), a.bytes.clone()))
                .collect(),
            inspections: artifacts
                .iter()
                .map(|a| (a.spec.label.to_owned(), a.inspection.as_bytes().to_vec()))
                .collect(),
        })
    })();
    let snapshot = scratch.finish(result)?;
    toolchain.accepted().verify_unchanged()?;
    verify_repository_revision(&repository, &revision)?;
    Ok(snapshot)
}

/// Build the selector-31 E3A production userspace closure. This deliberately
/// stops before ESP/VM handoff freezing; the dedicated E3A request producer
/// owns those paths and the partial-evidence grammar.
pub(crate) fn build_e3a_snapshot(nonce: &str) -> Result<E3ASnapshot, Failure> {
    validate_c6_nonce(nonce)?;
    reject_ambient_build_environment(env::vars_os())?;
    let repository = crate::tasks::repository_root()?;
    let project = crate::tasks::canonical_project_root(&repository)?;
    let revision = clean_repository_revision(&repository)?;
    let manifest = BuildManifest::load(&repository)?;
    if manifest.rust_revision()? != ACCEPTED_RUST_REVISION
        || manifest.rust_toolchain_name()? != ACCEPTED_TOOLCHAIN_NAME
    {
        return Err(Failure::task(
            "DW1-E3A product metadata does not name the accepted a92dc7f Rust toolchain",
        ));
    }
    let profile = manifest.validate_loader_build_readiness(&repository)?;
    let toolchain = crate::tasks::prepare_loader_toolchain(&repository, &profile, &manifest)?;
    let cargo_home = crate::tasks::project_cargo_home(&repository, &manifest)?;
    if env::var_os("CARGO_HOME").as_deref() != Some(cargo_home.as_os_str()) {
        return Err(Failure::task(
            "DW1-E3A product requires the pinned launcher's exact CARGO_HOME",
        ));
    }
    toolchain.accepted().verify_unchanged()?;
    let project_directory = crate::secure_fs::Directory::open_exact(&project, "OS-Project root")?;
    let tmp = match project_directory.open_child(".tmp", "project temporary root") {
        Ok(directory) => directory,
        Err(_) => project_directory.create_child(".tmp", 0o700, "project temporary root")?,
    };
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| Failure::task("system clock is before the Unix epoch"))?
        .as_nanos();
    let scratch = tmp.create_scratch(
        &format!("dw1e3a-build-{}-{unique}", std::process::id()),
        "DW1-E3A build scratch",
    )?;
    let result = (|| {
        let mut artifacts = Vec::with_capacity(E3A_PRODUCT_NATIVE_SPECS.len());
        for spec in E3A_PRODUCT_NATIVE_SPECS {
            toolchain.accepted().verify_unchanged()?;
            let artifact = scratch.with_inheritable_anchor("DW1-E3A build scratch", |anchor| {
                let mut artifact = build_native(
                    &repository,
                    &cargo_home,
                    toolchain.accepted(),
                    anchor,
                    spec,
                    Some(nonce),
                )?;
                artifact.inspection = inspect_native(
                    &repository,
                    &artifact.bytes,
                    &artifact.sha256,
                    spec.label,
                    anchor,
                )?;
                Ok(artifact)
            })?;
            artifacts.push(artifact);
        }
        let product = assemble_e3a_product(&revision, &artifacts, nonce)?;
        Ok(E3ASnapshot {
            rrc_manifest: product.rrc_manifest,
            device_manifest: product.device_manifest,
            bootfs: product.bootfs,
            artifacts: artifacts
                .iter()
                .map(|artifact| (artifact.spec.label.to_owned(), artifact.bytes.clone()))
                .collect(),
            inspections: artifacts
                .iter()
                .map(|artifact| {
                    (
                        artifact.spec.label.to_owned(),
                        artifact.inspection.as_bytes().to_vec(),
                    )
                })
                .collect(),
        })
    })();
    let snapshot = scratch.finish(result)?;
    toolchain.accepted().verify_unchanged()?;
    verify_repository_revision(&repository, &revision)?;
    Ok(snapshot)
}

/// Build the selector-32 production userspace closure.  This is a distinct
/// product from selector 31 and therefore never compiles or admits the DWE3
/// probe actor.
pub(crate) fn build_d5_snapshot(nonce: &str) -> Result<D5Snapshot, Failure> {
    validate_c6_nonce(nonce)?;
    reject_ambient_build_environment(env::vars_os())?;
    let repository = crate::tasks::repository_root()?;
    let project = crate::tasks::canonical_project_root(&repository)?;
    let revision = clean_repository_revision(&repository)?;
    let manifest = BuildManifest::load(&repository)?;
    if manifest.rust_revision()? != ACCEPTED_RUST_REVISION
        || manifest.rust_toolchain_name()? != ACCEPTED_TOOLCHAIN_NAME
    {
        return Err(Failure::task(
            "WYR1-D5 product metadata does not name the accepted a92dc7f Rust toolchain",
        ));
    }
    let profile = manifest.validate_loader_build_readiness(&repository)?;
    let toolchain = crate::tasks::prepare_loader_toolchain(&repository, &profile, &manifest)?;
    let cargo_home = crate::tasks::project_cargo_home(&repository, &manifest)?;
    if env::var_os("CARGO_HOME").as_deref() != Some(cargo_home.as_os_str()) {
        return Err(Failure::task(
            "WYR1-D5 product requires the pinned launcher's exact CARGO_HOME",
        ));
    }
    toolchain.accepted().verify_unchanged()?;
    let project_directory = crate::secure_fs::Directory::open_exact(&project, "OS-Project root")?;
    let tmp = match project_directory.open_child(".tmp", "project temporary root") {
        Ok(directory) => directory,
        Err(_) => project_directory.create_child(".tmp", 0o700, "project temporary root")?,
    };
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| Failure::task("system clock is before the Unix epoch"))?
        .as_nanos();
    let scratch = tmp.create_scratch(
        &format!("wyr1d5-build-{}-{unique}", std::process::id()),
        "WYR1-D5 build scratch",
    )?;
    let result = (|| {
        let mut artifacts = Vec::with_capacity(D5_PRODUCT_NATIVE_SPECS.len());
        for spec in D5_PRODUCT_NATIVE_SPECS {
            toolchain.accepted().verify_unchanged()?;
            let artifact = scratch.with_inheritable_anchor("WYR1-D5 build scratch", |anchor| {
                let mut artifact = build_native(
                    &repository,
                    &cargo_home,
                    toolchain.accepted(),
                    anchor,
                    spec,
                    None,
                )?;
                artifact.inspection = inspect_native(
                    &repository,
                    &artifact.bytes,
                    &artifact.sha256,
                    spec.label,
                    anchor,
                )?;
                Ok(artifact)
            })?;
            artifacts.push(artifact);
        }
        let (product, launch_policy) = assemble_d5_product(&revision, &artifacts, nonce)?;
        Ok(D5Snapshot {
            rrc_manifest: product.rrc_manifest,
            device_manifest: product.device_manifest,
            launch_policy,
            bootfs: product.bootfs,
            artifacts: artifacts
                .iter()
                .map(|artifact| (artifact.spec.label.to_owned(), artifact.bytes.clone()))
                .collect(),
            inspections: artifacts
                .iter()
                .map(|artifact| {
                    (
                        artifact.spec.label.to_owned(),
                        artifact.inspection.as_bytes().to_vec(),
                    )
                })
                .collect(),
        })
    })();
    let snapshot = scratch.finish(result)?;
    toolchain.accepted().verify_unchanged()?;
    verify_repository_revision(&repository, &revision)?;
    Ok(snapshot)
}

/// Build the normal selector-free WYR1-E product. The returned snapshot is
/// still unpublished; `wyr1e` owns the immutable directory and receipts.
pub(crate) fn build_e6_snapshot() -> Result<E6Snapshot, Failure> {
    reject_e6_ambient_build_environment(env::vars_os())?;
    let repository = crate::tasks::repository_root()?;
    let revision = clean_repository_revision(&repository)?;
    let manifest = BuildManifest::load(&repository)?;
    if manifest.rust_revision()? != ACCEPTED_RUST_REVISION
        || manifest.rust_toolchain_name()? != ACCEPTED_TOOLCHAIN_NAME
    {
        return Err(Failure::task(
            "WYR1-E6 product metadata does not name the accepted a92dc7f Rust toolchain",
        ));
    }
    let profile = manifest.validate_loader_build_readiness(&repository)?;
    let toolchain = crate::tasks::prepare_loader_toolchain(&repository, &profile, &manifest)?;
    let cargo_home = crate::tasks::project_cargo_home(&repository, &manifest)?;
    if env::var_os("CARGO_HOME").as_deref() != Some(cargo_home.as_os_str()) {
        return Err(Failure::task(
            "WYR1-E6 product requires the pinned launcher's exact CARGO_HOME",
        ));
    }
    toolchain.accepted().verify_unchanged()?;
    let deep_source =
        inspect_e6_dependency_source(&repository, &manifest, toolchain.accepted(), &cargo_home)?;
    let repository_directory =
        crate::secure_fs::Directory::open_exact(&repository, "Wyrmroot source")?;
    let tmp = match repository_directory.open_child(".tmp", "WYR1-E6 temporary root") {
        Ok(directory) => directory,
        Err(_) => repository_directory.create_child(".tmp", 0o700, "WYR1-E6 temporary root")?,
    };
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| Failure::task("system clock is before the Unix epoch"))?
        .as_nanos();
    let scratch = tmp.create_scratch(
        &format!("wyr1e6-build-{}-{unique}", std::process::id()),
        "WYR1-E6 build scratch",
    )?;
    let result = (|| {
        let mut artifacts = Vec::with_capacity(WYR1E6_PRODUCT_NATIVE_SPECS.len());
        let mut stack_report = None;
        for spec in WYR1E6_PRODUCT_NATIVE_SPECS {
            toolchain.accepted().verify_unchanged()?;
            deep_source.verify_unchanged()?;
            let artifact = scratch.with_inheritable_anchor("WYR1-E6 build scratch", |anchor| {
                let extra_flags = if spec.label == "wyrmsh" {
                    &["-Cjump-tables=no", "-Zemit-stack-sizes"][..]
                } else {
                    &[][..]
                };
                let mut artifact = build_native_with_flags(
                    &repository,
                    &cargo_home,
                    toolchain.accepted(),
                    anchor,
                    spec,
                    None,
                    NativeBuildOptions::exact(extra_flags),
                )?;
                artifact.inspection = inspect_native(
                    &repository,
                    &artifact.bytes,
                    &artifact.sha256,
                    spec.label,
                    anchor,
                )?;
                Ok(artifact)
            })?;
            if spec.label == "wyrmsh" {
                let stack_input = scratch.write_new_retained(
                    "wyrmsh.elf",
                    &artifact.bytes,
                    0o400,
                    "WYR1-E6 stack input",
                )?;
                stack_report = Some(run_wyrmsh_stack_analyzer(
                    &repository,
                    &scratch,
                    Path::new("wyrmsh.elf"),
                )?);
                scratch.verify_retained_file_exact(
                    "wyrmsh.elf",
                    &stack_input,
                    artifact.bytes.len() as u64,
                    0o400,
                    "WYR1-E6 stack input",
                )?;
            }
            artifacts.push(artifact);
        }
        let product = assemble_e6_product(&revision, &artifacts)?;
        Ok(E6Snapshot {
            wyrmroot_revision: revision.clone(),
            rrc_manifest: product.rrc_manifest,
            device_manifest: product.device_manifest,
            launch_policy: product.launch_policy,
            bootfs: product.bootfs,
            artifacts: artifacts
                .iter()
                .map(|artifact| (artifact.spec.label.to_owned(), artifact.bytes.clone()))
                .collect(),
            inspections: artifacts
                .iter()
                .map(|artifact| {
                    (
                        artifact.spec.label.to_owned(),
                        artifact.inspection.as_bytes().to_vec(),
                    )
                })
                .collect(),
            stack_report: stack_report
                .ok_or_else(|| Failure::task("WYR1-E6 build omitted the shell stack proof"))?,
        })
    })();
    let snapshot = scratch.finish(result)?;
    toolchain.accepted().verify_unchanged()?;
    deep_source.verify_unchanged()?;
    verify_repository_revision(&repository, &revision)?;
    Ok(snapshot)
}

/// Builds the selected E7 artifacts while reusing the remaining immutable E6
/// production payloads and exact shell stack proof supplied by the caller.
pub(crate) fn build_e7_snapshot(
    evidence_nonce: &str,
    e6: &E6Snapshot,
) -> Result<E7Snapshot, Failure> {
    validate_e7_nonce(evidence_nonce)?;
    let selected = build_selected_e_artifacts(
        "WYR1-E7",
        "wyr1e7",
        evidence_nonce,
        e6,
        &WYR1E7_SELECTED_NATIVE_SPECS,
        NativeBuildOptions::exact_wyr1e7(),
    )?;
    let product =
        reassemble_e7_snapshot(&selected.revision, &selected.artifacts, E7_MALFORMED_ELF)?;
    Ok(E7Snapshot {
        wyrmroot_revision: selected.revision,
        evidence_nonce: evidence_nonce.to_owned(),
        generation: product.generation,
        rrc_manifest: product.rrc_manifest,
        device_manifest: product.device_manifest,
        launch_policy: product.launch_policy,
        bootfs: product.bootfs,
        artifacts: selected.artifacts,
        inspections: selected.inspections,
        malformed_elf: E7_MALFORMED_ELF.to_vec(),
        stack_report: e6.stack_report.clone(),
    })
}

/// Builds the additive E8 artifact set from the accepted immutable E6 input.
/// E7 remains an acceptance ancestor and is not used as a product dependency.
pub(crate) fn build_e8_snapshot(
    evidence_nonce: &str,
    e6: &E6Snapshot,
) -> Result<E8Snapshot, Failure> {
    validate_e8_nonce(evidence_nonce)?;
    let selected = build_selected_e_artifacts(
        "WYR1-E8",
        "wyr1e8",
        evidence_nonce,
        e6,
        &WYR1E8_SELECTED_NATIVE_SPECS,
        NativeBuildOptions::exact_wyr1e8(),
    )?;
    let product =
        reassemble_e8_snapshot(&selected.revision, &selected.artifacts, E7_MALFORMED_ELF)?;
    Ok(E8Snapshot {
        wyrmroot_revision: selected.revision,
        evidence_nonce: evidence_nonce.to_owned(),
        generation: product.generation,
        rrc_manifest: product.rrc_manifest,
        device_manifest: product.device_manifest,
        launch_policy: product.launch_policy,
        bootfs: product.bootfs,
        artifacts: selected.artifacts,
        inspections: selected.inspections,
        malformed_elf: E7_MALFORMED_ELF.to_vec(),
        stack_report: e6.stack_report.clone(),
    })
}

struct SelectedEArtifacts {
    revision: String,
    artifacts: BTreeMap<String, Vec<u8>>,
    inspections: BTreeMap<String, Vec<u8>>,
}

fn build_selected_e_artifacts(
    phase: &str,
    slug: &str,
    evidence_nonce: &str,
    e6: &E6Snapshot,
    specs: &[NativeSpec],
    init_options: NativeBuildOptions<'static>,
) -> Result<SelectedEArtifacts, Failure> {
    reject_e6_ambient_build_environment(env::vars_os())?;
    let repository = crate::tasks::repository_root()?;
    let revision = clean_repository_revision(&repository)?;
    let manifest = BuildManifest::load(&repository)?;
    if manifest.rust_revision()? != ACCEPTED_RUST_REVISION
        || manifest.rust_toolchain_name()? != ACCEPTED_TOOLCHAIN_NAME
    {
        return Err(Failure::task(format!(
            "{phase} product metadata does not name the accepted a92dc7f Rust toolchain"
        )));
    }
    let profile = manifest.validate_loader_build_readiness(&repository)?;
    let toolchain = crate::tasks::prepare_loader_toolchain(&repository, &profile, &manifest)?;
    let cargo_home = crate::tasks::project_cargo_home(&repository, &manifest)?;
    if env::var_os("CARGO_HOME").as_deref() != Some(cargo_home.as_os_str()) {
        return Err(Failure::task(format!(
            "{phase} product requires the pinned launcher's exact CARGO_HOME"
        )));
    }
    toolchain.accepted().verify_unchanged()?;
    let deep_source =
        inspect_e6_dependency_source(&repository, &manifest, toolchain.accepted(), &cargo_home)?;
    let repository_directory =
        crate::secure_fs::Directory::open_exact(&repository, "Wyrmroot source")?;
    let tmp = match repository_directory.open_child(".tmp", &format!("{phase} temporary root")) {
        Ok(directory) => directory,
        Err(_) => {
            repository_directory.create_child(".tmp", 0o700, &format!("{phase} temporary root"))?
        }
    };
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| Failure::task("system clock is before the Unix epoch"))?
        .as_nanos();
    let scratch = tmp.create_scratch(
        &format!("{slug}-build-{}-{unique}", std::process::id()),
        &format!("{phase} build scratch"),
    )?;
    let result = (|| {
        let mut artifacts = e6.artifacts.clone();
        let mut inspections = e6.inspections.clone();
        for spec in specs {
            artifacts.remove(spec.label);
            inspections.remove(spec.label);
        }
        for spec in specs.iter().copied() {
            toolchain.accepted().verify_unchanged()?;
            deep_source.verify_unchanged()?;
            let artifact =
                scratch.with_inheritable_anchor(&format!("{phase} build scratch"), |anchor| {
                    let options = if spec.label == "system-init" {
                        init_options
                    } else {
                        NativeBuildOptions::exact(&[])
                    };
                    let mut artifact = build_native_with_flags(
                        &repository,
                        &cargo_home,
                        toolchain.accepted(),
                        anchor,
                        spec,
                        (spec.label == "system-init").then_some(evidence_nonce),
                        options,
                    )?;
                    artifact.inspection = inspect_native(
                        &repository,
                        &artifact.bytes,
                        &artifact.sha256,
                        spec.label,
                        anchor,
                    )?;
                    Ok(artifact)
                })?;
            artifacts.insert(spec.label.to_owned(), artifact.bytes);
            inspections.insert(spec.label.to_owned(), artifact.inspection.into_bytes());
        }
        Ok(SelectedEArtifacts {
            revision: revision.clone(),
            artifacts,
            inspections,
        })
    })();
    let snapshot = scratch.finish(result)?;
    toolchain.accepted().verify_unchanged()?;
    deep_source.verify_unchanged()?;
    verify_repository_revision(&repository, &revision)?;
    Ok(snapshot)
}

fn publish_snapshot(
    output: &crate::secure_fs::Directory,
    snapshot: &FrozenSnapshot,
) -> Result<FrozenPublication, Failure> {
    let artifacts = output.create_child("artifacts", 0o700, "WYR1-C1 artifacts")?;
    let inspections = output.create_child("inspections", 0o700, "WYR1-C1 inspections")?;
    let product = output.create_child("product", 0o700, "WYR1-C1 product")?;
    let mut artifact_files = BTreeMap::new();
    let mut inspection_files = BTreeMap::new();
    for spec in NATIVE_SPECS {
        let artifact = artifacts.write_new_retained(
            &format!("{}.elf", spec.label),
            snapshot
                .artifacts
                .get(spec.label)
                .ok_or_else(|| Failure::task("WYR1-C1 snapshot lacks an artifact"))?,
            0o400,
            "WYR1-C1 artifact",
        )?;
        artifact_files.insert(spec.label.to_owned(), artifact);
        let inspection = inspections.write_new_retained(
            &format!("{}.json", spec.label),
            snapshot
                .inspections
                .get(spec.label)
                .ok_or_else(|| Failure::task("WYR1-C1 snapshot lacks an inspection"))?,
            0o400,
            "WYR1-C1 inspection",
        )?;
        inspection_files.insert(spec.label.to_owned(), inspection);
    }
    let rrc_manifest = product.write_new_retained(
        "rrc-c1-v1.bin",
        &snapshot.rrc_manifest,
        0o400,
        "WYR1-C1 WRRM",
    )?;
    let device_manifest = product.write_new_retained(
        "wrdm-c1-v1.bin",
        &snapshot.device_manifest,
        0o400,
        "WYR1-C1 WRDM",
    )?;
    let bootfs =
        product.write_new_retained("bootfs.img", &snapshot.bootfs, 0o400, "WYR1-C1 bootfs")?;
    let receipt = product.write_new_retained(
        "build-receipt.toml",
        &snapshot.receipt,
        0o400,
        "WYR1-C1 receipt",
    )?;
    Ok(FrozenPublication {
        directories: FrozenDirectories {
            artifacts,
            inspections,
            product,
        },
        artifacts: artifact_files,
        inspections: inspection_files,
        rrc_manifest,
        device_manifest,
        bootfs,
        receipt,
    })
}

#[cfg(test)]
pub(crate) fn publish_snapshot_for_test(
    output: &crate::secure_fs::Directory,
    snapshot: &FrozenSnapshot,
) -> Result<FrozenPublication, Failure> {
    publish_snapshot(output, snapshot)
}

pub(crate) fn open_frozen_directories(
    output: &crate::secure_fs::Directory,
) -> Result<FrozenDirectories, Failure> {
    Ok(FrozenDirectories {
        artifacts: output.open_child("artifacts", "WYR1-C1 artifacts")?,
        inspections: output.open_child("inspections", "WYR1-C1 inspections")?,
        product: output.open_child("product", "WYR1-C1 product")?,
    })
}

pub(crate) fn open_frozen_publication(
    output: &crate::secure_fs::Directory,
) -> Result<FrozenPublication, Failure> {
    let directories = open_frozen_directories(output)?;
    let mut artifacts = BTreeMap::new();
    let mut inspections = BTreeMap::new();
    for spec in NATIVE_SPECS {
        artifacts.insert(
            spec.label.to_owned(),
            directories.artifacts.open_retained_file(
                &format!("{}.elf", spec.label),
                MAX_ARTIFACT_BYTES as u64,
                "WYR1-C1 artifact",
            )?,
        );
        inspections.insert(
            spec.label.to_owned(),
            directories.inspections.open_retained_file(
                &format!("{}.json", spec.label),
                MAX_REPORT_BYTES as u64,
                "WYR1-C1 inspection",
            )?,
        );
    }
    let rrc_manifest = directories.product.open_retained_file(
        "rrc-c1-v1.bin",
        MAX_REPORT_BYTES as u64,
        "WYR1-C1 WRRM",
    )?;
    let device_manifest = directories.product.open_retained_file(
        "wrdm-c1-v1.bin",
        MAX_REPORT_BYTES as u64,
        "WYR1-C1 WRDM",
    )?;
    let bootfs = directories.product.open_retained_file(
        "bootfs.img",
        MAX_BOOTFS_BYTES as u64,
        "WYR1-C1 bootfs",
    )?;
    let receipt = directories.product.open_retained_file(
        "build-receipt.toml",
        MAX_REPORT_BYTES as u64,
        "WYR1-C1 receipt",
    )?;
    Ok(FrozenPublication {
        directories,
        artifacts,
        inspections,
        rrc_manifest,
        device_manifest,
        bootfs,
        receipt,
    })
}

pub(crate) fn snapshot_from_publication(
    publication: &mut FrozenPublication,
) -> Result<FrozenSnapshot, Failure> {
    let mut artifact_bytes = BTreeMap::new();
    let mut inspection_bytes = BTreeMap::new();
    for spec in NATIVE_SPECS {
        artifact_bytes.insert(
            spec.label.to_owned(),
            publication.directories.artifacts.read_retained_exact(
                &format!("{}.elf", spec.label),
                publication
                    .artifacts
                    .get_mut(spec.label)
                    .ok_or_else(|| Failure::task("WYR1-C1 retained artifact is missing"))?,
                MAX_ARTIFACT_BYTES as u64,
                0o400,
                "WYR1-C1 artifact",
            )?,
        );
        inspection_bytes.insert(
            spec.label.to_owned(),
            publication.directories.inspections.read_retained_exact(
                &format!("{}.json", spec.label),
                publication
                    .inspections
                    .get_mut(spec.label)
                    .ok_or_else(|| Failure::task("WYR1-C1 retained inspection is missing"))?,
                MAX_REPORT_BYTES as u64,
                0o400,
                "WYR1-C1 inspection",
            )?,
        );
    }
    Ok(FrozenSnapshot {
        receipt: publication.directories.product.read_retained_exact(
            "build-receipt.toml",
            &mut publication.receipt,
            MAX_REPORT_BYTES as u64,
            0o400,
            "WYR1-C1 receipt",
        )?,
        rrc_manifest: publication.directories.product.read_retained_exact(
            "rrc-c1-v1.bin",
            &mut publication.rrc_manifest,
            MAX_REPORT_BYTES as u64,
            0o400,
            "WYR1-C1 WRRM",
        )?,
        device_manifest: publication.directories.product.read_retained_exact(
            "wrdm-c1-v1.bin",
            &mut publication.device_manifest,
            MAX_REPORT_BYTES as u64,
            0o400,
            "WYR1-C1 WRDM",
        )?,
        bootfs: publication.directories.product.read_retained_exact(
            "bootfs.img",
            &mut publication.bootfs,
            MAX_BOOTFS_BYTES as u64,
            0o400,
            "WYR1-C1 bootfs",
        )?,
        artifacts: artifact_bytes,
        inspections: inspection_bytes,
    })
}

pub(crate) fn verify_published_directories(
    output: &crate::secure_fs::Directory,
    directories: &FrozenDirectories,
) -> Result<(), Failure> {
    output.verify_child_identity(
        "artifacts",
        &directories.artifacts,
        0o700,
        "WYR1-C artifacts",
    )?;
    output.verify_child_identity(
        "inspections",
        &directories.inspections,
        0o700,
        "WYR1-C inspections",
    )?;
    output.verify_child_identity("product", &directories.product, 0o700, "WYR1-C product")?;
    Ok(())
}

pub(crate) fn accept_publication(
    repository: &Path,
    parent: &crate::secure_fs::Directory,
    parent_mode: u32,
    name: &str,
    output: &crate::secure_fs::Directory,
    publication: &mut FrozenPublication,
) -> Result<FrozenSnapshot, Failure> {
    verify_publication(parent, parent_mode, name, output, &publication.directories)?;
    let accepted = snapshot_from_publication(publication)?;
    validate_frozen_product(repository, &accepted)?;
    final_recheck_publication(output, publication, &accepted, || Ok(()))?;
    verify_publication(parent, parent_mode, name, output, &publication.directories)?;
    Ok(accepted)
}

fn final_recheck_publication(
    output: &crate::secure_fs::Directory,
    publication: &mut FrozenPublication,
    accepted: &FrozenSnapshot,
    hook: impl FnOnce() -> Result<(), Failure>,
) -> Result<(), Failure> {
    hook()?;
    let final_snapshot = snapshot_from_publication(publication)?;
    if &final_snapshot != accepted {
        return Err(Failure::task(
            "WYR1-C1 retained publication bytes changed after validation",
        ));
    }
    verify_published_directories(output, &publication.directories)
}

fn verify_publication(
    parent: &crate::secure_fs::Directory,
    parent_mode: u32,
    name: &str,
    output: &crate::secure_fs::Directory,
    directories: &FrozenDirectories,
) -> Result<(), Failure> {
    parent.verify_owned_container_path_mode(parent_mode, "WYR1-C1 output parent")?;
    parent.verify_child_identity(name, output, 0o700, "WYR1-C1 output")?;
    verify_published_directories(output, directories)
}

struct ProductBytes {
    generation: [u8; 32],
    rrc_manifest: Vec<u8>,
    rrc_manifest_sha256: String,
    device_manifest: Vec<u8>,
    device_manifest_sha256: String,
    bootfs: Vec<u8>,
    bootfs_sha256: String,
}

pub(crate) struct E6ProductBytes {
    pub(crate) generation: [u8; 32],
    pub(crate) rrc_manifest: Vec<u8>,
    pub(crate) device_manifest: Vec<u8>,
    pub(crate) launch_policy: Vec<u8>,
    pub(crate) bootfs: Vec<u8>,
}

pub(crate) struct E7ProductBytes {
    pub(crate) generation: [u8; 32],
    pub(crate) rrc_manifest: Vec<u8>,
    pub(crate) device_manifest: Vec<u8>,
    pub(crate) launch_policy: Vec<u8>,
    pub(crate) bootfs: Vec<u8>,
}

pub(crate) struct E8ProductBytes {
    pub(crate) generation: [u8; 32],
    pub(crate) rrc_manifest: Vec<u8>,
    pub(crate) device_manifest: Vec<u8>,
    pub(crate) launch_policy: Vec<u8>,
    pub(crate) bootfs: Vec<u8>,
}

fn assemble_product(revision: &str, artifacts: &[NativeArtifact]) -> Result<ProductBytes, Failure> {
    let [init, registryd, devmgr, uart, consoled, wyrmsh]: [&NativeArtifact; 6] = artifacts
        .iter()
        .collect::<Vec<_>>()
        .try_into()
        .map_err(|_| Failure::task("WYR1-C1 product requires exactly six native artifacts"))?;
    let role_hashes = [
        digest_array(&registryd.sha256)?,
        digest_array(&devmgr.sha256)?,
        digest_array(&uart.sha256)?,
        digest_array(&consoled.sha256)?,
        digest_array(&wyrmsh.sha256)?,
    ];
    let generation = product_generation(revision, artifacts);
    let rrc_manifest = crate::wyr1::fixed_builder_for_profiles(
        &generation,
        role_hashes,
        StartupProfile::BootstrapRegistry,
        StartupProfile::DeviceCoordinator,
    )?
    .build_structural()
    .map_err(|error| Failure::task(format!("WYR1-C1 WRRM build failed: {error:?}")))?;
    validate_rrc(&rrc_manifest, &generation, role_hashes)?;

    let mut wrdm = [0u8; WRDM_HEADER_BYTES + WRDM_RECORD_BYTES];
    let wrdm_size = encode_com2_manifest(ContentIdentity(role_hashes[2]), &mut wrdm)
        .map_err(|error| Failure::task(format!("WYR1-C1 WRDM build failed: {error:?}")))?;
    let device_manifest = wrdm[..wrdm_size].to_vec();
    let bootfs = build_c1(ProductC1 {
        base: Product {
            init: &init.bytes,
            registryd: &registryd.bytes,
            devmgr: &devmgr.bytes,
            uart16550d: &uart.bytes,
            consoled: &consoled.bytes,
            wyrmsh: &wyrmsh.bytes,
            rrc_manifest: &rrc_manifest,
            gate_config: GATE_CONFIG,
        },
        marker: WYR1_C1_MARKER,
        device_manifest: &device_manifest,
        expected_uart16550d_identity: role_hashes[2],
    })
    .map_err(|error| Failure::task(format!("WYR1-C1 bootfs build failed: {error:?}")))?;
    if bootfs.len() > MAX_BOOTFS_BYTES {
        return Err(Failure::task("WYR1-C1 bootfs exceeds the image bound"));
    }
    inspect_archive(&bootfs, artifacts, &rrc_manifest, &device_manifest)?;
    Ok(ProductBytes {
        generation,
        rrc_manifest_sha256: sha256::bytes_digest(&rrc_manifest),
        device_manifest_sha256: sha256::bytes_digest(&device_manifest),
        bootfs_sha256: sha256::bytes_digest(&bootfs),
        rrc_manifest,
        device_manifest,
        bootfs,
    })
}

fn assemble_e6_product(
    revision: &str,
    artifacts: &[NativeArtifact],
) -> Result<E6ProductBytes, Failure> {
    let [init, registryd, devmgr, uart, consoled, wyrmsh, hello]: [&NativeArtifact; 7] = artifacts
        .iter()
        .collect::<Vec<_>>()
        .try_into()
        .map_err(|_| Failure::task("WYR1-E6 requires seven explicit native artifacts"))?;
    let role_hashes = [
        digest_array(&registryd.sha256)?,
        digest_array(&devmgr.sha256)?,
        digest_array(&uart.sha256)?,
        digest_array(&consoled.sha256)?,
        digest_array(&wyrmsh.sha256)?,
    ];
    let generation = e6_product_generation(revision, artifacts);
    let builder = crate::wyr1::fixed_builder_for_wyrmsh(&generation, role_hashes)?;
    let structural_rrc = builder
        .build_structural()
        .map_err(|error| Failure::task(format!("WYR1-E6 WRRM build failed: {error:?}")))?;

    let mut wrdm = [0u8; WRDM_HEADER_BYTES + WRDM_RECORD_BYTES];
    let wrdm_size = encode_com2_manifest(ContentIdentity(role_hashes[2]), &mut wrdm)
        .map_err(|error| Failure::task(format!("WYR1-E6 WRDM build failed: {error:?}")))?;
    let device_manifest = wrdm[..wrdm_size].to_vec();
    let hello_identity = digest_array(&hello.sha256)?;
    let mut policy = [0u8; 512];
    let policy_size = encode_wyrmsh(
        generation,
        &[
            LaunchPolicyEntry {
                path: "bin/hello",
                content_sha256: hello_identity,
                startup_abi: 2,
                profile_id: JOB_V2_PROFILE_ID,
                allow_no_streams: false,
                allow_three_streams: true,
            },
            LaunchPolicyEntry {
                path: WYRMSH_PATH,
                content_sha256: role_hashes[4],
                startup_abi: 2,
                profile_id: WYRMSH_PROFILE_ID,
                allow_no_streams: false,
                allow_three_streams: true,
            },
        ],
        &mut policy,
    )
    .map_err(|error| Failure::task(format!("WYR1-E6 launch policy failed: {error:?}")))?;
    let launch_policy = policy[..policy_size].to_vec();
    let bootfs = build_e6(ProductE6 {
        base: ProductC1 {
            base: Product {
                init: &init.bytes,
                registryd: &registryd.bytes,
                devmgr: &devmgr.bytes,
                uart16550d: &uart.bytes,
                consoled: &consoled.bytes,
                wyrmsh: &wyrmsh.bytes,
                rrc_manifest: &structural_rrc,
                gate_config: GATE_CONFIG,
            },
            marker: WYR1_C1_MARKER,
            device_manifest: &device_manifest,
            expected_uart16550d_identity: role_hashes[2],
        },
        launch_policy: &launch_policy,
        hello: &hello.bytes,
        expected_wyrmsh_identity: role_hashes[4],
        expected_hello_identity: hello_identity,
    })
    .map_err(|error| Failure::task(format!("WYR1-E6 bootfs build failed: {error:?}")))?;
    if bootfs.len() > MAX_BOOTFS_BYTES {
        return Err(Failure::task("WYR1-E6 bootfs exceeds the image bound"));
    }
    let expected_closure = crate::wyr1::expected_closure_for_request(
        digest_array(&init.sha256)?,
        role_hashes,
        sha256::bytes_digest_array(GATE_CONFIG),
    );
    let observed = crate::wyr1::observe_closure_from_archive(&bootfs)?;
    let profile = Wyr1eProductProfile {
        base: crate::wyr1::product_profile_for_request(
            sha256::bytes_digest_array(&structural_rrc),
            sha256::bytes_digest_array(&structural_rrc),
            sha256::bytes_digest_array(&bootfs),
            sha256::bytes_digest_array(&bootfs),
            &expected_closure,
            &observed,
        ),
        production_wyrmsh_identity: role_hashes[4],
    };
    let admitted_rrc = builder
        .build_wyr1e_product(profile)
        .map_err(|error| Failure::task(format!("WYR1-E6 WRRM admission failed: {error:?}")))?;
    if admitted_rrc != structural_rrc {
        return Err(Failure::task(
            "WYR1-E6 admitted WRRM differs from its structural bytes",
        ));
    }
    Manifest::parse_wyr1e_product(&admitted_rrc, &generation, profile)
        .and_then(|manifest| manifest.validate_wyr1e_product(profile))
        .map_err(|error| Failure::task(format!("WYR1-E6 WRRM inspection failed: {error:?}")))?;
    inspect_e6_archive(
        &bootfs,
        artifacts,
        &admitted_rrc,
        &device_manifest,
        &launch_policy,
    )?;
    Ok(E6ProductBytes {
        generation,
        rrc_manifest: admitted_rrc,
        device_manifest,
        launch_policy,
        bootfs,
    })
}

pub(crate) fn reassemble_e6_snapshot(
    revision: &str,
    artifact_bytes: &BTreeMap<String, Vec<u8>>,
) -> Result<E6ProductBytes, Failure> {
    let mut artifacts = Vec::with_capacity(WYR1E6_PRODUCT_NATIVE_SPECS.len());
    for spec in WYR1E6_PRODUCT_NATIVE_SPECS {
        let bytes = artifact_bytes
            .get(spec.label)
            .ok_or_else(|| Failure::task(format!("WYR1-E6 snapshot lacks {}", spec.label)))?
            .clone();
        artifacts.push(NativeArtifact {
            spec,
            sha256: sha256::bytes_digest(&bytes),
            bytes,
            inspection: String::new(),
        });
    }
    assemble_e6_product(revision, &artifacts)
}

pub(crate) fn reassemble_e7_snapshot(
    revision: &str,
    artifact_bytes: &BTreeMap<String, Vec<u8>>,
    malformed_elf: &[u8],
) -> Result<E7ProductBytes, Failure> {
    let mut artifacts = Vec::with_capacity(E7_ARTIFACT_LABELS.len());
    for label in E7_ARTIFACT_LABELS {
        let spec = e7_native_spec(label)?;
        let bytes = artifact_bytes
            .get(label)
            .ok_or_else(|| Failure::task(format!("WYR1-E7 snapshot lacks {label}")))?
            .clone();
        artifacts.push(NativeArtifact {
            spec,
            sha256: sha256::bytes_digest(&bytes),
            bytes,
            inspection: String::new(),
        });
    }
    assemble_e7_product(revision, &artifacts, malformed_elf)
}

fn assemble_e7_product(
    revision: &str,
    artifacts: &[NativeArtifact],
    malformed_elf: &[u8],
) -> Result<E7ProductBytes, Failure> {
    let [
        init,
        registryd,
        devmgr,
        uart,
        consoled,
        wyrmsh,
        hello,
        cpu_hog,
        exit_nonzero,
        fault,
    ]: [&NativeArtifact; 10] = artifacts
        .iter()
        .collect::<Vec<_>>()
        .try_into()
        .map_err(|_| Failure::task("WYR1-E7 requires ten explicit native artifacts"))?;
    if malformed_elf != E7_MALFORMED_ELF {
        return Err(Failure::task(
            "WYR1-E7 malformed ELF bytes differ from the frozen fixture",
        ));
    }
    let role_hashes = [
        digest_array(&registryd.sha256)?,
        digest_array(&devmgr.sha256)?,
        digest_array(&uart.sha256)?,
        digest_array(&consoled.sha256)?,
        digest_array(&wyrmsh.sha256)?,
    ];
    let generation = e7_product_generation(revision, artifacts, malformed_elf);
    let builder = crate::wyr1::fixed_builder_for_wyrmsh(&generation, role_hashes)?;
    let structural_rrc = builder
        .build_structural()
        .map_err(|error| Failure::task(format!("WYR1-E7 WRRM build failed: {error:?}")))?;
    let mut wrdm = [0u8; WRDM_HEADER_BYTES + WRDM_RECORD_BYTES];
    let wrdm_size = encode_com2_manifest(ContentIdentity(role_hashes[2]), &mut wrdm)
        .map_err(|error| Failure::task(format!("WYR1-E7 WRDM build failed: {error:?}")))?;
    let device_manifest = wrdm[..wrdm_size].to_vec();
    let hello_identity = digest_array(&hello.sha256)?;
    let cpu_hog_identity = digest_array(&cpu_hog.sha256)?;
    let exit_nonzero_identity = digest_array(&exit_nonzero.sha256)?;
    let fault_identity = digest_array(&fault.sha256)?;
    let malformed_identity = sha256::bytes_digest_array(malformed_elf);
    let mut policy = [0u8; 1024];
    let policy_size = encode_wyrmsh(
        generation,
        &[
            LaunchPolicyEntry {
                path: CPU_HOG_PATH,
                content_sha256: cpu_hog_identity,
                startup_abi: 2,
                profile_id: JOB_V2_PROFILE_ID,
                allow_no_streams: true,
                allow_three_streams: false,
            },
            LaunchPolicyEntry {
                path: "bin/hello",
                content_sha256: hello_identity,
                startup_abi: 2,
                profile_id: JOB_V2_PROFILE_ID,
                allow_no_streams: false,
                allow_three_streams: true,
            },
            LaunchPolicyEntry {
                path: WYRMSH_PATH,
                content_sha256: role_hashes[4],
                startup_abi: 2,
                profile_id: WYRMSH_PROFILE_ID,
                allow_no_streams: false,
                allow_three_streams: true,
            },
            LaunchPolicyEntry {
                path: E7_EXIT_NONZERO_PATH,
                content_sha256: exit_nonzero_identity,
                startup_abi: 2,
                profile_id: JOB_V2_PROFILE_ID,
                allow_no_streams: false,
                allow_three_streams: true,
            },
            LaunchPolicyEntry {
                path: E7_FAULT_PATH,
                content_sha256: fault_identity,
                startup_abi: 2,
                profile_id: JOB_V2_PROFILE_ID,
                allow_no_streams: false,
                allow_three_streams: true,
            },
            LaunchPolicyEntry {
                path: E7_MALFORMED_ELF_PATH,
                content_sha256: malformed_identity,
                startup_abi: 2,
                profile_id: JOB_V2_PROFILE_ID,
                allow_no_streams: false,
                allow_three_streams: true,
            },
        ],
        &mut policy,
    )
    .map_err(|error| Failure::task(format!("WYR1-E7 launch policy failed: {error:?}")))?;
    let launch_policy = policy[..policy_size].to_vec();
    let bootfs = build_e7(ProductE7 {
        base: ProductC1 {
            base: Product {
                init: &init.bytes,
                registryd: &registryd.bytes,
                devmgr: &devmgr.bytes,
                uart16550d: &uart.bytes,
                consoled: &consoled.bytes,
                wyrmsh: &wyrmsh.bytes,
                rrc_manifest: &structural_rrc,
                gate_config: GATE_CONFIG,
            },
            marker: WYR1_C1_MARKER,
            device_manifest: &device_manifest,
            expected_uart16550d_identity: role_hashes[2],
        },
        launch_policy: &launch_policy,
        hello: &hello.bytes,
        cpu_hog: &cpu_hog.bytes,
        exit_nonzero: &exit_nonzero.bytes,
        fault: &fault.bytes,
        malformed_elf,
        expected_wyrmsh_identity: role_hashes[4],
        expected_hello_identity: hello_identity,
        expected_cpu_hog_identity: cpu_hog_identity,
        expected_exit_nonzero_identity: exit_nonzero_identity,
        expected_fault_identity: fault_identity,
        expected_malformed_elf_identity: malformed_identity,
    })
    .map_err(|error| Failure::task(format!("WYR1-E7 bootfs build failed: {error:?}")))?;
    if bootfs.len() > MAX_BOOTFS_BYTES {
        return Err(Failure::task("WYR1-E7 bootfs exceeds the image bound"));
    }
    let expected_closure = crate::wyr1::expected_closure_for_request(
        digest_array(&init.sha256)?,
        role_hashes,
        sha256::bytes_digest_array(GATE_CONFIG),
    );
    let observed = crate::wyr1::observe_closure_from_archive(&bootfs)?;
    let profile = Wyr1eProductProfile {
        base: crate::wyr1::product_profile_for_request(
            sha256::bytes_digest_array(&structural_rrc),
            sha256::bytes_digest_array(&structural_rrc),
            sha256::bytes_digest_array(&bootfs),
            sha256::bytes_digest_array(&bootfs),
            &expected_closure,
            &observed,
        ),
        production_wyrmsh_identity: role_hashes[4],
    };
    let admitted_rrc = builder
        .build_wyr1e_product(profile)
        .map_err(|error| Failure::task(format!("WYR1-E7 WRRM admission failed: {error:?}")))?;
    if admitted_rrc != structural_rrc {
        return Err(Failure::task(
            "WYR1-E7 admitted WRRM differs from its structural bytes",
        ));
    }
    Manifest::parse_wyr1e_product(&admitted_rrc, &generation, profile)
        .and_then(|manifest| manifest.validate_wyr1e_product(profile))
        .map_err(|error| Failure::task(format!("WYR1-E7 WRRM inspection failed: {error:?}")))?;
    inspect_e7_archive(
        &bootfs,
        artifacts,
        malformed_elf,
        &admitted_rrc,
        &device_manifest,
        &launch_policy,
    )?;
    Ok(E7ProductBytes {
        generation,
        rrc_manifest: admitted_rrc,
        device_manifest,
        launch_policy,
        bootfs,
    })
}

pub(crate) fn reassemble_e8_snapshot(
    revision: &str,
    artifact_bytes: &BTreeMap<String, Vec<u8>>,
    malformed_elf: &[u8],
) -> Result<E8ProductBytes, Failure> {
    let mut artifacts = Vec::with_capacity(E8_ARTIFACT_LABELS.len());
    for label in E8_ARTIFACT_LABELS {
        let spec = e8_native_spec(label)?;
        let bytes = artifact_bytes
            .get(label)
            .ok_or_else(|| Failure::task(format!("WYR1-E8 snapshot lacks {label}")))?
            .clone();
        artifacts.push(NativeArtifact {
            spec,
            sha256: sha256::bytes_digest(&bytes),
            bytes,
            inspection: String::new(),
        });
    }
    assemble_e8_product(revision, &artifacts, malformed_elf)
}

fn assemble_e8_product(
    revision: &str,
    artifacts: &[NativeArtifact],
    malformed_elf: &[u8],
) -> Result<E8ProductBytes, Failure> {
    let [
        init,
        registryd,
        devmgr,
        uart,
        consoled,
        wyrmsh,
        hello,
        cpu_hog,
        exit_nonzero,
        fault,
        recovery_trigger,
        stdout_pressure,
    ]: [&NativeArtifact; 12] = artifacts
        .iter()
        .collect::<Vec<_>>()
        .try_into()
        .map_err(|_| Failure::task("WYR1-E8 requires twelve explicit native artifacts"))?;
    if malformed_elf != E7_MALFORMED_ELF {
        return Err(Failure::task(
            "WYR1-E8 malformed ELF bytes differ from the inherited frozen fixture",
        ));
    }
    let role_hashes = [
        digest_array(&registryd.sha256)?,
        digest_array(&devmgr.sha256)?,
        digest_array(&uart.sha256)?,
        digest_array(&consoled.sha256)?,
        digest_array(&wyrmsh.sha256)?,
    ];
    let generation = e8_product_generation(revision, artifacts, malformed_elf);
    let builder = crate::wyr1::fixed_builder_for_wyrmsh(&generation, role_hashes)?;
    let structural_rrc = builder
        .build_structural()
        .map_err(|error| Failure::task(format!("WYR1-E8 WRRM build failed: {error:?}")))?;
    let mut wrdm = [0u8; WRDM_HEADER_BYTES + WRDM_RECORD_BYTES];
    let wrdm_size = encode_com2_manifest(ContentIdentity(role_hashes[2]), &mut wrdm)
        .map_err(|error| Failure::task(format!("WYR1-E8 WRDM build failed: {error:?}")))?;
    let device_manifest = wrdm[..wrdm_size].to_vec();
    let identities = [
        digest_array(&hello.sha256)?,
        digest_array(&cpu_hog.sha256)?,
        digest_array(&exit_nonzero.sha256)?,
        digest_array(&fault.sha256)?,
        sha256::bytes_digest_array(malformed_elf),
        digest_array(&recovery_trigger.sha256)?,
        digest_array(&stdout_pressure.sha256)?,
    ];
    let mut policy = [0u8; 1536];
    let policy_size = encode_wyrmsh(
        generation,
        &[
            LaunchPolicyEntry {
                path: CPU_HOG_PATH,
                content_sha256: identities[1],
                startup_abi: 2,
                profile_id: JOB_V2_PROFILE_ID,
                allow_no_streams: true,
                allow_three_streams: false,
            },
            LaunchPolicyEntry {
                path: "bin/hello",
                content_sha256: identities[0],
                startup_abi: 2,
                profile_id: JOB_V2_PROFILE_ID,
                allow_no_streams: false,
                allow_three_streams: true,
            },
            LaunchPolicyEntry {
                path: WYRMSH_PATH,
                content_sha256: role_hashes[4],
                startup_abi: 2,
                profile_id: WYRMSH_PROFILE_ID,
                allow_no_streams: false,
                allow_three_streams: true,
            },
            LaunchPolicyEntry {
                path: E7_EXIT_NONZERO_PATH,
                content_sha256: identities[2],
                startup_abi: 2,
                profile_id: JOB_V2_PROFILE_ID,
                allow_no_streams: false,
                allow_three_streams: true,
            },
            LaunchPolicyEntry {
                path: E7_FAULT_PATH,
                content_sha256: identities[3],
                startup_abi: 2,
                profile_id: JOB_V2_PROFILE_ID,
                allow_no_streams: false,
                allow_three_streams: true,
            },
            LaunchPolicyEntry {
                path: E7_MALFORMED_ELF_PATH,
                content_sha256: identities[4],
                startup_abi: 2,
                profile_id: JOB_V2_PROFILE_ID,
                allow_no_streams: false,
                allow_three_streams: true,
            },
            LaunchPolicyEntry {
                path: E8_RECOVERY_TRIGGER_PATH,
                content_sha256: identities[5],
                startup_abi: 2,
                profile_id: JOB_V2_PROFILE_ID,
                allow_no_streams: false,
                allow_three_streams: true,
            },
            LaunchPolicyEntry {
                path: E8_STDOUT_PRESSURE_PATH,
                content_sha256: identities[6],
                startup_abi: 2,
                profile_id: JOB_V2_PROFILE_ID,
                allow_no_streams: false,
                allow_three_streams: true,
            },
        ],
        &mut policy,
    )
    .map_err(|error| Failure::task(format!("WYR1-E8 launch policy failed: {error:?}")))?;
    let launch_policy = policy[..policy_size].to_vec();
    let bootfs = build_e8(ProductE8 {
        base: ProductC1 {
            base: Product {
                init: &init.bytes,
                registryd: &registryd.bytes,
                devmgr: &devmgr.bytes,
                uart16550d: &uart.bytes,
                consoled: &consoled.bytes,
                wyrmsh: &wyrmsh.bytes,
                rrc_manifest: &structural_rrc,
                gate_config: GATE_CONFIG,
            },
            marker: WYR1_C1_MARKER,
            device_manifest: &device_manifest,
            expected_uart16550d_identity: role_hashes[2],
        },
        launch_policy: &launch_policy,
        hello: &hello.bytes,
        cpu_hog: &cpu_hog.bytes,
        exit_nonzero: &exit_nonzero.bytes,
        fault: &fault.bytes,
        malformed_elf,
        recovery_trigger: &recovery_trigger.bytes,
        stdout_pressure: &stdout_pressure.bytes,
        expected_wyrmsh_identity: role_hashes[4],
        expected_hello_identity: identities[0],
        expected_cpu_hog_identity: identities[1],
        expected_exit_nonzero_identity: identities[2],
        expected_fault_identity: identities[3],
        expected_malformed_elf_identity: identities[4],
        expected_recovery_trigger_identity: identities[5],
        expected_stdout_pressure_identity: identities[6],
    })
    .map_err(|error| Failure::task(format!("WYR1-E8 bootfs build failed: {error:?}")))?;
    if bootfs.len() > MAX_BOOTFS_BYTES {
        return Err(Failure::task("WYR1-E8 bootfs exceeds the image bound"));
    }
    let expected_closure = crate::wyr1::expected_closure_for_request(
        digest_array(&init.sha256)?,
        role_hashes,
        sha256::bytes_digest_array(GATE_CONFIG),
    );
    let observed = crate::wyr1::observe_closure_from_archive(&bootfs)?;
    let profile = Wyr1eProductProfile {
        base: crate::wyr1::product_profile_for_request(
            sha256::bytes_digest_array(&structural_rrc),
            sha256::bytes_digest_array(&structural_rrc),
            sha256::bytes_digest_array(&bootfs),
            sha256::bytes_digest_array(&bootfs),
            &expected_closure,
            &observed,
        ),
        production_wyrmsh_identity: role_hashes[4],
    };
    let admitted_rrc = builder
        .build_wyr1e_product(profile)
        .map_err(|error| Failure::task(format!("WYR1-E8 WRRM admission failed: {error:?}")))?;
    if admitted_rrc != structural_rrc {
        return Err(Failure::task(
            "WYR1-E8 admitted WRRM differs from its structural bytes",
        ));
    }
    Manifest::parse_wyr1e_product(&admitted_rrc, &generation, profile)
        .and_then(|manifest| manifest.validate_wyr1e_product(profile))
        .map_err(|error| Failure::task(format!("WYR1-E8 WRRM inspection failed: {error:?}")))?;
    inspect_e8_archive(
        &bootfs,
        artifacts,
        malformed_elf,
        &admitted_rrc,
        &device_manifest,
        &launch_policy,
    )?;
    Ok(E8ProductBytes {
        generation,
        rrc_manifest: admitted_rrc,
        device_manifest,
        launch_policy,
        bootfs,
    })
}

#[allow(dead_code)]
fn assemble_c6_product(
    revision: &str,
    artifacts: &[NativeArtifact],
    nonce: &str,
) -> Result<ProductBytes, Failure> {
    let [init, registryd, devmgr, uart, consoled, wyrmsh]: [&NativeArtifact; 6] = artifacts
        .iter()
        .collect::<Vec<_>>()
        .try_into()
        .map_err(|_| Failure::task("WYR1-C6 requires six native artifacts"))?;
    let hashes = [
        digest_array(&registryd.sha256)?,
        digest_array(&devmgr.sha256)?,
        digest_array(&uart.sha256)?,
        digest_array(&consoled.sha256)?,
        digest_array(&wyrmsh.sha256)?,
    ];
    let generation = product_generation(revision, artifacts);
    let rrc_manifest = crate::wyr1::fixed_builder_for_profiles(
        &generation,
        hashes,
        StartupProfile::BootstrapRegistry,
        StartupProfile::DeviceCoordinator,
    )?
    .build_structural()
    .map_err(|error| Failure::task(format!("WYR1-C6 WRRM build failed: {error:?}")))?;
    let mut wrdm = [0u8; WRDM_HEADER_BYTES + WRDM_RECORD_BYTES];
    let size = encode_com2_manifest(ContentIdentity(hashes[2]), &mut wrdm)
        .map_err(|error| Failure::task(format!("WYR1-C6 WRDM build failed: {error:?}")))?;
    let device_manifest = wrdm[..size].to_vec();
    let gate = format!(
        "schema = 1\nselector = \"device-coordinator-restart\"\ntest_id = 29\nevidence_protocol = \"WRC6\"\nnonce = \"{nonce}\"\nphysical_io = \"not-performed\"\n"
    );
    let bootfs = build_c6(ProductC6 {
        base: ProductC1 {
            base: Product {
                init: &init.bytes,
                registryd: &registryd.bytes,
                devmgr: &devmgr.bytes,
                uart16550d: &uart.bytes,
                consoled: &consoled.bytes,
                wyrmsh: &wyrmsh.bytes,
                rrc_manifest: &rrc_manifest,
                gate_config: GATE_CONFIG,
            },
            marker: WYR1_C1_MARKER,
            device_manifest: &device_manifest,
            expected_uart16550d_identity: hashes[2],
        },
        gate: gate.as_bytes(),
    })
    .map_err(|error| Failure::task(format!("WYR1-C6 bootfs build failed: {error:?}")))?;
    validate_rrc(&rrc_manifest, &generation, hashes)?;
    wyrmroot_device_proto::Manifest::parse(&device_manifest)
        .and_then(|manifest| manifest.match_com2(ContentIdentity(hashes[2])))
        .map_err(|error| Failure::task(format!("WYR1-C6 WRDM inspection failed: {error:?}")))?;
    inspect_c6_archive(
        &bootfs,
        artifacts,
        &rrc_manifest,
        &device_manifest,
        gate.as_bytes(),
    )?;
    Ok(ProductBytes {
        generation,
        rrc_manifest_sha256: sha256::bytes_digest(&rrc_manifest),
        device_manifest_sha256: sha256::bytes_digest(&device_manifest),
        bootfs_sha256: sha256::bytes_digest(&bootfs),
        rrc_manifest,
        device_manifest,
        bootfs,
    })
}

fn assemble_e3a_product(
    revision: &str,
    artifacts: &[NativeArtifact],
    nonce: &str,
) -> Result<ProductBytes, Failure> {
    let [init, registryd, devmgr, uart, consoled, wyrmsh, probe]: [&NativeArtifact; 7] = artifacts
        .iter()
        .collect::<Vec<_>>()
        .try_into()
        .map_err(|_| Failure::task("DW1-E3A requires seven explicit native artifacts"))?;
    let hashes = [
        digest_array(&registryd.sha256)?,
        digest_array(&devmgr.sha256)?,
        digest_array(&uart.sha256)?,
        digest_array(&consoled.sha256)?,
        digest_array(&wyrmsh.sha256)?,
    ];
    let generation = product_generation(revision, &artifacts[..6]);
    let rrc_manifest = crate::wyr1::fixed_builder_for_profiles(
        &generation,
        hashes,
        StartupProfile::BootstrapRegistry,
        StartupProfile::DeviceCoordinator,
    )?
    .build_structural()
    .map_err(|error| Failure::task(format!("DW1-E3A WRRM build failed: {error:?}")))?;
    let mut wrdm = [0u8; WRDM_HEADER_BYTES + WRDM_RECORD_BYTES];
    let size = encode_com2_manifest(ContentIdentity(hashes[2]), &mut wrdm)
        .map_err(|error| Failure::task(format!("DW1-E3A WRDM build failed: {error:?}")))?;
    let device_manifest = wrdm[..size].to_vec();
    let gate = format!(
        "schema = 1\nselector = \"q35-com2-interrupt\"\ntest_id = 31\nevidence_protocol = \"DWE3E1\"\nnonce = \"{nonce}\"\npartial_evidence = true\nphysical_io = \"real-com2-irq3-intended\"\n"
    );
    let bootfs = build_e3a(ProductE3A {
        base: ProductC1 {
            base: Product {
                init: &init.bytes,
                registryd: &registryd.bytes,
                devmgr: &devmgr.bytes,
                uart16550d: &uart.bytes,
                consoled: &consoled.bytes,
                wyrmsh: &wyrmsh.bytes,
                rrc_manifest: &rrc_manifest,
                gate_config: GATE_CONFIG,
            },
            marker: WYR1_C1_MARKER,
            device_manifest: &device_manifest,
            expected_uart16550d_identity: hashes[2],
        },
        gate: gate.as_bytes(),
        raw_com2_probe: &probe.bytes,
    })
    .map_err(|error| Failure::task(format!("DW1-E3A bootfs build failed: {error:?}")))?;
    validate_rrc(&rrc_manifest, &generation, hashes)?;
    wyrmroot_device_proto::Manifest::parse(&device_manifest)
        .and_then(|manifest| manifest.match_com2(ContentIdentity(hashes[2])))
        .map_err(|error| Failure::task(format!("DW1-E3A WRDM inspection failed: {error:?}")))?;
    inspect_e3a_archive(
        &bootfs,
        artifacts,
        &rrc_manifest,
        &device_manifest,
        gate.as_bytes(),
    )?;
    Ok(ProductBytes {
        generation,
        rrc_manifest_sha256: sha256::bytes_digest(&rrc_manifest),
        device_manifest_sha256: sha256::bytes_digest(&device_manifest),
        bootfs_sha256: sha256::bytes_digest(&bootfs),
        rrc_manifest,
        device_manifest,
        bootfs,
    })
}

fn assemble_d5_product(
    revision: &str,
    artifacts: &[NativeArtifact],
    nonce: &str,
) -> Result<(ProductBytes, Vec<u8>), Failure> {
    let [
        init,
        registryd,
        devmgr,
        uart,
        consoled,
        wyrmsh,
        console_echo,
    ]: [&NativeArtifact; 7] = artifacts
        .iter()
        .collect::<Vec<_>>()
        .try_into()
        .map_err(|_| Failure::task("WYR1-D5 requires seven explicit native artifacts"))?;
    let hashes = [
        digest_array(&registryd.sha256)?,
        digest_array(&devmgr.sha256)?,
        digest_array(&uart.sha256)?,
        digest_array(&consoled.sha256)?,
        digest_array(&wyrmsh.sha256)?,
    ];
    let generation = product_generation(revision, artifacts);
    let rrc_manifest = crate::wyr1::fixed_builder_for_profiles(
        &generation,
        hashes,
        StartupProfile::BootstrapRegistry,
        StartupProfile::DeviceCoordinator,
    )?
    .build_structural()
    .map_err(|error| Failure::task(format!("WYR1-D5 WRRM build failed: {error:?}")))?;
    let mut wrdm = [0u8; WRDM_HEADER_BYTES + WRDM_RECORD_BYTES];
    let size = encode_com2_manifest(ContentIdentity(hashes[2]), &mut wrdm)
        .map_err(|error| Failure::task(format!("WYR1-D5 WRDM build failed: {error:?}")))?;
    let device_manifest = wrdm[..size].to_vec();
    let mut policy = [0u8; 512];
    let policy_size = encode_launch_policy(
        generation,
        &[LaunchPolicyEntry {
            path: CONSOLE_ECHO_PATH,
            content_sha256: digest_array(&console_echo.sha256)?,
            startup_abi: 2,
            profile_id: 1,
            allow_no_streams: false,
            allow_three_streams: true,
        }],
        &mut policy,
    )
    .map_err(|error| Failure::task(format!("WYR1-D5 launch policy failed: {error:?}")))?;
    let launch_policy = policy[..policy_size].to_vec();
    let gate = format!(
        "schema = 1\nselector = \"native-console-streams\"\ntest_id = 32\nevidence_protocol = \"WRD1\"\nnonce = \"{nonce}\"\n"
    );
    let bootfs = build_d5(ProductD5 {
        base: ProductC1 {
            base: Product {
                init: &init.bytes,
                registryd: &registryd.bytes,
                devmgr: &devmgr.bytes,
                uart16550d: &uart.bytes,
                consoled: &consoled.bytes,
                wyrmsh: &wyrmsh.bytes,
                rrc_manifest: &rrc_manifest,
                gate_config: GATE_CONFIG,
            },
            marker: WYR1_C1_MARKER,
            device_manifest: &device_manifest,
            expected_uart16550d_identity: hashes[2],
        },
        gate: gate.as_bytes(),
        launch_policy: &launch_policy,
        console_echo: &console_echo.bytes,
    })
    .map_err(|error| Failure::task(format!("WYR1-D5 bootfs build failed: {error:?}")))?;
    validate_rrc(&rrc_manifest, &generation, hashes)?;
    wyrmroot_device_proto::Manifest::parse(&device_manifest)
        .and_then(|manifest| manifest.match_com2(ContentIdentity(hashes[2])))
        .map_err(|error| Failure::task(format!("WYR1-D5 WRDM inspection failed: {error:?}")))?;
    let parsed_policy = LaunchPolicy::parse(&launch_policy).map_err(|error| {
        Failure::task(format!(
            "WYR1-D5 launch-policy inspection failed: {error:?}"
        ))
    })?;
    let entry = parsed_policy
        .find(CONSOLE_ECHO_PATH)
        .ok_or_else(|| Failure::task("WYR1-D5 launch policy lacks console-echo"))?;
    if parsed_policy.len() != 1
        || parsed_policy.boot_generation_sha256() != generation
        || entry.content_sha256 != digest_array(&console_echo.sha256)?
        || entry.allow_no_streams
        || !entry.allow_three_streams
    {
        return Err(Failure::task("WYR1-D5 launch-policy authority drifted"));
    }
    inspect_d5_archive(
        &bootfs,
        artifacts,
        &rrc_manifest,
        &device_manifest,
        &launch_policy,
        gate.as_bytes(),
    )?;
    Ok((
        ProductBytes {
            generation,
            rrc_manifest_sha256: sha256::bytes_digest(&rrc_manifest),
            device_manifest_sha256: sha256::bytes_digest(&device_manifest),
            bootfs_sha256: sha256::bytes_digest(&bootfs),
            rrc_manifest,
            device_manifest,
            bootfs,
        },
        launch_policy,
    ))
}

fn build_native(
    repository: &Path,
    cargo_home: &Path,
    toolchain: &crate::toolchain_artifact::AcceptedToolchain,
    build_directory: &InheritableDirectory,
    spec: NativeSpec,
    evidence_nonce: Option<&str>,
) -> Result<NativeArtifact, Failure> {
    build_native_with_flags(
        repository,
        cargo_home,
        toolchain,
        build_directory,
        spec,
        evidence_nonce,
        NativeBuildOptions::historical(),
    )
}

#[derive(Clone, Copy)]
struct NativeBuildOptions<'a> {
    extra_flags: &'a [&'a str],
    exact_environment: bool,
    evidence_variable: &'static str,
}

impl NativeBuildOptions<'_> {
    const fn historical() -> Self {
        Self {
            extra_flags: &[],
            exact_environment: false,
            evidence_variable: "DEEPWYRM_DW1E_EVIDENCE_NONCE",
        }
    }

    const fn exact(extra_flags: &'static [&'static str]) -> Self {
        Self {
            extra_flags,
            exact_environment: true,
            evidence_variable: "DEEPWYRM_DW1E_EVIDENCE_NONCE",
        }
    }

    const fn exact_wyr1e7() -> Self {
        Self::exact_with_evidence("WYRMROOT_WYR1E7_EVIDENCE_NONCE")
    }

    const fn exact_wyr1e8() -> Self {
        Self::exact_with_evidence("WYRMROOT_WYR1E8_EVIDENCE_NONCE")
    }

    const fn exact_with_evidence(evidence_variable: &'static str) -> Self {
        Self {
            extra_flags: &[],
            exact_environment: true,
            evidence_variable,
        }
    }
}

fn build_native_with_flags(
    repository: &Path,
    cargo_home: &Path,
    toolchain: &crate::toolchain_artifact::AcceptedToolchain,
    build_directory: &InheritableDirectory,
    spec: NativeSpec,
    evidence_nonce: Option<&str>,
    options: NativeBuildOptions<'_>,
) -> Result<NativeArtifact, Failure> {
    let target = build_directory.path().join(spec.label);
    fs::create_dir(&target)
        .map_err(|error| Failure::task(format!("could not create native target: {error}")))?;
    let exact_temp = target.join(".tmp");
    if options.exact_environment {
        fs::create_dir(&exact_temp).map_err(|error| {
            Failure::task(format!(
                "could not create E6 native temporary directory: {error}"
            ))
        })?;
        fs::set_permissions(&exact_temp, fs::Permissions::from_mode(0o700)).map_err(|error| {
            Failure::task(format!(
                "could not seal E6 native temporary directory: {error}"
            ))
        })?;
    }
    let mut flags = native_remap_flags(repository, cargo_home, &target)?;
    for flag in options.extra_flags {
        flags.push('\u{1f}');
        flags.push_str(flag);
    }
    let arguments = [
        "build",
        "--offline",
        "--locked",
        "--release",
        "--target",
        NATIVE_TARGET,
        "--package",
        spec.package,
        "--bin",
        spec.binary,
        "--no-default-features",
        "--features",
        spec.features,
    ];
    build_directory.verify_unchanged("WYR1-C1 build scratch")?;
    let mut command = Command::new(&toolchain.cargo);
    if options.exact_environment {
        let cargo_bin = toolchain
            .cargo
            .parent()
            .ok_or_else(|| Failure::task("accepted Cargo has no parent directory"))?;
        let path = env::join_paths([
            cargo_bin,
            Path::new("/usr/lib/llvm/22/bin"),
            Path::new("/usr/bin"),
            Path::new("/bin"),
        ])
        .map_err(|_| Failure::task("accepted Cargo path cannot be encoded for subprocess use"))?;
        command.env_clear().env("PATH", path).env("LC_ALL", "C");
        command.env("TMPDIR", &exact_temp);
    }
    command
        .args(arguments)
        .arg("--target-dir")
        .arg(&target)
        .env("RUSTC", &toolchain.rustc)
        .env("CARGO_HOME", cargo_home)
        .env("CARGO_ENCODED_RUSTFLAGS", flags)
        .env("CARGO_INCREMENTAL", "0")
        .env("CARGO_NET_OFFLINE", "true")
        .env("SOURCE_DATE_EPOCH", "0")
        .env_remove("LD_AUDIT")
        .env_remove("LD_LIBRARY_PATH")
        .env_remove("LD_PRELOAD")
        .current_dir(repository)
        .stdin(Stdio::null());
    if let Some(nonce) = evidence_nonce {
        command.env(options.evidence_variable, nonce);
    } else {
        command.env_remove(options.evidence_variable);
    }
    for variable in [
        "DEEPWYRM_DW1E_EVIDENCE_NONCE",
        "WYRMROOT_WYR1E7_EVIDENCE_NONCE",
        "WYRMROOT_WYR1E8_EVIDENCE_NONCE",
    ] {
        if variable != options.evidence_variable {
            command.env_remove(variable);
        }
    }
    let status = command.status();
    build_directory.verify_unchanged("WYR1-C1 build scratch")?;
    let status = status
        .map_err(|error| Failure::task(format!("could not build {}: {error}", spec.label)))?;
    if !status.success() {
        return Err(Failure::task(format!(
            "WYR1-C1 canonical {} build failed",
            spec.label
        )));
    }
    let artifact = PathBuf::from(spec.label)
        .join(NATIVE_TARGET)
        .join("release")
        .join(spec.artifact);
    let bytes = build_directory.read_producer(&artifact, MAX_ARTIFACT_BYTES as u64, spec.label)?;
    let sha256 = sha256::bytes_digest(&bytes);
    Ok(NativeArtifact {
        spec,
        bytes,
        sha256,
        inspection: String::new(),
    })
}

fn run_wyrmsh_stack_analyzer(
    repository: &Path,
    build_directory: &crate::secure_fs::Directory,
    elf: &Path,
) -> Result<Vec<u8>, Failure> {
    run_wyrmsh_stack_analyzer_path(
        repository,
        build_directory,
        &build_directory.path().join(elf),
    )
}

fn run_wyrmsh_stack_analyzer_path(
    repository: &Path,
    build_directory: &crate::secure_fs::Directory,
    elf: &Path,
) -> Result<Vec<u8>, Failure> {
    let report = PathBuf::from("wyrmsh-stack.json");
    build_directory.verify_owned_container_path_mode(0o700, "WYR1-E6 analyzer scratch")?;
    let output = Command::new("/usr/bin/python3")
        .arg(repository.join("tools/wyrmsh-native-stack.py"))
        .arg("--elf")
        .arg(elf)
        .arg("--report")
        .arg(build_directory.path().join(&report))
        .current_dir(repository)
        .env_clear()
        .env("PATH", crate::tasks::INSPECTION_PATH)
        .env("TMPDIR", build_directory.path())
        .stdin(Stdio::null())
        .output()
        .map_err(|error| Failure::task(format!("could not run Wyrmsh stack proof: {error}")))?;
    build_directory.verify_owned_container_path_mode(0o700, "WYR1-E6 analyzer scratch")?;
    if !output.status.success() {
        let detail = String::from_utf8_lossy(&output.stderr);
        return Err(Failure::task(format!(
            "WYR1-E6 Wyrmsh stack proof failed{}",
            if detail.trim().is_empty() {
                String::new()
            } else {
                format!("; stderr: {}", detail.trim())
            }
        )));
    }
    let mut report_file = build_directory.open_retained_file(
        "wyrmsh-stack.json",
        MAX_REPORT_BYTES as u64,
        "WYR1-E6 stack report",
    )?;
    let bytes = build_directory.read_retained_exact(
        "wyrmsh-stack.json",
        &mut report_file,
        MAX_REPORT_BYTES as u64,
        0o644,
        "WYR1-E6 stack report",
    )?;
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| Failure::task("WYR1-E6 stack report is not UTF-8"))?;
    if !text.contains("\"kind\": \"wyrmsh-native-stack-v1\"")
        || !text.contains("\"status\": \"pass\"")
    {
        return Err(Failure::task(
            "WYR1-E6 stack analyzer did not emit a passing v1 report",
        ));
    }
    Ok(bytes)
}

pub(crate) fn validate_e6_artifact_reports(
    repository: &Path,
    artifacts: &BTreeMap<String, Vec<u8>>,
    inspections: &BTreeMap<String, Vec<u8>>,
    expected_stack_report: &[u8],
) -> Result<(), Failure> {
    if artifacts.len() != WYR1E6_PRODUCT_NATIVE_SPECS.len()
        || inspections.len() != WYR1E6_PRODUCT_NATIVE_SPECS.len()
    {
        return Err(Failure::task("WYR1-E6 artifact or inspection set drifted"));
    }
    for spec in WYR1E6_PRODUCT_NATIVE_SPECS {
        let bytes = artifacts
            .get(spec.label)
            .ok_or_else(|| Failure::task(format!("WYR1-E6 lacks {}", spec.label)))?;
        let digest = sha256::bytes_digest(bytes);
        let expected = inspect_native_bytes(repository, bytes, &digest, spec.label)?;
        if inspections.get(spec.label).map(Vec::as_slice) != Some(expected.as_bytes()) {
            return Err(Failure::task(format!(
                "WYR1-E6 {} inspection was not recomputed exactly",
                spec.label
            )));
        }
    }
    validate_wyrmsh_stack_report(repository, artifacts, expected_stack_report, "WYR1-E6")
}

fn validate_wyrmsh_stack_report(
    repository: &Path,
    artifacts: &BTreeMap<String, Vec<u8>>,
    expected_stack_report: &[u8],
    phase: &str,
) -> Result<(), Failure> {
    let shell = artifacts
        .get("wyrmsh")
        .ok_or_else(|| Failure::task(format!("{phase} lacks wyrmsh")))?;
    let repository_directory =
        crate::secure_fs::Directory::open_exact(repository, "Wyrmroot source")?;
    let tmp = match repository_directory.open_child(".tmp", "WYR1-E6 temporary root") {
        Ok(directory) => directory,
        Err(_) => repository_directory.create_child(".tmp", 0o700, "WYR1-E6 temporary root")?,
    };
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| Failure::task("system clock is before the Unix epoch"))?
        .as_nanos();
    let scratch = tmp.create_scratch(
        &format!("wyr1e6-inspect-{}-{unique}", std::process::id()),
        "WYR1-E6 inspection scratch",
    )?;
    let shell_file =
        scratch.write_new_retained("wyrmsh.elf", shell, 0o400, "WYR1-E6 stack input")?;
    let result =
        run_wyrmsh_stack_analyzer_path(repository, &scratch, &scratch.path().join("wyrmsh.elf"));
    scratch.verify_retained_file_exact(
        "wyrmsh.elf",
        &shell_file,
        shell.len() as u64,
        0o400,
        "WYR1-E6 stack input",
    )?;
    let actual_stack_report = scratch.finish(result)?;
    if actual_stack_report != expected_stack_report {
        return Err(Failure::task(format!(
            "{phase} stack proof was not reproduced byte-for-byte"
        )));
    }
    Ok(())
}

pub(crate) fn validate_e7_artifact_reports(
    repository: &Path,
    artifacts: &BTreeMap<String, Vec<u8>>,
    inspections: &BTreeMap<String, Vec<u8>>,
    malformed_elf: &[u8],
    expected_stack_report: &[u8],
) -> Result<(), Failure> {
    if artifacts.len() != E7_ARTIFACT_LABELS.len()
        || inspections.len() != E7_ARTIFACT_LABELS.len()
        || malformed_elf != E7_MALFORMED_ELF
    {
        return Err(Failure::task("WYR1-E7 artifact set drifted"));
    }
    let mut e6_artifacts = BTreeMap::new();
    let mut e6_inspections = BTreeMap::new();
    for label in E6_ARTIFACT_LABELS {
        e6_artifacts.insert(
            label.to_owned(),
            artifacts
                .get(label)
                .ok_or_else(|| Failure::task(format!("WYR1-E7 lacks {label}")))?
                .clone(),
        );
        e6_inspections.insert(
            label.to_owned(),
            inspections
                .get(label)
                .ok_or_else(|| Failure::task(format!("WYR1-E7 lacks {label} inspection")))?
                .clone(),
        );
    }
    validate_e6_artifact_reports(
        repository,
        &e6_artifacts,
        &e6_inspections,
        expected_stack_report,
    )?;
    for label in ["cpu-hog", "exit-nonzero", "fault"] {
        let bytes = artifacts
            .get(label)
            .ok_or_else(|| Failure::task(format!("WYR1-E7 lacks {label}")))?;
        let digest = sha256::bytes_digest(bytes);
        let expected = inspect_native_bytes(repository, bytes, &digest, label)?;
        if inspections.get(label).map(Vec::as_slice) != Some(expected.as_bytes()) {
            return Err(Failure::task(format!(
                "WYR1-E7 {label} inspection was not recomputed exactly"
            )));
        }
    }
    Ok(())
}

pub(crate) fn validate_e8_artifact_reports(
    repository: &Path,
    artifacts: &BTreeMap<String, Vec<u8>>,
    inspections: &BTreeMap<String, Vec<u8>>,
    malformed_elf: &[u8],
    expected_stack_report: &[u8],
) -> Result<(), Failure> {
    if artifacts.len() != E8_ARTIFACT_LABELS.len()
        || inspections.len() != E8_ARTIFACT_LABELS.len()
        || malformed_elf != E7_MALFORMED_ELF
    {
        return Err(Failure::task("WYR1-E8 artifact set drifted"));
    }
    for label in E8_ARTIFACT_LABELS {
        let bytes = artifacts
            .get(label)
            .ok_or_else(|| Failure::task(format!("WYR1-E8 lacks {label}")))?;
        let digest = sha256::bytes_digest(bytes);
        let expected = inspect_native_bytes(repository, bytes, &digest, label)?;
        if inspections.get(label).map(Vec::as_slice) != Some(expected.as_bytes()) {
            return Err(Failure::task(format!(
                "WYR1-E8 {label} inspection was not recomputed exactly"
            )));
        }
    }
    validate_wyrmsh_stack_report(repository, artifacts, expected_stack_report, "WYR1-E8")
}

fn native_remap_flags(
    repository: &Path,
    cargo_home: &Path,
    target: &Path,
) -> Result<String, Failure> {
    let repository = fs::canonicalize(repository)
        .map_err(|error| Failure::task(format!("could not resolve source root: {error}")))?;
    let cargo_home = fs::canonicalize(cargo_home)
        .map_err(|error| Failure::task(format!("could not resolve Cargo home: {error}")))?;
    let target = fs::canonicalize(target)
        .map_err(|error| Failure::task(format!("could not resolve target root: {error}")))?;
    Ok([
        format!(
            "--remap-path-prefix={}=/source/wyrmroot",
            repository.display()
        ),
        format!("--remap-path-prefix={}=/cargo-home", cargo_home.display()),
        format!("--remap-path-prefix={}=/cargo-target", target.display()),
    ]
    .join("\u{1f}"))
}

fn inspect_native(
    repository: &Path,
    bytes: &[u8],
    expected_sha256: &str,
    label: &str,
    build_directory: &InheritableDirectory,
) -> Result<String, Failure> {
    build_directory.with_inheritance_disabled("WYR1-C1 build scratch", || {
        inspect_native_bytes(repository, bytes, expected_sha256, label)
    })
}

pub(crate) fn inspect_native_bytes(
    repository: &Path,
    bytes: &[u8],
    expected_sha256: &str,
    label: &str,
) -> Result<String, Failure> {
    let sealed = SealedFile::from_bytes(bytes, &format!("WYR1-C {label}"))?;
    let output = sealed.with_inheritable_path(&format!("WYR1-C {label}"), |artifact| {
        run_native_inspector(
            repository,
            &repository.join("toolchain/inspect-native-artifact.sh"),
            artifact,
            label,
        )
    })?;
    if !output.status.success()
        || output.stdout.is_empty()
        || output.stdout.len() > MAX_REPORT_BYTES
        || output.stderr.len() > MAX_REPORT_BYTES
    {
        return Err(Failure::task(format!(
            "WYR1-C canonical inspection failed for {label}"
        )));
    }
    let report = String::from_utf8(output.stdout)
        .map_err(|_| Failure::task("WYR1-C native inspection report is not UTF-8"))?;
    validate_inspection(&report, label, expected_sha256, bytes.len())?;
    Ok(report)
}

fn run_native_inspector(
    repository: &Path,
    script: &Path,
    artifact: &Path,
    label: &str,
) -> Result<Output, Failure> {
    Command::new(crate::tasks::INSPECTION_SHELL)
        .arg(script)
        .arg(artifact)
        .current_dir(repository)
        .env_clear()
        .env("PATH", crate::tasks::INSPECTION_PATH)
        .env("WYRMROOT_INSPECTION_ARTIFACT_NAME", label)
        .env("WYRMROOT_SEALED_INSPECTION", "1")
        .stdin(Stdio::null())
        .output()
        .map_err(|error| Failure::task(format!("could not inspect WYR1-C1 {label}: {error}")))
}

#[cfg(test)]
pub(crate) fn run_native_inspector_environment_probe(
    repository: &Path,
    script: &Path,
) -> Result<String, Failure> {
    let output = run_native_inspector(repository, script, Path::new("/dev/null"), "probe")?;
    if !output.status.success() {
        return Err(Failure::task(
            "WYR1-C1 native inspector environment probe failed",
        ));
    }
    String::from_utf8(output.stdout)
        .map_err(|_| Failure::task("WYR1-C1 native inspector environment probe is not UTF-8"))
}

fn validate_rrc(
    bytes: &[u8],
    generation: &[u8; 32],
    identities: [[u8; 32]; 5],
) -> Result<(), Failure> {
    let manifest = Manifest::parse_structural(bytes, generation)
        .map_err(|error| Failure::task(format!("WYR1-C1 WRRM inspection failed: {error:?}")))?;
    for (index, (id, profile)) in [
        (RoleId::Registryd, StartupProfile::BootstrapRegistry),
        (RoleId::Devmgr, StartupProfile::DeviceCoordinator),
        (RoleId::Uart16550d, StartupProfile::Retained),
        (RoleId::Consoled, StartupProfile::Retained),
        (RoleId::Wyrmsh, StartupProfile::Retained),
    ]
    .into_iter()
    .enumerate()
    {
        let role = manifest
            .role(id)
            .ok_or_else(|| Failure::task("WYR1-C1 WRRM lost a canonical role"))?;
        if role.startup_profile() != profile || role.executable_identity() != &identities[index] {
            return Err(Failure::task("WYR1-C1 WRRM role/profile identity drifted"));
        }
    }
    Ok(())
}

fn inspect_archive(
    bytes: &[u8],
    artifacts: &[NativeArtifact],
    rrc_manifest: &[u8],
    device_manifest: &[u8],
) -> Result<(), Failure> {
    let archive = Archive::new(bytes)
        .map_err(|error| Failure::task(format!("WYR1-C1 bootfs inspection failed: {error:?}")))?;
    let expected = [
        ("system/init", artifacts[0].bytes.as_slice()),
        ("system/registryd", artifacts[1].bytes.as_slice()),
        ("system/devmgr", artifacts[2].bytes.as_slice()),
        ("system/uart16550d", artifacts[3].bytes.as_slice()),
        ("system/consoled", artifacts[4].bytes.as_slice()),
        ("system/wyrmsh", artifacts[5].bytes.as_slice()),
        ("system/bootstrap/rrc-a-v1", rrc_manifest),
        ("system/bootstrap/wyr1-a-gate-v1", GATE_CONFIG),
        ("system/bootstrap/wyr1-c-gate-v1", WYR1_C1_MARKER),
        (
            "system/bootstrap/wyr1-c-device-manifest-v1",
            device_manifest,
        ),
    ];
    if archive.entries().count() != expected.len() {
        return Err(Failure::task("WYR1-C1 bootfs entry set drifted"));
    }
    for (path, expected_bytes) in expected {
        let entry = archive
            .lookup(path.as_bytes())
            .map_err(|_| Failure::task(format!("WYR1-C1 bootfs is missing {path}")))?;
        if entry.data() != expected_bytes {
            return Err(Failure::task(format!("WYR1-C1 bootfs changed {path}")));
        }
    }
    Ok(())
}

fn inspect_c6_archive(
    bytes: &[u8],
    artifacts: &[NativeArtifact],
    rrc: &[u8],
    wrdm: &[u8],
    gate: &[u8],
) -> Result<(), Failure> {
    let archive = Archive::new(bytes)
        .map_err(|error| Failure::task(format!("WYR1-C6 bootfs inspection failed: {error:?}")))?;
    if archive.entries().count() != 11 {
        return Err(Failure::task("WYR1-C6 bootfs entry set drifted"));
    }
    let expected = [
        ("system/init", artifacts[0].bytes.as_slice(), true),
        ("system/registryd", artifacts[1].bytes.as_slice(), true),
        ("system/devmgr", artifacts[2].bytes.as_slice(), true),
        ("system/uart16550d", artifacts[3].bytes.as_slice(), true),
        ("system/consoled", artifacts[4].bytes.as_slice(), true),
        ("system/wyrmsh", artifacts[5].bytes.as_slice(), true),
        ("system/bootstrap/rrc-a-v1", rrc, false),
        ("system/bootstrap/wyr1-a-gate-v1", GATE_CONFIG, false),
        ("system/bootstrap/wyr1-c-gate-v1", WYR1_C1_MARKER, false),
        ("system/bootstrap/wyr1-c-device-manifest-v1", wrdm, false),
        ("system/bootstrap/wyr1-c6-gate-v1", gate, false),
    ];
    for (path, expected_bytes, executable) in expected {
        let entry = archive
            .lookup(path.as_bytes())
            .map_err(|_| Failure::task(format!("WYR1-C6 bootfs lacks {path}")))?;
        if entry.data() != expected_bytes || entry.is_executable() != executable {
            return Err(Failure::task(format!("WYR1-C6 bootfs changed {path}")));
        }
    }
    Ok(())
}

fn inspect_e3a_archive(
    bytes: &[u8],
    artifacts: &[NativeArtifact],
    rrc: &[u8],
    wrdm: &[u8],
    gate: &[u8],
) -> Result<(), Failure> {
    let archive = Archive::new(bytes)
        .map_err(|error| Failure::task(format!("DW1-E3A bootfs inspection failed: {error:?}")))?;
    if archive.entries().count() != 12 {
        return Err(Failure::task("DW1-E3A bootfs entry set drifted"));
    }
    let expected = [
        ("system/init", artifacts[0].bytes.as_slice(), true),
        ("system/registryd", artifacts[1].bytes.as_slice(), true),
        ("system/devmgr", artifacts[2].bytes.as_slice(), true),
        ("system/uart16550d", artifacts[3].bytes.as_slice(), true),
        ("system/consoled", artifacts[4].bytes.as_slice(), true),
        ("system/wyrmsh", artifacts[5].bytes.as_slice(), true),
        (DW1_E3A_COM2_PROBE_PATH, artifacts[6].bytes.as_slice(), true),
        ("system/bootstrap/rrc-a-v1", rrc, false),
        ("system/bootstrap/wyr1-a-gate-v1", GATE_CONFIG, false),
        ("system/bootstrap/wyr1-c-gate-v1", WYR1_C1_MARKER, false),
        ("system/bootstrap/wyr1-c-device-manifest-v1", wrdm, false),
        (DW1_E3A_GATE_PATH, gate, false),
    ];
    for (path, expected_bytes, executable) in expected {
        let entry = archive
            .lookup(path.as_bytes())
            .map_err(|_| Failure::task(format!("DW1-E3A bootfs lacks {path}")))?;
        if entry.data() != expected_bytes || entry.is_executable() != executable {
            return Err(Failure::task(format!("DW1-E3A bootfs changed {path}")));
        }
    }
    Ok(())
}

fn inspect_d5_archive(
    bytes: &[u8],
    artifacts: &[NativeArtifact],
    rrc: &[u8],
    wrdm: &[u8],
    launch_policy: &[u8],
    gate: &[u8],
) -> Result<(), Failure> {
    let archive = Archive::new(bytes)
        .map_err(|error| Failure::task(format!("WYR1-D5 bootfs inspection failed: {error:?}")))?;
    if archive.entries().count() != 13 {
        return Err(Failure::task("WYR1-D5 bootfs entry set drifted"));
    }
    let expected = [
        ("system/init", artifacts[0].bytes.as_slice(), true),
        ("system/registryd", artifacts[1].bytes.as_slice(), true),
        ("system/devmgr", artifacts[2].bytes.as_slice(), true),
        ("system/uart16550d", artifacts[3].bytes.as_slice(), true),
        ("system/consoled", artifacts[4].bytes.as_slice(), true),
        ("system/wyrmsh", artifacts[5].bytes.as_slice(), true),
        (CONSOLE_ECHO_PATH, artifacts[6].bytes.as_slice(), true),
        ("system/bootstrap/rrc-a-v1", rrc, false),
        ("system/bootstrap/wyr1-a-gate-v1", GATE_CONFIG, false),
        ("system/bootstrap/wyr1-c-gate-v1", WYR1_C1_MARKER, false),
        ("system/bootstrap/wyr1-c-device-manifest-v1", wrdm, false),
        (LAUNCH_POLICY_PATH, launch_policy, false),
        (WYR1_D5_GATE_PATH, gate, false),
    ];
    for (path, expected_bytes, executable) in expected {
        let entry = archive
            .lookup(path.as_bytes())
            .map_err(|_| Failure::task(format!("WYR1-D5 bootfs lacks {path}")))?;
        if entry.data() != expected_bytes || entry.is_executable() != executable {
            return Err(Failure::task(format!("WYR1-D5 bootfs changed {path}")));
        }
    }
    if archive.lookup(DW1_E3A_GATE_PATH.as_bytes()).is_ok()
        || archive.lookup(DW1_E3A_COM2_PROBE_PATH.as_bytes()).is_ok()
    {
        return Err(Failure::task("WYR1-D5 bootfs inherited selector31 content"));
    }
    Ok(())
}

fn inspect_e6_archive(
    bytes: &[u8],
    artifacts: &[NativeArtifact],
    rrc: &[u8],
    wrdm: &[u8],
    launch_policy: &[u8],
) -> Result<(), Failure> {
    let archive = Archive::new(bytes)
        .map_err(|error| Failure::task(format!("WYR1-E6 bootfs inspection failed: {error:?}")))?;
    let expected = [
        ("system/init", artifacts[0].bytes.as_slice(), true),
        ("system/registryd", artifacts[1].bytes.as_slice(), true),
        ("system/devmgr", artifacts[2].bytes.as_slice(), true),
        ("system/uart16550d", artifacts[3].bytes.as_slice(), true),
        ("system/consoled", artifacts[4].bytes.as_slice(), true),
        ("system/wyrmsh", artifacts[5].bytes.as_slice(), true),
        ("system/bootstrap/rrc-a-v1", rrc, false),
        ("system/bootstrap/wyr1-a-gate-v1", GATE_CONFIG, false),
        ("system/bootstrap/wyr1-c-gate-v1", WYR1_C1_MARKER, false),
        ("system/bootstrap/wyr1-c-device-manifest-v1", wrdm, false),
        (LAUNCH_POLICY_PATH, launch_policy, false),
        ("bin/hello", artifacts[6].bytes.as_slice(), true),
    ];
    if archive.entries().count() != expected.len() {
        return Err(Failure::task("WYR1-E6 bootfs entry set drifted"));
    }
    for (path, expected_bytes, executable) in expected {
        let entry = archive
            .lookup(path.as_bytes())
            .map_err(|_| Failure::task(format!("WYR1-E6 bootfs lacks {path}")))?;
        if entry.data() != expected_bytes || entry.is_executable() != executable {
            return Err(Failure::task(format!("WYR1-E6 bootfs changed {path}")));
        }
    }
    Ok(())
}

fn inspect_e7_archive(
    bytes: &[u8],
    artifacts: &[NativeArtifact],
    malformed_elf: &[u8],
    rrc: &[u8],
    wrdm: &[u8],
    launch_policy: &[u8],
) -> Result<(), Failure> {
    let archive = Archive::new(bytes)
        .map_err(|error| Failure::task(format!("WYR1-E7 bootfs inspection failed: {error:?}")))?;
    let expected = [
        ("system/init", artifacts[0].bytes.as_slice(), true),
        ("system/registryd", artifacts[1].bytes.as_slice(), true),
        ("system/devmgr", artifacts[2].bytes.as_slice(), true),
        ("system/uart16550d", artifacts[3].bytes.as_slice(), true),
        ("system/consoled", artifacts[4].bytes.as_slice(), true),
        ("system/wyrmsh", artifacts[5].bytes.as_slice(), true),
        ("system/bootstrap/rrc-a-v1", rrc, false),
        ("system/bootstrap/wyr1-a-gate-v1", GATE_CONFIG, false),
        ("system/bootstrap/wyr1-c-gate-v1", WYR1_C1_MARKER, false),
        ("system/bootstrap/wyr1-c-device-manifest-v1", wrdm, false),
        (LAUNCH_POLICY_PATH, launch_policy, false),
        ("bin/hello", artifacts[6].bytes.as_slice(), true),
        (CPU_HOG_PATH, artifacts[7].bytes.as_slice(), true),
        (E7_EXIT_NONZERO_PATH, artifacts[8].bytes.as_slice(), true),
        (E7_FAULT_PATH, artifacts[9].bytes.as_slice(), true),
        (E7_MALFORMED_ELF_PATH, malformed_elf, true),
    ];
    if archive.entries().count() != expected.len() {
        return Err(Failure::task("WYR1-E7 bootfs entry set drifted"));
    }
    for (path, expected_bytes, executable) in expected {
        let entry = archive
            .lookup(path.as_bytes())
            .map_err(|_| Failure::task(format!("WYR1-E7 bootfs lacks {path}")))?;
        if entry.data() != expected_bytes || entry.is_executable() != executable {
            return Err(Failure::task(format!("WYR1-E7 bootfs changed {path}")));
        }
    }
    if archive.lookup(b"system/bootstrap/wyr1-e7-gate-v1").is_ok()
        || archive.lookup(CONSOLE_ECHO_PATH.as_bytes()).is_ok()
        || archive.lookup(WYR1_D5_GATE_PATH.as_bytes()).is_ok()
    {
        return Err(Failure::task(
            "WYR1-E7 bootfs inherited an unfrozen selector entry",
        ));
    }
    Ok(())
}

fn inspect_e8_archive(
    bytes: &[u8],
    artifacts: &[NativeArtifact],
    malformed_elf: &[u8],
    rrc: &[u8],
    wrdm: &[u8],
    launch_policy: &[u8],
) -> Result<(), Failure> {
    let archive = Archive::new(bytes)
        .map_err(|error| Failure::task(format!("WYR1-E8 bootfs inspection failed: {error:?}")))?;
    let expected = [
        ("system/init", artifacts[0].bytes.as_slice(), true),
        ("system/registryd", artifacts[1].bytes.as_slice(), true),
        ("system/devmgr", artifacts[2].bytes.as_slice(), true),
        ("system/uart16550d", artifacts[3].bytes.as_slice(), true),
        ("system/consoled", artifacts[4].bytes.as_slice(), true),
        ("system/wyrmsh", artifacts[5].bytes.as_slice(), true),
        ("system/bootstrap/rrc-a-v1", rrc, false),
        ("system/bootstrap/wyr1-a-gate-v1", GATE_CONFIG, false),
        ("system/bootstrap/wyr1-c-gate-v1", WYR1_C1_MARKER, false),
        ("system/bootstrap/wyr1-c-device-manifest-v1", wrdm, false),
        (LAUNCH_POLICY_PATH, launch_policy, false),
        ("bin/hello", artifacts[6].bytes.as_slice(), true),
        (CPU_HOG_PATH, artifacts[7].bytes.as_slice(), true),
        (E7_EXIT_NONZERO_PATH, artifacts[8].bytes.as_slice(), true),
        (E7_FAULT_PATH, artifacts[9].bytes.as_slice(), true),
        (E7_MALFORMED_ELF_PATH, malformed_elf, true),
        (
            E8_RECOVERY_TRIGGER_PATH,
            artifacts[10].bytes.as_slice(),
            true,
        ),
        (
            E8_STDOUT_PRESSURE_PATH,
            artifacts[11].bytes.as_slice(),
            true,
        ),
    ];
    if archive.entries().count() != expected.len() {
        return Err(Failure::task("WYR1-E8 bootfs entry set drifted"));
    }
    for (path, expected_bytes, executable) in expected {
        let entry = archive
            .lookup(path.as_bytes())
            .map_err(|_| Failure::task(format!("WYR1-E8 bootfs lacks {path}")))?;
        if entry.data() != expected_bytes || entry.is_executable() != executable {
            return Err(Failure::task(format!("WYR1-E8 bootfs changed {path}")));
        }
    }
    if archive.lookup(b"system/bootstrap/wyr1-e7-gate-v1").is_ok()
        || archive.lookup(b"system/bootstrap/wyr1-e8-gate-v1").is_ok()
        || archive.lookup(CONSOLE_ECHO_PATH.as_bytes()).is_ok()
        || archive.lookup(WYR1_D5_GATE_PATH.as_bytes()).is_ok()
    {
        return Err(Failure::task(
            "WYR1-E8 bootfs inherited an unfrozen selector entry",
        ));
    }
    Ok(())
}

fn validate_c6_nonce(nonce: &str) -> Result<(), Failure> {
    if nonce.len() != 16
        || !nonce
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'A'..=b'F'))
        || nonce.bytes().all(|byte| byte == b'0')
    {
        return Err(Failure::task(
            "WYR1-C6 gate nonce must be 16 nonzero uppercase hexadecimal characters",
        ));
    }
    Ok(())
}

fn render_receipt(
    revision: &str,
    manifest: &BuildManifest,
    toolchain: &crate::toolchain_artifact::AcceptedToolchain,
    product: &ProductBytes,
    artifacts: &[NativeArtifact],
) -> Result<String, Failure> {
    let mut receipt = format!(
        "kind = \"{RECEIPT_KIND}\"\nschema_version = {SCHEMA_VERSION}\nproduct_kind = \"{PRODUCT_KIND}\"\nselector = \"none\"\nevidence = \"not-produced\"\nwyrmroot_revision = \"{revision}\"\ncargo_lock_sha256 = \"{}\"\nrust_revision = \"{}\"\nrust_toolchain_name = \"{}\"\nrustc_sha256 = \"{}\"\ncargo_sha256 = \"{}\"\nrust_lld_sha256 = \"{}\"\ntoolchain_manifest_sha256 = \"{}\"\ntoolchain_tree_sha256 = \"{}\"\nboot_generation = \"{}\"\nrrc_manifest_path = \"product/rrc-c1-v1.bin\"\nrrc_manifest_sha256 = \"{}\"\ndevice_manifest_path = \"product/wrdm-c1-v1.bin\"\ndevice_manifest_sha256 = \"{}\"\nbootfs_path = \"product/bootfs.img\"\nbootfs_sha256 = \"{}\"\nbootfs_bytes = {}\n",
        sha256::file_digest(&crate::tasks::repository_root()?.join("Cargo.lock"))
            .map_err(|error| Failure::task(format!("could not hash Cargo.lock: {error}")))?,
        manifest.rust_revision()?,
        manifest.rust_toolchain_name()?,
        sha256::file_digest(&toolchain.rustc)
            .map_err(|error| Failure::task(format!("could not hash accepted rustc: {error}")))?,
        toolchain.cargo_sha256,
        toolchain.rust_lld_sha256,
        toolchain.manifest_sha256,
        toolchain.toolchain_tree_sha256,
        hex_digest(&product.generation),
        product.rrc_manifest_sha256,
        product.device_manifest_sha256,
        product.bootfs_sha256,
        product.bootfs.len(),
    );
    for artifact in artifacts {
        receipt.push_str(&format!(
            "{}_path = \"artifacts/{}.elf\"\n{}_sha256 = \"{}\"\n{}_command = \"{}\"\n{}_inspection_sha256 = \"{}\"\n",
            artifact.spec.label,
            artifact.spec.label,
            artifact.spec.label,
            artifact.sha256,
            artifact.spec.label,
            native_command(artifact.spec),
            artifact.spec.label,
            sha256::bytes_digest(artifact.inspection.as_bytes()),
        ));
    }
    Ok(receipt)
}

pub(crate) fn validate_frozen_product(
    repository: &Path,
    snapshot: &FrozenSnapshot,
) -> Result<ValidatedFrozenProduct, Failure> {
    let receipt_text = std::str::from_utf8(&snapshot.receipt)
        .map_err(|_| Failure::task("WYR1-C1 receipt is not UTF-8"))?;
    let receipt = parse_receipt(receipt_text)?;
    let expected_keys = c1_receipt_keys();
    if receipt.keys().cloned().collect::<BTreeSet<_>>() != expected_keys {
        return Err(Failure::task("WYR1-C1 receipt key set drifted"));
    }
    for (key, expected) in [
        ("kind", RECEIPT_KIND),
        ("schema_version", "1"),
        ("product_kind", PRODUCT_KIND),
        ("selector", "none"),
        ("evidence", "not-produced"),
        ("rust_revision", ACCEPTED_RUST_REVISION),
        ("rust_toolchain_name", ACCEPTED_TOOLCHAIN_NAME),
        ("rrc_manifest_path", "product/rrc-c1-v1.bin"),
        ("device_manifest_path", "product/wrdm-c1-v1.bin"),
        ("bootfs_path", "product/bootfs.img"),
    ] {
        if receipt.get(key).map(String::as_str) != Some(expected) {
            return Err(Failure::task(format!("WYR1-C1 receipt {key} drifted")));
        }
    }

    let revision = receipt
        .get("wyrmroot_revision")
        .ok_or_else(|| Failure::task("WYR1-C1 receipt lacks Wyrmroot revision"))?
        .clone();
    validate_revision(&revision, "Wyrmroot")?;
    validate_commit(repository, &revision, "Wyrmroot")?;
    let cargo_lock = git_file(repository, &revision, "Cargo.lock")?;
    if receipt.get("cargo_lock_sha256") != Some(&sha256::bytes_digest(&cargo_lock)) {
        return Err(Failure::task(
            "WYR1-C1 receipt Cargo.lock hash is not from its declared revision",
        ));
    }

    let manifest = BuildManifest::load(repository)?;
    if manifest.rust_revision()? != ACCEPTED_RUST_REVISION
        || manifest.rust_toolchain_name()? != ACCEPTED_TOOLCHAIN_NAME
    {
        return Err(Failure::task(
            "current metadata lost the accepted C1 toolchain tuple",
        ));
    }
    let profile = manifest.validate_loader_build_readiness(repository)?;
    let toolchain = crate::tasks::prepare_loader_toolchain(repository, &profile, &manifest)?;
    toolchain.accepted().verify_unchanged()?;
    for (key, actual) in [
        ("rustc_sha256", toolchain.accepted().rustc_sha256.as_str()),
        ("cargo_sha256", toolchain.accepted().cargo_sha256.as_str()),
        (
            "rust_lld_sha256",
            toolchain.accepted().rust_lld_sha256.as_str(),
        ),
        (
            "toolchain_manifest_sha256",
            toolchain.accepted().manifest_sha256.as_str(),
        ),
        (
            "toolchain_tree_sha256",
            toolchain.accepted().toolchain_tree_sha256.as_str(),
        ),
    ] {
        if receipt.get(key).map(String::as_str) != Some(actual) {
            return Err(Failure::task(format!("WYR1-C1 receipt {key} drifted")));
        }
    }

    let mut artifacts = Vec::with_capacity(NATIVE_SPECS.len());
    for spec in NATIVE_SPECS {
        let bytes = snapshot
            .artifacts
            .get(spec.label)
            .ok_or_else(|| Failure::task("WYR1-C1 snapshot lacks a native artifact"))?
            .clone();
        let inspection_bytes = snapshot
            .inspections
            .get(spec.label)
            .ok_or_else(|| Failure::task("WYR1-C1 snapshot lacks an inspection"))?;
        let digest = sha256::bytes_digest(&bytes);
        let expected_path = format!("artifacts/{}.elf", spec.label);
        if receipt.get(&format!("{}_path", spec.label)) != Some(&expected_path)
            || receipt.get(&format!("{}_sha256", spec.label)) != Some(&digest)
            || receipt.get(&format!("{}_command", spec.label)) != Some(&native_command(spec))
            || receipt.get(&format!("{}_inspection_sha256", spec.label))
                != Some(&sha256::bytes_digest(inspection_bytes))
        {
            return Err(Failure::task(format!(
                "WYR1-C1 {} receipt binding drifted",
                spec.label
            )));
        }
        let inspection = std::str::from_utf8(inspection_bytes)
            .map_err(|_| Failure::task("WYR1-C1 inspection is not UTF-8"))?
            .to_owned();
        validate_inspection(&inspection, spec.label, &digest, bytes.len())?;
        artifacts.push(NativeArtifact {
            spec,
            bytes,
            sha256: digest,
            inspection,
        });
    }

    for (key, bytes) in [
        ("rrc_manifest_sha256", snapshot.rrc_manifest.as_slice()),
        (
            "device_manifest_sha256",
            snapshot.device_manifest.as_slice(),
        ),
        ("bootfs_sha256", snapshot.bootfs.as_slice()),
    ] {
        if receipt.get(key) != Some(&sha256::bytes_digest(bytes)) {
            return Err(Failure::task(format!("WYR1-C1 {key} drifted")));
        }
    }
    if receipt.get("bootfs_bytes") != Some(&snapshot.bootfs.len().to_string()) {
        return Err(Failure::task("WYR1-C1 bootfs byte count drifted"));
    }
    let generation = product_generation(&revision, &artifacts);
    if receipt.get("boot_generation") != Some(&hex_digest(&generation)) {
        return Err(Failure::task("WYR1-C1 boot generation was not recomputed"));
    }
    validate_rrc(
        &snapshot.rrc_manifest,
        &generation,
        [
            digest_array(&artifacts[1].sha256)?,
            digest_array(&artifacts[2].sha256)?,
            digest_array(&artifacts[3].sha256)?,
            digest_array(&artifacts[4].sha256)?,
            digest_array(&artifacts[5].sha256)?,
        ],
    )?;
    let uart_identity = digest_array(&artifacts[3].sha256)?;
    wyrmroot_device_proto::Manifest::parse(&snapshot.device_manifest)
        .and_then(|manifest| manifest.match_com2(ContentIdentity(uart_identity)))
        .map_err(|error| Failure::task(format!("WYR1-C1 WRDM failed inspection: {error:?}")))?;
    inspect_archive(
        &snapshot.bootfs,
        &artifacts,
        &snapshot.rrc_manifest,
        &snapshot.device_manifest,
    )?;
    if snapshot.receipt != canonical_c1_receipt(&receipt)?.as_bytes() {
        return Err(Failure::task("WYR1-C1 receipt is not canonically rendered"));
    }
    Ok(ValidatedFrozenProduct {
        wyrmroot_revision: revision,
    })
}

fn canonical_c1_receipt(values: &BTreeMap<String, String>) -> Result<String, Failure> {
    let mut output = String::new();
    for key in [
        "kind",
        "schema_version",
        "product_kind",
        "selector",
        "evidence",
        "wyrmroot_revision",
        "cargo_lock_sha256",
        "rust_revision",
        "rust_toolchain_name",
        "rustc_sha256",
        "cargo_sha256",
        "rust_lld_sha256",
        "toolchain_manifest_sha256",
        "toolchain_tree_sha256",
        "boot_generation",
        "rrc_manifest_path",
        "rrc_manifest_sha256",
        "device_manifest_path",
        "device_manifest_sha256",
        "bootfs_path",
        "bootfs_sha256",
        "bootfs_bytes",
    ] {
        let value = values
            .get(key)
            .ok_or_else(|| Failure::task("WYR1-C1 receipt lost a canonical field"))?;
        if matches!(key, "schema_version" | "bootfs_bytes") {
            output.push_str(&format!("{key} = {value}\n"));
        } else {
            output.push_str(&format!("{key} = \"{value}\"\n"));
        }
    }
    for spec in NATIVE_SPECS {
        for suffix in ["path", "sha256", "command", "inspection_sha256"] {
            let key = format!("{}_{suffix}", spec.label);
            let value = values
                .get(&key)
                .ok_or_else(|| Failure::task("WYR1-C1 receipt lost an artifact field"))?;
            output.push_str(&format!("{key} = \"{value}\"\n"));
        }
    }
    Ok(output)
}

fn c1_receipt_keys() -> BTreeSet<String> {
    let mut keys = [
        "kind",
        "schema_version",
        "product_kind",
        "selector",
        "evidence",
        "wyrmroot_revision",
        "cargo_lock_sha256",
        "rust_revision",
        "rust_toolchain_name",
        "rustc_sha256",
        "cargo_sha256",
        "rust_lld_sha256",
        "toolchain_manifest_sha256",
        "toolchain_tree_sha256",
        "boot_generation",
        "rrc_manifest_path",
        "rrc_manifest_sha256",
        "device_manifest_path",
        "device_manifest_sha256",
        "bootfs_path",
        "bootfs_sha256",
        "bootfs_bytes",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect::<BTreeSet<_>>();
    for spec in NATIVE_SPECS {
        for suffix in ["path", "sha256", "command", "inspection_sha256"] {
            keys.insert(format!("{}_{suffix}", spec.label));
        }
    }
    keys
}

fn parse_receipt(text: &str) -> Result<BTreeMap<String, String>, Failure> {
    if !text.ends_with('\n') || text.contains('\r') {
        return Err(Failure::task("WYR1-C1 receipt line endings drifted"));
    }
    let mut values = BTreeMap::new();
    for line in text.lines() {
        let (key, raw) = line
            .split_once(" = ")
            .ok_or_else(|| Failure::task("WYR1-C1 receipt line is malformed"))?;
        if key.is_empty()
            || !key.bytes().all(|byte| {
                byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b'-')
            })
            || values.contains_key(key)
        {
            return Err(Failure::task("WYR1-C1 receipt key is invalid or duplicate"));
        }
        let value = if raw.starts_with('"') && raw.ends_with('"') && raw.len() >= 2 {
            let value = &raw[1..raw.len() - 1];
            if value.contains(['"', '\\']) || value.is_empty() {
                return Err(Failure::task("WYR1-C1 receipt string is malformed"));
            }
            value
        } else if !raw.is_empty() && raw.bytes().all(|byte| byte.is_ascii_digit()) {
            raw
        } else {
            return Err(Failure::task("WYR1-C1 receipt scalar is malformed"));
        };
        values.insert(key.to_owned(), value.to_owned());
    }
    Ok(values)
}

fn validate_inspection(
    report: &str,
    label: &str,
    digest: &str,
    size: usize,
) -> Result<(), Failure> {
    if !report.ends_with('\n') || report.contains('\r') {
        return Err(Failure::task("WYR1-C1 inspection line endings drifted"));
    }
    let body = report
        .strip_suffix('\n')
        .and_then(|value| value.strip_prefix('{'))
        .and_then(|value| value.strip_suffix('}'))
        .ok_or_else(|| Failure::task("WYR1-C1 inspection JSON is malformed"))?;
    let mut fields = BTreeMap::new();
    for field in body.split(',') {
        let (key, value) = field
            .split_once(':')
            .ok_or_else(|| Failure::task("WYR1-C1 inspection field is malformed"))?;
        let key = key
            .strip_prefix('"')
            .and_then(|value| value.strip_suffix('"'))
            .ok_or_else(|| Failure::task("WYR1-C1 inspection key is malformed"))?;
        if fields.insert(key, value).is_some() {
            return Err(Failure::task("WYR1-C1 inspection key is duplicate"));
        }
    }
    let expected_keys = [
        "schema_version",
        "report_kind",
        "verified",
        "artifact",
        "sha256",
        "size",
        "osabi",
        "abi_version",
        "program_headers",
        "load_segments",
        "syscall_veneers",
    ]
    .into_iter()
    .collect::<BTreeSet<_>>();
    let expected_artifact = format!("\"{label}\"");
    let expected_digest = format!("\"{digest}\"");
    let expected_size = size.to_string();
    if fields.keys().copied().collect::<BTreeSet<_>>() != expected_keys
        || fields.get("schema_version") != Some(&"1")
        || fields.get("report_kind") != Some(&"\"wyrmroot-wyr0-native-artifact-inspection\"")
        || fields.get("verified") != Some(&"true")
        || fields.get("artifact") != Some(&expected_artifact.as_str())
        || fields.get("sha256") != Some(&expected_digest.as_str())
        || fields.get("size") != Some(&expected_size.as_str())
        || fields.get("osabi") != Some(&"0")
        || fields.get("abi_version") != Some(&"0")
        || fields.get("syscall_veneers") != Some(&"1")
        || !["program_headers", "load_segments"].into_iter().all(|key| {
            fields
                .get(key)
                .is_some_and(|value| !value.is_empty() && value.bytes().all(|b| b.is_ascii_digit()))
        })
    {
        return Err(Failure::task(format!(
            "WYR1-C1 inspection did not exactly bind {label}"
        )));
    }
    Ok(())
}

fn validate_revision(revision: &str, label: &str) -> Result<(), Failure> {
    if revision.len() != 40
        || !revision
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(Failure::task(format!(
            "{label} revision is not a commit ID"
        )));
    }
    Ok(())
}

pub(crate) fn validate_commit(
    repository: &Path,
    revision: &str,
    label: &str,
) -> Result<(), Failure> {
    validate_revision(revision, label)?;
    let commit = format!("{revision}^{{commit}}");
    let output = Command::new("git")
        .arg("-C")
        .arg(repository)
        .args(["rev-parse", "--verify", &commit])
        .output()
        .map_err(|error| Failure::task(format!("could not inspect {label} commit: {error}")))?;
    if !output.status.success()
        || std::str::from_utf8(&output.stdout).ok().map(str::trim) != Some(revision)
    {
        return Err(Failure::task(format!(
            "declared {label} revision is not that exact commit"
        )));
    }
    Ok(())
}

fn git_file(repository: &Path, revision: &str, path: &str) -> Result<Vec<u8>, Failure> {
    let object = format!("{revision}:{path}");
    let output = Command::new("git")
        .arg("-C")
        .arg(repository)
        .args(["show", &object])
        .output()
        .map_err(|error| Failure::task(format!("could not inspect historical {path}: {error}")))?;
    if !output.status.success() {
        return Err(Failure::task(format!(
            "declared WYR1-C1 revision lacks {path}"
        )));
    }
    Ok(output.stdout)
}

fn product_generation(revision: &str, artifacts: &[NativeArtifact]) -> [u8; 32] {
    let mut material = Vec::from(b"wyrmroot-wyr1-c1-host-product-v1\0".as_slice());
    material.extend_from_slice(revision.as_bytes());
    for artifact in artifacts {
        material.extend_from_slice(artifact.spec.label.as_bytes());
        material.extend_from_slice(artifact.sha256.as_bytes());
    }
    sha256::bytes_digest_array(&material)
}

fn e6_product_generation(revision: &str, artifacts: &[NativeArtifact]) -> [u8; 32] {
    let mut material = Vec::from(b"wyrmroot-wyr1-e6-host-product-v1\0".as_slice());
    material.extend_from_slice(revision.as_bytes());
    for artifact in artifacts {
        material.extend_from_slice(artifact.spec.label.as_bytes());
        material.extend_from_slice(artifact.sha256.as_bytes());
    }
    sha256::bytes_digest_array(&material)
}

fn e7_product_generation(
    revision: &str,
    artifacts: &[NativeArtifact],
    malformed_elf: &[u8],
) -> [u8; 32] {
    let mut material = Vec::from(b"wyrmroot-wyr1-e7-selector33-product-v1\0".as_slice());
    material.extend_from_slice(revision.as_bytes());
    for artifact in artifacts {
        material.extend_from_slice(artifact.spec.label.as_bytes());
        material.extend_from_slice(artifact.sha256.as_bytes());
    }
    material.extend_from_slice(E7_MALFORMED_ELF_PATH.as_bytes());
    material.extend_from_slice(sha256::bytes_digest(malformed_elf).as_bytes());
    sha256::bytes_digest_array(&material)
}

fn e8_product_generation(
    revision: &str,
    artifacts: &[NativeArtifact],
    malformed_elf: &[u8],
) -> [u8; 32] {
    let mut material = Vec::from(b"wyrmroot-wyr1-e8-selector33-product-v1\0".as_slice());
    material.extend_from_slice(revision.as_bytes());
    for artifact in artifacts {
        material.extend_from_slice(artifact.spec.label.as_bytes());
        material.extend_from_slice(artifact.sha256.as_bytes());
    }
    material.extend_from_slice(E7_MALFORMED_ELF_PATH.as_bytes());
    material.extend_from_slice(sha256::bytes_digest(malformed_elf).as_bytes());
    sha256::bytes_digest_array(&material)
}

fn e7_native_spec(label: &str) -> Result<NativeSpec, Failure> {
    WYR1E7_SELECTED_NATIVE_SPECS
        .iter()
        .chain(WYR1E6_PRODUCT_NATIVE_SPECS.iter())
        .copied()
        .find(|spec| spec.label == label)
        .ok_or_else(|| Failure::task("unknown WYR1-E7 native artifact label"))
}

fn e8_native_spec(label: &str) -> Result<NativeSpec, Failure> {
    WYR1E8_SELECTED_NATIVE_SPECS
        .iter()
        .chain(WYR1E6_PRODUCT_NATIVE_SPECS.iter())
        .copied()
        .find(|spec| spec.label == label)
        .ok_or_else(|| Failure::task("unknown WYR1-E8 native artifact label"))
}

fn native_command(spec: NativeSpec) -> String {
    format!(
        "cargo build --offline --locked --release --target {NATIVE_TARGET} --package {} --bin {} --no-default-features --features {}",
        spec.package, spec.binary, spec.features
    )
}

pub(crate) fn e6_native_command(label: &str) -> Result<String, Failure> {
    let spec = WYR1E6_PRODUCT_NATIVE_SPECS
        .iter()
        .copied()
        .find(|spec| spec.label == label)
        .ok_or_else(|| Failure::task("unknown WYR1-E6 native artifact label"))?;
    let mut command = native_command(spec);
    if label == "wyrmsh" {
        command.push_str(" [rustflags: -Cjump-tables=no -Zemit-stack-sizes]");
    }
    Ok(command)
}

pub(crate) fn e7_native_command(label: &str) -> Result<String, Failure> {
    let spec = e7_native_spec(label)?;
    let mut command = native_command(spec);
    if label == "wyrmsh" {
        command.push_str(" [rustflags: -Cjump-tables=no -Zemit-stack-sizes]");
    }
    if label == "system-init" {
        command.push_str(" [env: WYRMROOT_WYR1E7_EVIDENCE_NONCE=<validated-16-hex>]");
    }
    Ok(command)
}

pub(crate) fn e7_native_features(label: &str) -> Result<&'static str, Failure> {
    Ok(e7_native_spec(label)?.features)
}

pub(crate) fn e8_native_command(label: &str) -> Result<String, Failure> {
    let spec = e8_native_spec(label)?;
    let mut command = native_command(spec);
    if label == "wyrmsh" {
        command.push_str(" [rustflags: -Cjump-tables=no -Zemit-stack-sizes]");
    }
    if label == "system-init" {
        command.push_str(" [env: WYRMROOT_WYR1E8_EVIDENCE_NONCE=<validated-16-hex>]");
    }
    Ok(command)
}

pub(crate) fn e8_native_features(label: &str) -> Result<&'static str, Failure> {
    Ok(e8_native_spec(label)?.features)
}

pub(crate) fn validate_e7_nonce(nonce: &str) -> Result<(), Failure> {
    if nonce.len() != 16
        || !nonce
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'A'..=b'F'))
        || nonce.bytes().all(|byte| byte == b'0')
    {
        return Err(Failure::task(
            "WYR1-E7 evidence nonce must be 16 nonzero uppercase hexadecimal characters",
        ));
    }
    Ok(())
}

pub(crate) fn validate_e8_nonce(nonce: &str) -> Result<(), Failure> {
    if nonce.len() != 16
        || !nonce
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'A'..=b'F'))
        || nonce.bytes().all(|byte| byte == b'0')
    {
        return Err(Failure::task(
            "WYR1-E8 evidence nonce must be 16 nonzero uppercase hexadecimal characters",
        ));
    }
    const SELECTED_TOKEN_INDICES: [&str; 17] = [
        "0000000000000001",
        "0000000000000002",
        "0000000000000003",
        "0000000000000004",
        "0000000000000005",
        "0000000000000006",
        "0000000000000101",
        "0000000000000102",
        "0000000000000201",
        "0000000000000202",
        "0000000000000301",
        "0000000000000310",
        "0000000000000311",
        "0000000000000312",
        "0000000000000320",
        "0000000000000321",
        "0000000000000322",
    ];
    if SELECTED_TOKEN_INDICES.contains(&nonce) {
        return Err(Failure::task(
            "WYR1-E8 evidence nonce must not equal a selected token index",
        ));
    }
    Ok(())
}

pub(crate) fn validate_fresh_output(
    repository: &Path,
    project: &Path,
    output: &Path,
) -> Result<PathBuf, Failure> {
    if fs::symlink_metadata(output).is_ok() {
        return Err(Failure::task(
            "WYR1-C1 product refuses a pre-existing output path",
        ));
    }
    if output.is_absolute()
        && output
            .components()
            .any(|component| matches!(component, Component::ParentDir | Component::CurDir))
    {
        return Err(Failure::task("WYR1-C1 output path is not canonical"));
    }
    let parent = output
        .parent()
        .ok_or_else(|| Failure::task("WYR1-C1 output has no parent"))?;
    let parent = fs::canonicalize(parent)
        .map_err(|error| Failure::task(format!("could not resolve output parent: {error}")))?;
    let project = fs::canonicalize(project)
        .map_err(|error| Failure::task(format!("could not resolve OS-Project root: {error}")))?;
    let repository = fs::canonicalize(repository)
        .map_err(|error| Failure::task(format!("could not resolve Wyrmroot source: {error}")))?;
    let name = output
        .file_name()
        .ok_or_else(|| Failure::task("WYR1-C1 output has no final component"))?;
    let resolved = parent.join(name);
    if !resolved.starts_with(&project) || resolved.starts_with(&repository) {
        return Err(Failure::task(
            "WYR1-C1 output must remain inside OS-Project and outside the Wyrmroot source tree",
        ));
    }
    Ok(resolved)
}

pub(crate) fn reject_ambient_build_environment(
    environment: impl IntoIterator<Item = (OsString, OsString)>,
) -> Result<(), Failure> {
    let variables = environment
        .into_iter()
        .collect::<std::collections::BTreeMap<_, _>>();
    for variable in [
        "RUSTUP_TOOLCHAIN",
        "RUSTC_BOOTSTRAP",
        "RUSTC",
        "RUSTDOC",
        "RUSTFMT",
        "RUSTFLAGS",
        "RUSTDOCFLAGS",
        "CARGO_ENCODED_RUSTFLAGS",
        "RUSTC_WRAPPER",
        "RUSTC_WORKSPACE_WRAPPER",
        "CARGO_BUILD_RUSTC",
        "CARGO_BUILD_RUSTDOC",
        "CARGO_BUILD_TARGET",
        "CARGO_TARGET_DIR",
        "WYRMROOT_RUSTC",
        "DEEPWYRM_GUEST_TEST_SELECTOR",
        "DEEPWYRM_GUEST_TEST_ID",
        "WYRMROOT_WYR1E7_EVIDENCE_NONCE",
    ] {
        if variables.contains_key(OsStr::new(variable)) {
            return Err(Failure::task(format!(
                "WYR1-C1 product refuses ambient {variable}"
            )));
        }
    }
    if variables
        .keys()
        .any(|key| key.as_encoded_bytes().starts_with(b"CARGO_TARGET_"))
    {
        return Err(Failure::task(
            "WYR1-C1 product refuses ambient CARGO_TARGET_*",
        ));
    }
    Ok(())
}

pub(crate) fn reject_e6_ambient_build_environment(
    environment: impl IntoIterator<Item = (OsString, OsString)>,
) -> Result<(), Failure> {
    let environment = environment.into_iter().collect::<Vec<_>>();
    reject_ambient_build_environment(environment.iter().cloned())?;
    for (key, _) in environment {
        let display = key.to_string_lossy();
        let key = key.as_encoded_bytes();
        if [b"CARGO_PROFILE_".as_slice(), b"CARGO_BUILD_".as_slice()]
            .iter()
            .any(|prefix| key.starts_with(prefix))
        {
            return Err(Failure::task(format!(
                "WYR1-E6 product refuses ambient {}",
                display
            )));
        }
    }
    Ok(())
}

pub(crate) fn inspect_e6_dependency_source(
    repository: &Path,
    manifest: &BuildManifest,
    toolchain: &crate::toolchain_artifact::AcceptedToolchain,
    cargo_home: &Path,
) -> Result<crate::deep_layout::CargoGitSourceIdentity, Failure> {
    inspect_e6_dependency_source_with_tools(
        repository,
        manifest,
        &toolchain.cargo,
        &toolchain.rustc,
        cargo_home,
    )
}

fn inspect_e6_dependency_source_with_tools(
    repository: &Path,
    manifest: &BuildManifest,
    cargo: &Path,
    rustc: &Path,
    cargo_home: &Path,
) -> Result<crate::deep_layout::CargoGitSourceIdentity, Failure> {
    let repository_directory =
        crate::secure_fs::Directory::open_exact(repository, "Wyrmroot source")?;
    let tmp = match repository_directory.open_child(".tmp", "WYR1-E6 temporary root") {
        Ok(directory) => directory,
        Err(_) => repository_directory.create_child(".tmp", 0o700, "WYR1-E6 temporary root")?,
    };
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| Failure::task("system clock is before the Unix epoch"))?
        .as_nanos();
    let scratch = tmp.create_scratch(
        &format!("wyr1e6-source-{}-{unique}", std::process::id()),
        "WYR1-E6 source inspection scratch",
    )?;
    let result = crate::deep_layout::inspect_cargo_git_source(
        repository,
        cargo,
        rustc,
        cargo_home,
        scratch.path(),
        manifest.deepwyrm_repository()?,
        manifest.deepwyrm_revision()?,
    );
    scratch.finish(result)
}

pub(crate) fn clean_repository_revision(repository: &Path) -> Result<String, Failure> {
    let revision = Command::new("git")
        .arg("-C")
        .arg(repository)
        .args(["rev-parse", "HEAD"])
        .output()
        .map_err(|error| Failure::task(format!("could not inspect Wyrmroot HEAD: {error}")))?;
    let revision = std::str::from_utf8(&revision.stdout)
        .map_err(|_| Failure::task("Wyrmroot HEAD is not UTF-8"))?
        .trim()
        .to_owned();
    verify_repository_revision(repository, &revision)?;
    Ok(revision)
}

pub(crate) fn verify_repository_revision(repository: &Path, expected: &str) -> Result<(), Failure> {
    let head = Command::new("git")
        .arg("-C")
        .arg(repository)
        .args(["rev-parse", "HEAD"])
        .output()
        .map_err(|error| Failure::task(format!("could not recheck Wyrmroot HEAD: {error}")))?;
    let status = Command::new("git")
        .arg("-C")
        .arg(repository)
        .args(["status", "--porcelain=v1", "--untracked-files=all"])
        .output()
        .map_err(|error| Failure::task(format!("could not inspect Wyrmroot status: {error}")))?;
    if !head.status.success()
        || !status.status.success()
        || !status.stdout.is_empty()
        || std::str::from_utf8(&head.stdout).ok().map(str::trim) != Some(expected)
    {
        return Err(Failure::task(
            "WYR1-C1 product requires one exact clean Wyrmroot revision",
        ));
    }
    Ok(())
}

fn digest_array(value: &str) -> Result<[u8; 32], Failure> {
    crate::wyr1::decode_digest(value)
}

fn hex_digest(value: &[u8; 32]) -> String {
    let mut output = String::with_capacity(64);
    for byte in value {
        use std::fmt::Write as _;
        write!(&mut output, "{byte:02x}").expect("writing to String cannot fail");
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn e6_actual_dependency_source_preflight() {
        let repository = crate::tasks::repository_root().expect("resolve Wyrmroot source");
        let manifest = BuildManifest::load(&repository).expect("load build manifest");
        let project = crate::tasks::canonical_project_root(&repository)
            .expect("resolve canonical project root");
        let toolchain = project
            .join(
                manifest
                    .accepted_artifact_root()
                    .expect("resolve accepted artifact root"),
            )
            .join("toolchains")
            .join(
                manifest
                    .rust_toolchain_name()
                    .expect("resolve accepted toolchain name"),
            )
            .join("bin");
        let cargo_home = crate::tasks::project_cargo_home(&repository, &manifest)
            .expect("resolve project Cargo home");
        let source = inspect_e6_dependency_source_with_tools(
            &repository,
            &manifest,
            &toolchain.join("cargo"),
            &toolchain.join("rustc"),
            &cargo_home,
        )
        .expect("verify actual Cargo-selected Deepwyrm source");
        source
            .verify_unchanged()
            .expect("actual Cargo-selected Deepwyrm source changed");
    }

    #[test]
    fn wyrmsh_native_check_selects_the_separate_production_shell() {
        assert_eq!(WYRMSH_NATIVE_CHECK_SPECS.len(), 1);
        let spec = &WYRMSH_NATIVE_CHECK_SPECS[0];
        assert_eq!(spec.package, "wyrmroot-wyrmsh");
        assert_eq!(spec.binary, "wyrmsh");
        assert_eq!(spec.features, "native-wyrmsh");
    }

    #[test]
    fn wyr1e6_native_gate_selects_one_normal_product_and_historical_regressions() {
        let specs = WYR1E6_NATIVE_CHECK_SPECS
            .iter()
            .map(|spec| (spec.package, spec.binary, spec.features))
            .collect::<Vec<_>>();
        assert_eq!(
            &specs[..7],
            &[
                ("wyrmroot-system-init", "system-init", "wyr1e-production"),
                ("wyrmroot-registryd", "registryd", "native-registryd"),
                ("wyrmroot-devmgr", "devmgr", "wyr1e-production"),
                ("wyrmroot-uart16550d", "uart16550d", "native-uart16550d",),
                (
                    "wyrmroot-consoled",
                    "consoled",
                    "native-consoled,wyr1e-wyrmsh",
                ),
                ("wyrmroot-wyrmsh", "wyrmsh", "native-wyrmsh"),
                (
                    "wyrmroot-hello",
                    "wyrmroot-stream-hello",
                    "native-stream-hello",
                ),
            ]
        );
        assert_eq!(
            &specs[7..],
            &[
                (
                    "wyrmroot-consoled",
                    "consoled",
                    "native-consoled,wyr1d-selector32",
                ),
                ("wyrmroot-system-init", "system-init", "wyr1d-selector32"),
                ("wyrmroot-devmgr", "devmgr", "wyr1d-selector32"),
            ]
        );
    }

    #[test]
    fn wyr1e6_product_is_exact_normal_twelve_entry_archive() {
        let artifacts = E6_ARTIFACT_LABELS
            .iter()
            .enumerate()
            .map(|(index, label)| ((*label).to_owned(), vec![index as u8 + 1; index + 1]))
            .collect::<BTreeMap<_, _>>();
        let product = reassemble_e6_snapshot(&"1".repeat(40), &artifacts).unwrap();
        let archive = Archive::new(&product.bootfs).unwrap();
        assert_eq!(archive.entries().count(), 12);
        assert!(archive.lookup(b"bin/hello").unwrap().is_executable());
        assert!(archive.lookup(b"test/wyr1-e/cpu-hog").is_err());
        let policy = LaunchPolicy::parse(&product.launch_policy).unwrap();
        assert_eq!(policy.version_minor(), 1);
        assert_eq!(policy.len(), 2);
        assert_eq!(
            policy.find("bin/hello").unwrap().profile_id,
            JOB_V2_PROFILE_ID
        );
        assert_eq!(
            policy.find(WYRMSH_PATH).unwrap().profile_id,
            WYRMSH_PROFILE_ID
        );
        let manifest =
            Manifest::parse_structural(&product.rrc_manifest, &product.generation).unwrap();
        assert_eq!(
            manifest.role(RoleId::Wyrmsh).unwrap().startup_profile(),
            StartupProfile::Wyrmsh
        );
    }

    #[test]
    fn wyr1e7_native_gate_selects_current_init_devmgr_hello_and_three_fixture_actors() {
        let specs = WYR1E7_SELECTED_NATIVE_SPECS
            .iter()
            .map(|spec| (spec.label, spec.package, spec.binary, spec.features))
            .collect::<Vec<_>>();
        assert_eq!(
            specs,
            vec![
                (
                    "system-init",
                    "wyrmroot-system-init",
                    "system-init",
                    "wyr1e-selector33",
                ),
                ("devmgr", "wyrmroot-devmgr", "devmgr", "wyr1e-production",),
                (
                    "hello",
                    "wyrmroot-hello",
                    "wyrmroot-stream-hello",
                    "native-stream-hello",
                ),
                (
                    "cpu-hog",
                    "wyrmroot-dw1b-preemption",
                    "wyrmroot-job-cpu-hog",
                    "native-job-cpu-hog",
                ),
                (
                    "exit-nonzero",
                    "wyrmroot-wyr1e-test-actors",
                    "wyrmroot-wyr1e-exit-nonzero",
                    "native-exit-nonzero",
                ),
                (
                    "fault",
                    "wyrmroot-wyr1e-test-actors",
                    "wyrmroot-wyr1e-fault",
                    "native-fault",
                ),
            ]
        );
        assert!(
            e7_native_command("system-init")
                .unwrap()
                .contains("WYRMROOT_WYR1E7_EVIDENCE_NONCE")
        );
        for label in ["devmgr", "hello", "cpu-hog", "exit-nonzero", "fault"] {
            assert!(
                !e7_native_command(label)
                    .unwrap()
                    .contains("WYRMROOT_WYR1E7_EVIDENCE_NONCE")
            );
        }
    }

    #[test]
    fn wyr1e7_product_is_exact_augmented_sixteen_entry_archive() {
        let artifacts = E7_ARTIFACT_LABELS
            .iter()
            .enumerate()
            .map(|(index, label)| {
                let bytes = vec![index as u8 + 1; index + 3];
                NativeArtifact {
                    spec: e7_native_spec(label).unwrap(),
                    sha256: sha256::bytes_digest(&bytes),
                    bytes,
                    inspection: format!("{{\"verified\":true,\"artifact\":\"{label}\"}}\n"),
                }
            })
            .collect::<Vec<_>>();
        let product = assemble_e7_product(&"3".repeat(40), &artifacts, E7_MALFORMED_ELF).unwrap();
        let archive = Archive::new(&product.bootfs).unwrap();
        assert_eq!(archive.entries().count(), 16);
        for path in [
            CPU_HOG_PATH,
            E7_EXIT_NONZERO_PATH,
            E7_FAULT_PATH,
            E7_MALFORMED_ELF_PATH,
        ] {
            assert!(archive.lookup(path.as_bytes()).unwrap().is_executable());
        }
        assert_eq!(
            archive
                .lookup(E7_MALFORMED_ELF_PATH.as_bytes())
                .unwrap()
                .data(),
            E7_MALFORMED_ELF
        );
        let policy = LaunchPolicy::parse(&product.launch_policy).unwrap();
        assert_eq!(policy.version_minor(), 1);
        assert_eq!(policy.len(), 6);
    }

    #[test]
    fn wyr1e8_native_gate_selects_current_recovery_product_and_actors() {
        let specs = WYR1E8_SELECTED_NATIVE_SPECS
            .iter()
            .map(|spec| (spec.label, spec.package, spec.binary, spec.features))
            .collect::<Vec<_>>();
        assert_eq!(specs.len(), 10);
        assert_eq!(
            specs[0],
            (
                "system-init",
                "wyrmroot-system-init",
                "system-init",
                "wyr1e8-selector33",
            )
        );
        assert!(specs.contains(&("devmgr", "wyrmroot-devmgr", "devmgr", "wyr1e8-production",)));
        assert!(specs.contains(&(
            "uart16550d",
            "wyrmroot-uart16550d",
            "uart16550d",
            "native-uart16550d",
        )));
        assert!(specs.contains(&(
            "consoled",
            "wyrmroot-consoled",
            "consoled",
            "native-consoled,wyr1e-wyrmsh,wyr1e8-recovery",
        )));
        assert!(specs.contains(&(
            "recovery-trigger",
            "wyrmroot-wyr1e-test-actors",
            "wyrmroot-recovery-trigger",
            "native-recovery-trigger",
        )));
        assert!(specs.contains(&(
            "stdout-pressure",
            "wyrmroot-wyr1e-test-actors",
            "wyrmroot-stdout-pressure",
            "native-stdout-pressure",
        )));
        assert!(
            e8_native_command("system-init")
                .unwrap()
                .contains("WYRMROOT_WYR1E8_EVIDENCE_NONCE")
        );
        for label in E8_ARTIFACT_LABELS {
            assert_eq!(
                e8_native_features(label).unwrap(),
                e8_native_spec(label).unwrap().features
            );
        }
    }

    #[test]
    fn wyr1e8_product_is_exact_additive_eighteen_entry_archive() {
        let artifacts = E8_ARTIFACT_LABELS
            .iter()
            .enumerate()
            .map(|(index, label)| {
                let bytes = vec![index as u8 + 1; index + 3];
                NativeArtifact {
                    spec: e8_native_spec(label).unwrap(),
                    sha256: sha256::bytes_digest(&bytes),
                    bytes,
                    inspection: format!("{{\"verified\":true,\"artifact\":\"{label}\"}}\n"),
                }
            })
            .collect::<Vec<_>>();
        let product = assemble_e8_product(&"8".repeat(40), &artifacts, E7_MALFORMED_ELF).unwrap();
        let archive = Archive::new(&product.bootfs).unwrap();
        assert_eq!(archive.entries().count(), 18);
        for path in [
            CPU_HOG_PATH,
            E7_EXIT_NONZERO_PATH,
            E7_FAULT_PATH,
            E7_MALFORMED_ELF_PATH,
            E8_RECOVERY_TRIGGER_PATH,
            E8_STDOUT_PRESSURE_PATH,
        ] {
            assert!(archive.lookup(path.as_bytes()).unwrap().is_executable());
        }
        let policy = LaunchPolicy::parse(&product.launch_policy).unwrap();
        assert_eq!(policy.version_minor(), 1);
        assert_eq!(policy.len(), 8);

        let e7_artifacts = artifacts[..10]
            .iter()
            .map(|artifact| NativeArtifact {
                spec: artifact.spec,
                bytes: artifact.bytes.clone(),
                sha256: artifact.sha256.clone(),
                inspection: artifact.inspection.clone(),
            })
            .collect::<Vec<_>>();
        let e7 = assemble_e7_product(&"7".repeat(40), &e7_artifacts, E7_MALFORMED_ELF).unwrap();
        assert_eq!(Archive::new(&e7.bootfs).unwrap().entries().count(), 16);
        assert!(
            Archive::new(&e7.bootfs)
                .unwrap()
                .lookup(E8_RECOVERY_TRIGGER_PATH.as_bytes())
                .is_err()
        );
    }

    #[test]
    fn wyr1e7_nonce_is_fixed_uppercase_nonzero_hex() {
        assert!(validate_e7_nonce("0123456789ABCDEF").is_ok());
        for invalid in [
            "0000000000000000",
            "0123456789abcdef",
            "0123456789ABCDE",
            "0123456789ABCDEG",
        ] {
            assert!(validate_e7_nonce(invalid).is_err());
        }
    }

    #[test]
    fn wyr1e8_nonce_is_fixed_uppercase_nonzero_hex() {
        assert!(validate_e8_nonce("E800000000000001").is_ok());
        for invalid in [
            "0000000000000000",
            "e800000000000001",
            "E80000000000001",
            "E80000000000000G",
        ] {
            assert!(validate_e8_nonce(invalid).is_err());
        }
        for selected_index in [
            "0000000000000001",
            "0000000000000002",
            "0000000000000003",
            "0000000000000004",
            "0000000000000005",
            "0000000000000006",
            "0000000000000101",
            "0000000000000102",
            "0000000000000201",
            "0000000000000202",
            "0000000000000301",
            "0000000000000310",
            "0000000000000311",
            "0000000000000312",
            "0000000000000320",
            "0000000000000321",
            "0000000000000322",
        ] {
            assert!(validate_e8_nonce(selected_index).is_err());
        }
        for adjacent_allowed in [
            "0000000000000007",
            "0000000000000100",
            "0000000000000103",
            "0000000000000200",
            "0000000000000203",
            "0000000000000300",
            "0000000000000302",
            "000000000000030F",
            "0000000000000313",
            "000000000000031F",
            "0000000000000323",
        ] {
            assert!(validate_e8_nonce(adjacent_allowed).is_ok());
        }
    }

    #[test]
    fn wyr1e3_native_checks_keep_shell_and_historical_selections_separate() {
        assert_eq!(WYR1E3_NATIVE_CHECK_SPECS.len(), 5);
        for spec in WYR1E3_NATIVE_CHECK_SPECS {
            assert!(!(spec.features.contains("wyr1e-") && spec.features.contains("selector32")));
            assert!(!spec.package.contains("retained-stubs"));
        }
        assert_eq!(
            WYR1E3_NATIVE_CHECK_SPECS[0].features,
            "native-init,wyr1e-shell-controller"
        );
        assert_eq!(WYR1E3_NATIVE_CHECK_SPECS[1].features, "native-registryd");
        assert_eq!(
            WYR1E3_NATIVE_CHECK_SPECS[2].features,
            "native-consoled,wyr1e-wyrmsh"
        );
        assert_eq!(
            WYR1E3_NATIVE_CHECK_SPECS[3].features,
            "native-consoled,wyr1d-selector32"
        );
        assert_eq!(WYR1E3_NATIVE_CHECK_SPECS[4].features, "wyr1d-selector32");
    }

    #[test]
    fn e3b_native_gate_covers_the_exact_product_and_nonce_inputs() {
        let specs = E3B_NATIVE_CHECK_SPECS
            .iter()
            .map(|spec| (spec.package, spec.binary, spec.features))
            .collect::<Vec<_>>();
        assert_eq!(
            specs,
            vec![
                (
                    "wyrmroot-bootstrap",
                    "wyrmroot-bootstrap",
                    "wyr1c5-production",
                ),
                ("wyrmroot-system-init", "system-init", "dw1e3-selector31",),
                ("wyrmroot-registryd", "registryd", "native-registryd",),
                ("wyrmroot-devmgr", "devmgr", "dw1e3-selector31"),
                ("wyrmroot-uart16550d", "uart16550d", "dw1e3-selector31",),
                (
                    "wyrmroot-wyr1-retained-stubs",
                    "consoled",
                    "native-retained",
                ),
                ("wyrmroot-wyr1-retained-stubs", "wyrmsh", "native-retained",),
                (
                    "wyrmroot-dw1e3-com2-test",
                    "dw1e3-com2-test",
                    "native-probe",
                ),
            ]
        );
        assert_eq!(
            E3B_NATIVE_CHECK_ENVIRONMENT.map(|(name, _)| name),
            [
                "DEEPWYRM_DW1E_EVIDENCE_NONCE",
                "WYRMROOT_DW1E3_CHALLENGE_1_NONCE",
                "WYRMROOT_DW1E3_CHALLENGE_2_NONCE",
            ]
        );
        assert_eq!(
            E3B_NATIVE_CHECK_ENVIRONMENT
                .map(|(_, value)| value)
                .into_iter()
                .collect::<BTreeSet<_>>()
                .len(),
            3
        );
    }

    fn fixture_artifacts() -> Vec<NativeArtifact> {
        NATIVE_SPECS
            .into_iter()
            .enumerate()
            .map(|(index, spec)| {
                let bytes = vec![index as u8 + 1; index + 3];
                NativeArtifact {
                    spec,
                    sha256: sha256::bytes_digest(&bytes),
                    bytes,
                    inspection: format!("{{\"verified\":true,\"artifact\":\"{}\"}}\n", spec.label),
                }
            })
            .collect()
    }

    fn d5_fixture_artifacts() -> Vec<NativeArtifact> {
        D5_PRODUCT_NATIVE_SPECS
            .into_iter()
            .enumerate()
            .map(|(index, spec)| {
                let bytes = vec![index as u8 + 11; index + 5];
                NativeArtifact {
                    spec,
                    sha256: sha256::bytes_digest(&bytes),
                    bytes,
                    inspection: format!("{{\"verified\":true,\"artifact\":\"{}\"}}\n", spec.label),
                }
            })
            .collect()
    }

    fn publication_snapshot() -> FrozenSnapshot {
        FrozenSnapshot {
            receipt: b"receipt bytes\n".to_vec(),
            rrc_manifest: b"rrc bytes\n".to_vec(),
            device_manifest: b"wrdm bytes\n".to_vec(),
            bootfs: b"bootfs bytes\n".to_vec(),
            artifacts: NATIVE_SPECS
                .into_iter()
                .map(|spec| {
                    (
                        spec.label.to_owned(),
                        format!("{} elf\n", spec.label).into_bytes(),
                    )
                })
                .collect(),
            inspections: NATIVE_SPECS
                .into_iter()
                .map(|spec| {
                    (
                        spec.label.to_owned(),
                        format!("{} inspection\n", spec.label).into_bytes(),
                    )
                })
                .collect(),
        }
    }

    fn published_leaf_bytes<'a>(snapshot: &'a FrozenSnapshot, relative: &str) -> &'a [u8] {
        if let Some(name) = relative
            .strip_prefix("artifacts/")
            .and_then(|value| value.strip_suffix(".elf"))
        {
            return &snapshot.artifacts[name];
        }
        if let Some(name) = relative
            .strip_prefix("inspections/")
            .and_then(|value| value.strip_suffix(".json"))
        {
            return &snapshot.inspections[name];
        }
        match relative {
            "product/rrc-c1-v1.bin" => &snapshot.rrc_manifest,
            "product/wrdm-c1-v1.bin" => &snapshot.device_manifest,
            "product/bootfs.img" => &snapshot.bootfs,
            "product/build-receipt.toml" => &snapshot.receipt,
            _ => panic!("unknown C1 retained leaf {relative}"),
        }
    }

    #[test]
    fn c1_product_is_deterministic_and_uses_real_profiles() {
        let artifacts = fixture_artifacts();
        let first = assemble_product(&"a".repeat(40), &artifacts).unwrap();
        let second = assemble_product(&"a".repeat(40), &artifacts).unwrap();
        assert_eq!(first.rrc_manifest, second.rrc_manifest);
        assert_eq!(first.device_manifest, second.device_manifest);
        assert_eq!(first.bootfs, second.bootfs);
        validate_rrc(
            &first.rrc_manifest,
            &first.generation,
            [
                digest_array(&artifacts[1].sha256).unwrap(),
                digest_array(&artifacts[2].sha256).unwrap(),
                digest_array(&artifacts[3].sha256).unwrap(),
                digest_array(&artifacts[4].sha256).unwrap(),
                digest_array(&artifacts[5].sha256).unwrap(),
            ],
        )
        .unwrap();
    }

    #[test]
    fn c6_product_is_deterministic_and_adds_only_the_selector_gate() {
        let artifacts = fixture_artifacts();
        let nonce = "0123456789ABCDEF";
        let first = assemble_c6_product(&"a".repeat(40), &artifacts, nonce).unwrap();
        let second = assemble_c6_product(&"a".repeat(40), &artifacts, nonce).unwrap();
        assert_eq!(first.rrc_manifest, second.rrc_manifest);
        assert_eq!(first.device_manifest, second.device_manifest);
        assert_eq!(first.bootfs, second.bootfs);
        let gate = b"schema = 1\nselector = \"device-coordinator-restart\"\ntest_id = 29\nevidence_protocol = \"WRC6\"\nnonce = \"0123456789ABCDEF\"\nphysical_io = \"not-performed\"\n";
        inspect_c6_archive(
            &first.bootfs,
            &artifacts,
            &first.rrc_manifest,
            &first.device_manifest,
            gate,
        )
        .unwrap();
        let archive = Archive::new(&first.bootfs).unwrap();
        assert_eq!(archive.entries().count(), 11);
        assert_eq!(
            archive
                .lookup(b"system/bootstrap/wyr1-c6-gate-v1")
                .unwrap()
                .data(),
            gate
        );
        assert!(
            !archive
                .lookup(b"system/bootstrap/wyr1-c6-gate-v1")
                .unwrap()
                .is_executable()
        );
    }

    #[test]
    fn d5_product_binds_console_echo_policy_and_excludes_selector31() {
        assert_eq!(D5_PRODUCT_NATIVE_SPECS[0].features, "wyr1d-selector32");
        assert_eq!(D5_PRODUCT_NATIVE_SPECS[2].features, "wyr1d-selector32");
        assert_eq!(D5_PRODUCT_NATIVE_SPECS[3].features, "wyr1d-selector32");
        assert_eq!(
            D5_PRODUCT_NATIVE_SPECS[4].features,
            "native-consoled,wyr1d-selector32"
        );
        let artifacts = d5_fixture_artifacts();
        let nonce = "0123456789ABCDEF";
        let (first, first_policy) =
            assemble_d5_product(&"b".repeat(40), &artifacts, nonce).unwrap();
        let (second, second_policy) =
            assemble_d5_product(&"b".repeat(40), &artifacts, nonce).unwrap();
        assert_eq!(first.bootfs, second.bootfs);
        assert_eq!(first_policy, second_policy);
        let policy = LaunchPolicy::parse(&first_policy).unwrap();
        let entry = policy.find(CONSOLE_ECHO_PATH).unwrap();
        assert_eq!(policy.len(), 1);
        assert!(!entry.allow_no_streams);
        assert!(entry.allow_three_streams);
        assert_eq!(
            entry.content_sha256,
            digest_array(&artifacts[6].sha256).unwrap()
        );
        let archive = Archive::new(&first.bootfs).unwrap();
        assert!(archive.lookup(DW1_E3A_GATE_PATH.as_bytes()).is_err());
        assert!(archive.lookup(DW1_E3A_COM2_PROBE_PATH.as_bytes()).is_err());
        assert_eq!(
            archive.lookup(WYR1_D5_GATE_PATH.as_bytes()).unwrap().data(),
            b"schema = 1\nselector = \"native-console-streams\"\ntest_id = 32\nevidence_protocol = \"WRD1\"\nnonce = \"0123456789ABCDEF\"\n"
        );
    }

    #[test]
    fn c6_nonce_is_exact_uppercase_hex_and_nonzero() {
        assert!(validate_c6_nonce("0123456789ABCDEF").is_ok());
        for nonce in [
            "0000000000000000",
            "0123456789abcdef",
            "0123456789ABCDEG",
            "0123456789ABCDE",
            "0123456789ABCDEF0",
        ] {
            assert!(validate_c6_nonce(nonce).is_err(), "accepted {nonce}");
        }
    }

    #[test]
    fn ambient_overrides_and_existing_outputs_are_rejected() {
        assert!(reject_ambient_build_environment([]).is_ok());
        assert!(
            reject_ambient_build_environment([(
                OsString::from("CARGO_TARGET_DIR"),
                OsString::from("elsewhere")
            )])
            .is_err()
        );
        let root = std::env::temp_dir().join(format!("wyr1c1-output-{}", std::process::id()));
        let repository = root.join("OS-Project/wyrmroot");
        fs::create_dir_all(&repository).unwrap();
        let output = root.join("OS-Project/product");
        fs::create_dir(&output).unwrap();
        assert!(validate_fresh_output(&repository, &root.join("OS-Project"), &output).is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn e6_environment_rejects_unrecorded_cargo_build_configuration() {
        for variable in [
            "CARGO_PROFILE_RELEASE_LTO",
            "CARGO_PROFILE_RELEASE_CODEGEN_UNITS",
            "CARGO_PROFILE_RELEASE_OPT_LEVEL",
            "CARGO_PROFILE_RELEASE_PANIC",
            "CARGO_PROFILE_RELEASE_STRIP",
            "CARGO_BUILD_JOBS",
            "CARGO_BUILD_RUSTFLAGS",
            "CARGO_BUILD_RUSTC_WRAPPER",
        ] {
            assert!(
                reject_e6_ambient_build_environment([(
                    OsString::from(variable),
                    OsString::from("hostile"),
                )])
                .is_err(),
                "accepted unrecorded E6 build variable {variable}"
            );
        }
        assert!(reject_e6_ambient_build_environment([]).is_ok());
    }

    #[test]
    fn command_is_unambiguously_host_only() {
        for spec in NATIVE_SPECS {
            let command = native_command(spec);
            assert!(command.contains("--target x86_64-unknown-wyrmroot"));
            assert!(command.contains("--offline --locked --release"));
        }
    }

    #[test]
    fn native_inspection_uses_only_the_pinned_host_tool_path() {
        assert_eq!(
            crate::tasks::INSPECTION_PATH,
            "/usr/lib/llvm/22/bin:/usr/bin:/bin"
        );
        assert!(!crate::tasks::INSPECTION_PATH.contains("/usr/local"));
    }

    #[test]
    fn frozen_structure_rejects_generation_artifact_and_gate_mutation() {
        let artifacts = fixture_artifacts();
        let product = assemble_product(&"a".repeat(40), &artifacts).unwrap();
        let mut wrong_generation = product.generation;
        wrong_generation[0] ^= 1;
        assert!(
            validate_rrc(
                &product.rrc_manifest,
                &wrong_generation,
                [
                    digest_array(&artifacts[1].sha256).unwrap(),
                    digest_array(&artifacts[2].sha256).unwrap(),
                    digest_array(&artifacts[3].sha256).unwrap(),
                    digest_array(&artifacts[4].sha256).unwrap(),
                    digest_array(&artifacts[5].sha256).unwrap(),
                ],
            )
            .is_err()
        );
        let mut substituted = fixture_artifacts();
        substituted[2].bytes[0] ^= 1;
        assert!(
            inspect_archive(
                &product.bootfs,
                &substituted,
                &product.rrc_manifest,
                &product.device_manifest,
            )
            .is_err()
        );
        let mut changed_bootfs = product.bootfs.clone();
        changed_bootfs[0] ^= 1;
        assert!(
            inspect_archive(
                &changed_bootfs,
                &artifacts,
                &product.rrc_manifest,
                &product.device_manifest,
            )
            .is_err()
        );
    }

    #[test]
    fn inspection_validator_binds_utf8_name_hash_size_and_verified_state() {
        let digest = "ab".repeat(32);
        let report = format!(
            "{{\"schema_version\":1,\"report_kind\":\"wyrmroot-wyr0-native-artifact-inspection\",\"verified\":true,\"artifact\":\"devmgr\",\"sha256\":\"{digest}\",\"size\":17,\"osabi\":0,\"abi_version\":0,\"program_headers\":2,\"load_segments\":1,\"syscall_veneers\":1}}\n"
        );
        assert!(validate_inspection(&report, "devmgr", &digest, 17).is_ok());
        assert!(validate_inspection(&report, "registryd", &digest, 17).is_err());
        assert!(validate_inspection(&report, "devmgr", &digest, 18).is_err());
        assert!(
            validate_inspection(
                &report.replace("\"verified\":true", "\"verified\":false"),
                "devmgr",
                &digest,
                17,
            )
            .is_err()
        );
    }

    #[test]
    fn c1_receipt_parser_rejects_command_key_and_size_ambiguity() {
        assert!(parse_receipt("bootfs_bytes = 17\n").is_ok());
        assert!(parse_receipt("bootfs_bytes = \"17\"\n").is_ok());
        assert!(parse_receipt("system-init_command = \"x\"\n").is_ok());
        assert!(parse_receipt("a = \"x\"\na = \"y\"\n").is_err());
        assert!(parse_receipt("bootfs_bytes = +17\n").is_err());
        assert!(parse_receipt("system/init = \"x\"\n").is_err());
    }

    #[test]
    fn declared_revision_must_be_the_exact_commit_not_its_tree() {
        let root = std::env::temp_dir().join(format!(
            "wyr1c-commit-kind-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&root).unwrap();
        let git = |arguments: &[&str]| {
            Command::new("git")
                .arg("-C")
                .arg(&root)
                .args(arguments)
                .env("GIT_AUTHOR_NAME", "WYR1-C test")
                .env("GIT_AUTHOR_EMAIL", "test@example.invalid")
                .env("GIT_COMMITTER_NAME", "WYR1-C test")
                .env("GIT_COMMITTER_EMAIL", "test@example.invalid")
                .output()
                .unwrap()
        };
        assert!(git(&["init", "--quiet"]).status.success());
        fs::write(root.join("file"), b"fixture").unwrap();
        assert!(git(&["add", "file"]).status.success());
        assert!(
            git(&[
                "-c",
                "commit.gpgsign=false",
                "commit",
                "--quiet",
                "-m",
                "fixture"
            ])
            .status
            .success()
        );
        let commit = String::from_utf8(git(&["rev-parse", "HEAD"]).stdout)
            .unwrap()
            .trim()
            .to_owned();
        let tree = String::from_utf8(git(&["rev-parse", "HEAD^{tree}"]).stdout)
            .unwrap()
            .trim()
            .to_owned();
        assert!(validate_commit(&root, &commit, "fixture").is_ok());
        assert!(validate_commit(&root, &tree, "fixture").is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn c1_publication_rechecks_parent_children_and_retained_receipt() {
        let parent_path = std::env::temp_dir().join(format!(
            "wyr1c-publication-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&parent_path).unwrap();
        fs::set_permissions(&parent_path, fs::Permissions::from_mode(0o755)).unwrap();
        let parent = crate::secure_fs::Directory::open_exact(&parent_path, "parent").unwrap();
        let parent_mode = parent.owned_container_mode("parent").unwrap();
        let output = parent.create_child("generation", 0o700, "output").unwrap();
        let expected = publication_snapshot();
        let mut publication = publish_snapshot(&output, &expected).unwrap();
        final_recheck_publication(&output, &mut publication, &expected, || Ok(())).unwrap();
        verify_publication(
            &parent,
            parent_mode,
            "generation",
            &output,
            &publication.directories,
        )
        .unwrap();

        fs::set_permissions(&parent_path, fs::Permissions::from_mode(0o700)).unwrap();
        assert!(
            verify_publication(
                &parent,
                parent_mode,
                "generation",
                &output,
                &publication.directories,
            )
            .is_err()
        );
        fs::set_permissions(&parent_path, fs::Permissions::from_mode(parent_mode)).unwrap();

        let inspections = parent_path.join("generation/inspections");
        let moved_inspections = parent_path.join("generation/inspections-original");
        fs::rename(&inspections, &moved_inspections).unwrap();
        fs::create_dir(&inspections).unwrap();
        fs::set_permissions(&inspections, fs::Permissions::from_mode(0o700)).unwrap();
        assert!(
            verify_publication(
                &parent,
                parent_mode,
                "generation",
                &output,
                &publication.directories,
            )
            .is_err()
        );
        fs::remove_dir(&inspections).unwrap();
        fs::rename(&moved_inspections, &inspections).unwrap();

        let artifact_path = parent_path.join("generation/artifacts/devmgr.elf");
        fs::set_permissions(&artifact_path, fs::Permissions::from_mode(0o600)).unwrap();
        fs::write(&artifact_path, b"changed elf\n").unwrap();
        fs::set_permissions(&artifact_path, fs::Permissions::from_mode(0o400)).unwrap();
        assert_ne!(
            snapshot_from_publication(&mut publication).unwrap(),
            expected
        );

        let inspection_path = parent_path.join("generation/inspections/devmgr.json");
        fs::set_permissions(&inspection_path, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(snapshot_from_publication(&mut publication).is_err());
        fs::set_permissions(&inspection_path, fs::Permissions::from_mode(0o400)).unwrap();

        let rrc_path = parent_path.join("generation/product/rrc-c1-v1.bin");
        fs::rename(
            &rrc_path,
            parent_path.join("generation/product/original-rrc.bin"),
        )
        .unwrap();
        fs::write(&rrc_path, &expected.rrc_manifest).unwrap();
        fs::set_permissions(&rrc_path, fs::Permissions::from_mode(0o400)).unwrap();
        assert!(snapshot_from_publication(&mut publication).is_err());
        fs::remove_file(&rrc_path).unwrap();
        fs::rename(
            parent_path.join("generation/product/original-rrc.bin"),
            &rrc_path,
        )
        .unwrap();

        let receipt_path = parent_path.join("generation/product/build-receipt.toml");
        fs::set_permissions(&receipt_path, fs::Permissions::from_mode(0o600)).unwrap();
        fs::write(&receipt_path, b"Receipt bytes\n").unwrap();
        fs::set_permissions(&receipt_path, fs::Permissions::from_mode(0o400)).unwrap();
        assert_ne!(
            snapshot_from_publication(&mut publication).unwrap(),
            expected
        );
        fs::remove_dir_all(parent_path).unwrap();
    }

    #[test]
    fn every_c1_retained_leaf_is_rechecked_after_the_acceptance_hook() {
        let mut leaves = NATIVE_SPECS
            .into_iter()
            .flat_map(|spec| {
                [
                    format!("artifacts/{}.elf", spec.label),
                    format!("inspections/{}.json", spec.label),
                ]
            })
            .collect::<Vec<_>>();
        leaves.extend(
            [
                "product/rrc-c1-v1.bin",
                "product/wrdm-c1-v1.bin",
                "product/bootfs.img",
                "product/build-receipt.toml",
            ]
            .into_iter()
            .map(str::to_owned),
        );
        for (index, relative) in leaves.iter().enumerate() {
            for attack in ["replacement", "mode", "same-inode-bytes"] {
                let parent_path = std::env::temp_dir().join(format!(
                    "wyr1c-leaf-{index}-{attack}-{}-{}",
                    std::process::id(),
                    SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap()
                        .as_nanos()
                ));
                fs::create_dir(&parent_path).unwrap();
                fs::set_permissions(&parent_path, fs::Permissions::from_mode(0o755)).unwrap();
                let parent =
                    crate::secure_fs::Directory::open_exact(&parent_path, "parent").unwrap();
                let output = parent.create_child("generation", 0o700, "output").unwrap();
                let expected = publication_snapshot();
                let original = published_leaf_bytes(&expected, relative).to_vec();
                let mut publication = publish_snapshot(&output, &expected).unwrap();
                let path = parent_path.join("generation").join(relative);
                assert!(
                    final_recheck_publication(&output, &mut publication, &expected, move || {
                        match attack {
                            "replacement" => {
                                fs::rename(&path, path.with_extension("original")).unwrap();
                                fs::write(&path, &original).unwrap();
                                fs::set_permissions(&path, fs::Permissions::from_mode(0o400))
                                    .unwrap();
                            }
                            "mode" => {
                                fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
                                    .unwrap();
                            }
                            "same-inode-bytes" => {
                                let mut changed = original;
                                changed[0] ^= 0x20;
                                fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
                                    .unwrap();
                                fs::write(&path, changed).unwrap();
                                fs::set_permissions(&path, fs::Permissions::from_mode(0o400))
                                    .unwrap();
                            }
                            _ => unreachable!(),
                        }
                        Ok(())
                    })
                    .is_err(),
                    "C1 retained leaf admitted {attack} of {relative}"
                );
                fs::remove_dir_all(parent_path).unwrap();
            }
        }
    }
}
