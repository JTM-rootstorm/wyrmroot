use deepwyrm_syscall as _;
use wyrmroot_dw1d6_device_test as _;
use wyrmroot_loader as _;
use wyrmroot_runtime as _;

const OWNER: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/bin/owner.rs"));
const TRIGGER: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/bin/trigger.rs"));
const REPLACEMENT_OWNER: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/src/bin/replacement_owner.rs"
));
const RUNTIME: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../crates/wyrmroot-runtime/src/dw1d6.rs"
));

#[test]
fn owner_roles_are_scoped_and_use_com2_scratch_only() {
    assert!(OWNER.contains("claim_device_resource"));
    assert!(OWNER.contains("create_interrupt"));
    assert!(OWNER.contains("SCRATCH_OFFSET"));
    assert!(OWNER.contains("PIO_WIDTH_1"));
    assert!(!OWNER.contains("PIO_WIDTH_2"));
    assert!(!OWNER.contains("PIO_WIDTH_4"));
    assert!(REPLACEMENT_OWNER.contains("claim_device_resource"));
    assert!(REPLACEMENT_OWNER.contains("create_interrupt"));
    assert!(!TRIGGER.contains("claim_device_resource"));
    assert!(!TRIGGER.contains("create_interrupt"));
    assert!(!TRIGGER.contains("device_pio_"));
    assert!(TRIGGER.contains("d6_deliver"));
    assert!(OWNER.contains("OwnerWaitIntent"));
    assert!(REPLACEMENT_OWNER.contains("ReplacementWaitIntent"));
}

#[test]
fn private_carrier_matches_frozen_op_layouts_and_reports_dwd6e1_events() {
    assert!(RUNTIME.contains("DwSyscallId(0xffff_ff1d)"));
    assert!(RUNTIME.contains("[1, owner.0, trigger.0, nonce, challenge, 0]"));
    assert!(RUNTIME.contains("[2, interrupt.0, lease_generation, nonce, challenge, 0]"));
    assert!(RUNTIME.contains("[3, sequence, nonce, challenge, 0, 0]"));
    assert!(
        RUNTIME.contains("private_call([4, event.wire(), value, auxiliary, nonce, challenge])")
    );
    for event in [
        "BootstrapOutsideDomainClaimRejected",
        "OwnerScratchSaved",
        "OwnerChallengeWritten",
        "OwnerChallengeReadBack",
        "OwnerScratchRestored",
        "BootstrapReady",
    ] {
        assert!(
            RUNTIME.contains(event),
            "missing permitted DWD6E1 event {event}"
        );
    }
    for forbidden in [
        "BootstrapActorsArmed",
        "OwnerResourceValidated",
        "OwnerInterruptValidated",
        "OwnerBlockedBeforeDelivery",
        "OwnerWokeSignaled",
        "OwnerAckRearmed",
        "ReplacementResourceValidated",
        "ReplacementInterruptValidated",
        "ReplacementPendingCloseRequested",
    ] {
        assert!(
            !RUNTIME.contains(forbidden),
            "userspace private report surface must not expose {forbidden}"
        );
    }
}
