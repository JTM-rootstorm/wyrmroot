use wyrmroot_runtime as _;
use {deepwyrm_syscall as _, wyrmroot_device_proto as _, wyrmroot_loader as _};

const ACTOR: &str = include_str!("../src/uart16550d.rs");

#[test]
fn c5_actor_validates_exact_bundle_before_ready_without_device_io() {
    let c5 = &ACTOR[ACTOR.find("fn run_c5_driver(").unwrap()..];
    let receive = c5.find("receive_channel(control").unwrap();
    let resource_type = c5.find("DW_OBJECT_TYPE_DEVICE_RESOURCE").unwrap();
    let interrupt_type = c5.find("DW_OBJECT_TYPE_INTERRUPT").unwrap();
    let resource_info = c5.find("device_resource_info").unwrap();
    let interrupt_info = c5.find("interrupt_info").unwrap();
    let ready = c5.find("ControlMessage::Ready").unwrap();
    assert!(receive < resource_type && resource_type < interrupt_type);
    assert!(interrupt_type < resource_info && resource_info < interrupt_info);
    assert!(interrupt_info < ready);
    assert!(c5.contains("counts.handles != 2"));
    assert!(c5.contains("resource.pio_base != 0x2f8"));
    assert!(c5.contains("resource.pio_length != 8"));
    assert!(c5.contains("interrupt.source != 3"));
    assert!(c5.contains("interrupt.state != DW_INTERRUPT_STATE_ARMED"));
    assert!(!c5.contains("device_pio_read"));
    assert!(!c5.contains("device_pio_write"));
    assert!(!c5.contains("interrupt_ack"));
}

#[test]
fn malformed_intake_and_retire_both_close_the_two_authority_handles() {
    let c5 = &ACTOR[ACTOR.find("fn run_c5_driver(").unwrap()..];
    assert!(c5.contains("return close_c5_intake(control, &handles, 18)"));
    assert!(c5.contains("return close_c5_intake(control, &handles, 19)"));
    assert!(c5.contains("return close_c5_intake(control, &handles, 21)"));
    assert!(c5.contains("return close_c5_intake(control, &handles, 22)"));
    let cleanup = &c5[c5.find("fn close_c5_intake(").unwrap()..];
    let interrupt = cleanup.find("close_handle(handles[1].handle)").unwrap();
    let resource = cleanup.find("close_handle(handles[0].handle)").unwrap();
    let control = cleanup.find("close_handle(control)").unwrap();
    assert!(interrupt < resource && resource < control);
    assert!(c5.contains("ControlMessage::Retire"));
    assert!(c5.contains("let result = hold_until_retire(control, ready)"));
}

#[test]
fn selector29_failure_is_triggered_only_after_ready_and_releases_both_handles() {
    let actor = &ACTOR[ACTOR.find("fn run_c5_driver(").unwrap()..];
    let ready = actor.find("send_channel(control, &ready_bytes").unwrap();
    let selector = actor.find("selector29_should_fail(").unwrap();
    let trigger = actor
        .find("hold_until_failure_trigger(control, ready)")
        .unwrap();
    let failure = actor.find("FailureCode::IntentionalRestart").unwrap();
    let close_interrupt = actor[trigger..]
        .find("close_handle(handles[1].handle)")
        .unwrap();
    let close_resource = actor[trigger..]
        .find("close_handle(handles[0].handle)")
        .unwrap();
    assert!(ready < selector && selector < trigger && trigger < failure);
    assert!(close_interrupt < close_resource);
    assert!(actor.contains("ControlMessage::TriggerFailure"));
}
