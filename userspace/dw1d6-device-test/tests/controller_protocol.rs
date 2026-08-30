use deepwyrm_syscall as _;
use wyrmroot_dw1d6_device_test::{
    BAD_STATE_STATUS, ControllerMessage, ControllerModel, ControllerProtocolError, DELIVERY_CYCLES,
    MessageKind, PENDING_DELIVERY_SEQUENCE, RACE_PERMIT_SEQUENCE, STALE_DELIVERY_SEQUENCE,
    deliver_command, owner_ack_permit,
};
use wyrmroot_loader as _;
use wyrmroot_runtime as _;

fn message(kind: MessageKind, sequence: u64, status: i32) -> ControllerMessage {
    ControllerMessage::new(kind, sequence, status)
}

#[test]
fn controller_requires_five_registered_delivery_cycles_then_race_stale_replacement_and_reap() {
    let mut controller = ControllerModel::new();
    assert_eq!(
        controller.accept(message(MessageKind::FirstOwnerBound, 0, 0)),
        Ok(None)
    );
    for sequence in 1..=DELIVERY_CYCLES {
        assert_eq!(
            controller.accept(message(MessageKind::OwnerWaitIntent, sequence, 0)),
            Ok(Some(deliver_command(sequence, 0)))
        );
        assert_eq!(
            controller.accept(message(MessageKind::TriggerComplete, sequence, 0)),
            Ok(None)
        );
        let next = controller
            .accept(message(MessageKind::OwnerWaitComplete, sequence, 0))
            .unwrap();
        if sequence < DELIVERY_CYCLES {
            assert_eq!(next, Some(owner_ack_permit(sequence)));
        } else {
            assert_eq!(next, Some(deliver_command(PENDING_DELIVERY_SEQUENCE, 0)));
            assert_eq!(
                controller.accept(message(
                    MessageKind::TriggerComplete,
                    PENDING_DELIVERY_SEQUENCE,
                    0,
                )),
                Ok(Some(deliver_command(RACE_PERMIT_SEQUENCE, 0)))
            );
            assert_eq!(
                controller.accept(message(
                    MessageKind::TriggerComplete,
                    RACE_PERMIT_SEQUENCE,
                    0
                )),
                Ok(Some(owner_ack_permit(DELIVERY_CYCLES)))
            );
        }
        assert_eq!(
            controller.accept(message(MessageKind::OwnerAckComplete, sequence, 0)),
            Ok(None)
        );
    }
    assert_eq!(
        controller.accept(message(MessageKind::FirstOwnerClosed, 0, 0)),
        Ok(Some(deliver_command(
            STALE_DELIVERY_SEQUENCE,
            BAD_STATE_STATUS,
        )))
    );
    assert_eq!(
        controller.accept(message(
            MessageKind::TriggerComplete,
            STALE_DELIVERY_SEQUENCE,
            BAD_STATE_STATUS,
        )),
        Ok(None)
    );
    assert_eq!(
        controller.accept(message(MessageKind::ReplacementBound, 0, 0)),
        Ok(None)
    );
    assert_eq!(
        controller.accept(message(MessageKind::ReplacementWaitIntent, 0, 0)),
        Ok(None)
    );
    assert_eq!(
        controller.trigger_finish_command(),
        Ok(message(MessageKind::TriggerFinish, 0, 0))
    );
    assert_eq!(
        controller.accept(message(MessageKind::TriggerFinished, 0, 0)),
        Ok(None)
    );
    assert!(controller.is_complete());
}

#[test]
fn controller_rejects_the_race_permit_before_pending_delivery() {
    let mut controller = ControllerModel::new();
    controller
        .accept(message(MessageKind::FirstOwnerBound, 0, 0))
        .unwrap();
    assert_eq!(
        controller.accept(message(
            MessageKind::TriggerComplete,
            RACE_PERMIT_SEQUENCE,
            0
        )),
        Err(ControllerProtocolError::OutOfOrder)
    );
}
