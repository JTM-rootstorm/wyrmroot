use deepwyrm_syscall::{DW_OBJECT_TYPE_CHANNEL, DwHandle};
use wyrmroot_device_proto::ControlIdentityV1_1;
use wyrmroot_device_proto::connector::ConnectorMessage;
use wyrmroot_device_proto::control::ControlEndpoint;
use wyrmroot_device_proto::coordinator::{
    AttemptGeneration, BundleGeneration, EndpointGeneration, EndpointId,
};
use wyrmroot_device_proto::manifest::RoleId;
use wyrmroot_devmgr::connector::{
    ConnectorAction, ConnectorBroker, ConnectorSlot, PublishedDriver,
};
use wyrmroot_stream_proto as _;
use wyrmroot_uart16550_core as _;
use wyrmroot_uart16550d::{RAW_STREAM_RIGHTS, ReceivedStreamEndpoint, StreamAttachment};

fn driver() -> PublishedDriver {
    PublishedDriver {
        publication_generation: 10,
        control: ControlIdentityV1_1 {
            role_id: RoleId(1),
            bundle_generation: BundleGeneration(2),
            attempt_generation: AttemptGeneration(3),
            endpoint: ControlEndpoint {
                id: EndpointId(4),
                generation: EndpointGeneration(5),
            },
            transaction_id: 6,
        },
    }
}

fn connect_once(
    broker: &mut ConnectorBroker,
    driver: &mut StreamAttachment,
    transaction: u64,
) -> wyrmroot_devmgr::connector::AttachCorrelation {
    let ConnectorAction::AllocatePair {
        attach,
        driver_message,
    } = broker
        .begin_connect(ConnectorMessage::ConnectStream {
            publication_generation: 10,
            client_transaction_id: transaction,
        })
        .unwrap()
    else {
        panic!("allocate pair");
    };
    broker.driver_endpoint_moved(attach).unwrap();
    let ready = driver
        .attach(
            driver_message,
            ReceivedStreamEndpoint {
                handle: DwHandle(transaction + 100),
                object_type: DW_OBJECT_TYPE_CHANNEL,
                rights: RAW_STREAM_RIGHTS,
                reserved0: 0,
                reserved: [0; 2],
            },
        )
        .unwrap();
    broker.accept_stream_ready(ready).unwrap();
    assert!(matches!(
        broker.connected_response(),
        Ok(ConnectorMessage::Connected { .. })
    ));
    broker.client_endpoint_moved().unwrap();
    attach
}

#[test]
fn direct_driver_endpoint_ready_and_reconnect_join_exactly() {
    let current = driver();
    let mut broker = ConnectorBroker::new(Some(current), 100, 200).unwrap();
    let mut driver = StreamAttachment::new(current.control);

    let first = connect_once(&mut broker, &mut driver, 7);
    broker.active_client_released(first).unwrap();
    let (detached, _) = driver.detach().unwrap();
    broker.driver_detached(detached).unwrap();
    assert_eq!(broker.slot(), ConnectorSlot::Empty);

    let second = connect_once(&mut broker, &mut driver, 8);
    assert!(second.attach_transaction_id > first.attach_transaction_id);
    assert!(second.stream_generation > first.stream_generation);
}
