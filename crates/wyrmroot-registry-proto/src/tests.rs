use super::*;

fn header(kind: MessageType) -> Header {
    Header {
        message_type: kind,
        registry_generation: 7,
        endpoint_id: 0,
        endpoint_generation: 0,
        transaction_id: 11,
    }
}

#[test]
fn golden_install_publication_round_trips_without_allocation() {
    let versions = [
        ProtocolVersion { major: 1, minor: 0 },
        ProtocolVersion { major: 1, minor: 2 },
    ];
    let mut bytes = [0u8; 160];
    let size = encode_install_publication(
        header(MessageType::InstallPublication),
        21,
        2,
        3,
        5,
        9,
        0x1200,
        &versions,
        b"org.wyrmroot.echo",
        &mut bytes,
    )
    .unwrap();
    let parsed = parse(&bytes[..size], 1).unwrap();
    let Message::InstallPublication(value) = parsed.message else {
        panic!("wrong message")
    };
    assert_eq!(value.endpoint_id, 21);
    assert_eq!(value.endpoint_generation, 2);
    assert_eq!(value.supervisor_role_id, 3);
    assert_eq!(value.versions.get(1), Some(versions[1]));
    assert_eq!(value.service_name, b"org.wyrmroot.echo");
}

#[test]
fn exact_envelope_and_authority_scope_fail_closed() {
    let mut bytes = [0u8; HEADER_BYTES];
    let mut endpoint = header(MessageType::Publish);
    endpoint.endpoint_id = 2;
    endpoint.endpoint_generation = 4;
    encode_header(endpoint, 0, HEADER_BYTES, &mut bytes).unwrap();
    assert_eq!(parse(&bytes, 0).unwrap().message, Message::Publish);
    for offset in [0usize, 4, 6, 12, 16, 20, 56] {
        let mut malformed = bytes;
        malformed[offset] ^= 1;
        assert!(parse(&malformed, 0).is_err(), "offset {offset}");
    }
    for range in [24..32, 32..40, 40..48, 48..56] {
        let mut malformed = bytes;
        malformed[range].fill(0);
        assert!(parse(&malformed, 0).is_err());
    }
}

#[test]
fn names_versions_and_moved_handles_are_bounded() {
    assert_eq!(validate_name(b"org.wyrmroot.echo"), Ok(()));
    for name in [b"".as_slice(), b"Upper", b"bad/name", b"bad_underscore"] {
        assert_eq!(validate_name(name), Err(Error::InvalidServiceName));
    }
    let versions = [
        ProtocolVersion { major: 1, minor: 0 },
        ProtocolVersion { major: 1, minor: 0 },
    ];
    let mut bytes = [0u8; 140];
    assert_eq!(
        encode_install_publication(
            header(MessageType::InstallPublication),
            1,
            1,
            1,
            1,
            1,
            1,
            &versions,
            b"echo",
            &mut bytes
        ),
        Err(Error::NoncanonicalVersions)
    );
}

#[test]
fn response_and_direct_offer_encoders_round_trip_exactly() {
    let mut endpoint = header(MessageType::Published);
    endpoint.endpoint_id = 21;
    endpoint.endpoint_generation = 3;
    let mut bytes = [0u8; 128];
    let size = encode_empty(endpoint, &mut bytes).unwrap();
    assert_eq!(
        parse(&bytes[..size], 0).unwrap().message,
        Message::Published
    );

    endpoint.message_type = MessageType::GenerationChanged;
    let size = encode_generation_changed(endpoint, 19, &mut bytes).unwrap();
    assert_eq!(
        parse(&bytes[..size], 0).unwrap().message,
        Message::GenerationChanged {
            service_generation: 19
        }
    );

    endpoint.message_type = MessageType::ConnectOffer;
    let lookup = Lookup {
        protocol_id: 0x1300,
        version: ProtocolVersion { major: 1, minor: 2 },
        service_name: b"org.wyrmroot.echo",
    };
    let size = encode_lookup(endpoint, lookup, &mut bytes).unwrap();
    assert_eq!(
        parse(&bytes[..size], 1).unwrap().message,
        Message::ConnectOffer(lookup)
    );

    endpoint.message_type = MessageType::Watch;
    let watch = Watch {
        protocol_id: 0x1300,
        last_observed_generation: 19,
        service_name: b"org.wyrmroot.echo",
    };
    let size = encode_watch(endpoint, watch, &mut bytes).unwrap();
    assert_eq!(
        parse(&bytes[..size], 0).unwrap().message,
        Message::Watch(watch)
    );

    endpoint.message_type = MessageType::Cancelled;
    let size = encode_cancel(endpoint, 17, &mut bytes).unwrap();
    assert_eq!(
        parse(&bytes[..size], 0).unwrap().message,
        Message::Cancelled {
            target_transaction_id: 17
        }
    );
}

#[test]
fn correlation_environment_is_canonical_bounded_and_exact() {
    let correlation = Correlation {
        registry_generation: u64::MAX,
        endpoint_id: 17,
        endpoint_generation: 2,
    };
    let packed = CorrelationEnvironment::new(correlation).unwrap();
    let entries = [
        packed.entry(0).unwrap(),
        packed.entry(1).unwrap(),
        packed.entry(2).unwrap(),
    ];
    assert_eq!(parse_correlation_environment(&entries), Ok(correlation));
    for malformed in [
        ["WYR_REGISTRY_GENERATION=0", entries[1], entries[2]],
        ["WYR_REGISTRY_GENERATION=01", entries[1], entries[2]],
        [
            "WYR_REGISTRY_GENERATION=18446744073709551616",
            entries[1],
            entries[2],
        ],
        [entries[1], entries[0], entries[2]],
        [entries[0], entries[0], entries[2]],
    ] {
        assert_eq!(
            parse_correlation_environment(&malformed),
            Err(Error::InvalidCorrelationEnvironment)
        );
    }
    assert_eq!(
        parse_correlation_environment(&entries[..2]),
        Err(Error::InvalidCorrelationEnvironment)
    );
    let extra = [entries[0], entries[1], entries[2], "EXTRA=1"];
    assert_eq!(
        parse_correlation_environment(&extra),
        Err(Error::InvalidCorrelationEnvironment)
    );
    let malformed = ["WYR_REGISTRY_GENERATION=seven", entries[1], entries[2]];
    assert_eq!(
        parse_correlation_environment(&malformed),
        Err(Error::InvalidCorrelationEnvironment)
    );
    assert_eq!(
        CorrelationEnvironment::new(Correlation {
            endpoint_id: 0,
            ..correlation
        }),
        Err(Error::InvalidCorrelationEnvironment)
    );
}

#[test]
fn canonical_service_list_pages_have_fixed_records_and_padding() {
    let mut endpoint = header(MessageType::ServiceList);
    endpoint.endpoint_id = 21;
    endpoint.endpoint_generation = 3;
    let versions = [
        ProtocolVersion { major: 1, minor: 0 },
        ProtocolVersion { major: 1, minor: 2 },
        ProtocolVersion::default(),
        ProtocolVersion::default(),
    ];
    let records = [
        ServiceListRecord {
            protocol_id: 7,
            service_generation: 11,
            versions,
            version_count: 2,
            service_name: b"alpha",
        },
        ServiceListRecord {
            protocol_id: 8,
            service_generation: 12,
            versions,
            version_count: 2,
            service_name: b"zeta",
        },
    ];
    let mut bytes = [0xAA; 416];
    let size = encode_service_list(endpoint, 0, 1, 2, &records, &mut bytes).unwrap();
    assert_eq!(size, 416);
    let Message::ServiceList(page) = parse(&bytes, 0).unwrap().message else {
        panic!("wrong message")
    };
    assert_eq!(
        (
            page.page_index,
            page.page_count,
            page.record_count,
            page.total_count
        ),
        (0, 1, 2, 2)
    );
    assert_eq!(page.record(0).unwrap().service_name, b"alpha");
    assert_eq!(
        page.version(0, 1),
        Some(ProtocolVersion { major: 1, minor: 2 })
    );
    assert!(bytes[80 + 40 + 5..80 + 168].iter().all(|byte| *byte == 0));

    let size = encode_service_list(endpoint, 0, 1, 0, &[], &mut bytes).unwrap();
    assert_eq!(size, 80);
    assert!(
        matches!(parse(&bytes[..size], 0).unwrap().message, Message::ServiceList(page) if page.record_count == 0)
    );
}

#[test]
fn service_list_error_and_watch_malformed_forms_fail_closed() {
    let mut endpoint = header(MessageType::ServiceList);
    endpoint.endpoint_id = 21;
    endpoint.endpoint_generation = 3;
    let versions = [
        ProtocolVersion { major: 1, minor: 0 },
        ProtocolVersion::default(),
        ProtocolVersion::default(),
        ProtocolVersion::default(),
    ];
    let records = [ServiceListRecord {
        protocol_id: 7,
        service_generation: 11,
        versions,
        version_count: 1,
        service_name: b"alpha",
    }];
    let mut bytes = [0u8; 416];
    assert_eq!(
        encode_service_list(endpoint, 0, 2, 3, &records, &mut bytes),
        Err(Error::InvalidServiceList)
    );
    let size = encode_service_list(endpoint, 0, 1, 1, &records, &mut bytes).unwrap();
    for offset in [72usize, 76, 99, 80 + 44] {
        let mut malformed = bytes;
        malformed[offset] = 1;
        assert!(parse(&malformed[..size], 0).is_err(), "offset {offset}");
    }

    endpoint.message_type = MessageType::Error;
    assert_eq!(
        encode_error(endpoint, ErrorCode::Capacity, &mut bytes).unwrap(),
        72
    );
    assert_eq!(
        parse(&bytes[..72], 0).unwrap().message,
        Message::Error {
            code: ErrorCode::Capacity
        }
    );
    bytes[64..68].fill(0);
    assert_eq!(parse(&bytes[..72], 0), Err(Error::InvalidErrorCode));
    bytes[64..68].copy_from_slice(&14u32.to_le_bytes());
    assert_eq!(parse(&bytes[..72], 0), Err(Error::InvalidErrorCode));

    endpoint.message_type = MessageType::Watch;
    let name = b"alpha";
    let watch_size = 88 + name.len();
    encode_header(endpoint, 0, watch_size, &mut bytes).unwrap();
    put_u64(&mut bytes, 64, 7).unwrap();
    put_u64(&mut bytes, 72, 0).unwrap();
    put_u16(&mut bytes, 80, name.len() as u16).unwrap();
    bytes[88..watch_size].copy_from_slice(name);
    assert!(matches!(
        parse(&bytes[..watch_size], 0).unwrap().message,
        Message::Watch(_)
    ));
    bytes[84] = 1;
    assert_eq!(parse(&bytes[..watch_size], 0), Err(Error::NonzeroReserved));
}

#[test]
fn minimal_header_decode_preserves_recoverable_correlation() {
    let mut endpoint = header(MessageType::Enumerate);
    endpoint.endpoint_id = 21;
    endpoint.endpoint_generation = 3;
    let mut bytes = [0u8; HEADER_BYTES];
    encode_empty(endpoint, &mut bytes).unwrap();
    bytes[4] = 9;
    bytes[12] = 1;
    let decoded = decode_header(&bytes).unwrap();
    assert_eq!(decoded.transaction_id, endpoint.transaction_id);
    assert_eq!(decoded.endpoint_id, endpoint.endpoint_id);
    assert_eq!(decoded.major, 9);
    assert_eq!(decoded.flags, 1);
    bytes[48..56].fill(0);
    assert_eq!(decode_header(&bytes), Err(Error::ZeroIdentity));
}
