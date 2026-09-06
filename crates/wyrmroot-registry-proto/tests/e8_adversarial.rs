// SPDX-License-Identifier: GPL-3.0-or-later

use wyrmroot_registry_proto::{
    Header, Message, MessageType, ProtocolVersion, SERVICE_LIST_PREFIX_BYTES,
    SERVICE_LIST_RECORD_BYTES, ServiceListRecord, encode_service_list, parse,
};

fn header(generation: u64, transaction: u64) -> Header {
    Header {
        message_type: MessageType::ServiceList,
        registry_generation: generation,
        endpoint_id: generation + 1,
        endpoint_generation: generation + 2,
        transaction_id: transaction,
    }
}

fn records() -> [ServiceListRecord<'static>; 2] {
    [
        ServiceListRecord {
            protocol_id: 11,
            service_generation: 12,
            versions: [
                ProtocolVersion { major: 1, minor: 0 },
                ProtocolVersion::default(),
                ProtocolVersion::default(),
                ProtocolVersion::default(),
            ],
            version_count: 1,
            service_name: b"alpha",
        },
        ServiceListRecord {
            protocol_id: 21,
            service_generation: 22,
            versions: [
                ProtocolVersion { major: 1, minor: 0 },
                ProtocolVersion::default(),
                ProtocolVersion::default(),
                ProtocolVersion::default(),
            ],
            version_count: 1,
            service_name: b"zeta",
        },
    ]
}

fn page(header: Header) -> Vec<u8> {
    let mut bytes = [0; SERVICE_LIST_PREFIX_BYTES + 2 * SERVICE_LIST_RECORD_BYTES];
    let size = encode_service_list(header, 0, 1, 2, &records(), &mut bytes).unwrap();
    bytes[..size].to_vec()
}

#[test]
fn enumeration_page_exhausts_truncation_count_length_and_padding_mutations() {
    let bytes = page(header(31, 34));
    for cut in 0..bytes.len() {
        assert!(parse(&bytes[..cut], 0).is_err());
    }
    assert!(parse(&bytes, 1).is_err());

    for (offset, value) in [(64, 1_u16), (66, 2), (68, 1), (70, 3)] {
        let mut malformed = bytes.clone();
        malformed[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
        assert!(parse(&malformed, 0).is_err(), "page field {offset}");
    }
    for offset in [16, 20] {
        let mut malformed = bytes.clone();
        malformed[offset..offset + 4].fill(0xff);
        assert!(parse(&malformed, 0).is_err());
    }

    for offset in 72..SERVICE_LIST_PREFIX_BYTES {
        let mut malformed = bytes.clone();
        malformed[offset] ^= 1;
        assert!(
            parse(&malformed, 0).is_err(),
            "page reserved offset {offset}"
        );
    }

    let record_bases = [
        SERVICE_LIST_PREFIX_BYTES,
        SERVICE_LIST_PREFIX_BYTES + SERVICE_LIST_RECORD_BYTES,
    ];
    let mut record_cases = 0;
    for base in record_bases {
        for (offset, width) in [(0, 8), (8, 8)] {
            let mut malformed = bytes.clone();
            malformed[base + offset..base + offset + width].fill(0);
            assert!(
                parse(&malformed, 0).is_err(),
                "record base {base} offset {offset}"
            );
            record_cases += 1;
        }
        for (offset, width) in [(16, 2), (18, 1), (19, 1), (20, 4), (44, 1)] {
            let mut malformed = bytes.clone();
            malformed[base + offset..base + offset + width].fill(0xff);
            assert!(
                parse(&malformed, 0).is_err(),
                "record base {base} offset {offset}"
            );
            record_cases += 1;
        }
    }
    assert_eq!(record_cases, 14);

    let mut padding_cases = 0;
    for base in record_bases {
        for offset in (19..24).chain(28..40).chain(45..SERVICE_LIST_RECORD_BYTES) {
            let mut malformed = bytes.clone();
            malformed[base + offset] ^= 1;
            assert!(
                parse(&malformed, 0).is_err(),
                "record padding base {base} offset {offset}"
            );
            padding_cases += 1;
        }
    }
    assert_eq!(padding_cases, 280);
}

#[test]
fn replay_and_cross_generation_pages_preserve_their_whole_tuples() {
    let old_header = header(41, 44);
    let current_header = header(51, 54);
    let old_bytes = page(old_header);
    let replay_bytes = page(old_header);
    let current_bytes = page(current_header);
    let Message::ServiceList(old_page) = parse(&old_bytes, 0).unwrap().message else {
        panic!("expected old page")
    };
    let old_names = [
        old_page.record(0).unwrap().service_name,
        old_page.record(1).unwrap().service_name,
    ];
    assert_eq!(old_names, [b"alpha".as_slice(), b"zeta".as_slice()]);

    let old_parsed = parse(&old_bytes, 0).unwrap();
    let replayed = parse(&replay_bytes, 0).unwrap();
    let current = parse(&current_bytes, 0).unwrap();
    assert_eq!(old_parsed.header, old_header);
    assert_eq!(replayed.header, old_header);
    assert_eq!(current.header, current_header);
    assert_ne!(replayed.header, current.header);
}
