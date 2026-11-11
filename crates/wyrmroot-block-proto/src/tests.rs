use super::*;

extern crate std;
use std::vec::Vec;

fn info() -> Info {
    Info {
        block_size: 512,
        flags: INFO_FLUSH,
        block_count: 0x1_0000,
        max_transfer_blocks: 256,
    }
}

fn transfer() -> Transfer {
    Transfer {
        lba: 7,
        block_count: 3,
        buffer_offset: 0x2000,
    }
}

fn every_body() -> [Body; 7] {
    [
        Body::GetInfo,
        Body::Info(info()),
        Body::Attach {
            byte_len: 0x10_0000,
        },
        Body::Read(transfer()),
        Body::Write(transfer()),
        Body::Flush,
        Body::Complete(Status::OutOfRange),
    ]
}

fn wire(body: Body) -> Vec<u8> {
    let mut bytes = [0u8; MAX_BYTES];
    let size = encode(
        Message {
            transaction_id: 0x55,
            body,
        },
        &mut bytes,
    )
    .unwrap();
    bytes[..size].to_vec()
}

#[test]
fn every_message_round_trips_at_its_fixed_size_and_handle_count() {
    for body in every_body() {
        let bytes = wire(body);
        assert_eq!(bytes.len(), body.wire_size());
        assert_eq!(
            parse(&bytes, body.handle_count()),
            Ok(Message {
                transaction_id: 0x55,
                body
            })
        );
    }
    assert_eq!(Body::Attach { byte_len: 4096 }.handle_count(), 1);
    assert!(
        every_body()
            .iter()
            .all(|body| body.wire_size() <= MAX_BYTES)
    );
}

#[test]
fn the_wire_layout_is_little_endian_at_fixed_offsets() {
    let bytes = wire(Body::Read(transfer()));
    assert_eq!(&bytes[..4], b"WRBD");
    assert_eq!(&bytes[4..8], &[1, 0, 0, 0]);
    assert_eq!(&bytes[8..12], &4u32.to_le_bytes());
    assert_eq!(&bytes[12..16], &56u32.to_le_bytes());
    assert_eq!(&bytes[24..32], &0x55u64.to_le_bytes());
    assert_eq!(&bytes[32..40], &7u64.to_le_bytes());
    assert_eq!(&bytes[40..44], &3u32.to_le_bytes());
    assert_eq!(&bytes[48..56], &0x2000u64.to_le_bytes());
}

#[test]
fn only_client_messages_are_requests() {
    let requests: Vec<bool> = every_body().iter().map(|body| body.is_request()).collect();
    assert_eq!(requests, [true, false, true, true, true, true, false]);
}

#[test]
fn malformed_framing_is_refused_before_any_body_field_is_read() {
    let good = wire(Body::Complete(Status::Ok));
    // Truncated to the header with the size field adjusted: a COMPLETE
    // without its body must not be read past the end.
    let mut short = good[..HEADER_BYTES].to_vec();
    short[12..16].copy_from_slice(&(HEADER_BYTES as u32).to_le_bytes());
    assert_eq!(parse(&short, 0), Err(Error::WrongSize));
    assert_eq!(parse(&good[..HEADER_BYTES - 1], 0), Err(Error::WrongSize));
    assert_eq!(parse(&[], 0), Err(Error::WrongSize));

    let mut cases: Vec<(Vec<u8>, Error)> = Vec::new();
    let mut bad = good.clone();
    bad[12] = 41;
    cases.push((bad, Error::WrongSize));
    let mut bad = good.clone();
    bad[0] = b'X';
    cases.push((bad, Error::WrongMagic));
    let mut bad = good.clone();
    bad[4] = 2;
    cases.push((bad, Error::WrongVersion));
    let mut bad = good.clone();
    bad[6] = 1;
    cases.push((bad, Error::WrongVersion));
    let mut bad = good.clone();
    bad[8] = 99;
    cases.push((bad, Error::UnknownMessage));
    let mut bad = good.clone();
    bad[20] = 1;
    cases.push((bad, Error::NonzeroReserved));
    let mut bad = good.clone();
    bad[24..32].fill(0);
    cases.push((bad, Error::ZeroTransaction));
    let mut bad = good.clone();
    bad[36] = 1;
    cases.push((bad, Error::NonzeroReserved));
    let mut bad = good.clone();
    bad[32] = 9;
    cases.push((bad, Error::UnknownStatus));
    let mut bad = good.clone();
    bad[16] = 1;
    cases.push((bad, Error::WrongHandleCount));
    for (bytes, error) in cases {
        assert_eq!(parse(&bytes, 0), Err(error), "{bytes:?}");
    }
}

#[test]
fn the_received_handle_count_must_match_the_type() {
    let attach = wire(Body::Attach { byte_len: 4096 });
    assert!(parse(&attach, 1).is_ok());
    assert_eq!(parse(&attach, 0), Err(Error::WrongHandleCount));
    assert_eq!(parse(&attach, 2), Err(Error::WrongHandleCount));
    let read = wire(Body::Read(transfer()));
    assert_eq!(parse(&read, 1), Err(Error::WrongHandleCount));
    let mut declared = read.clone();
    declared[16] = 1;
    assert_eq!(parse(&declared, 1), Err(Error::WrongHandleCount));
}

#[test]
fn body_fields_are_validated_in_both_directions() {
    let bad_bodies = [
        (
            Body::Info(Info {
                flags: 1 << 2,
                ..info()
            }),
            Error::UnknownFlags,
        ),
        (
            Body::Info(Info {
                block_size: 768,
                ..info()
            }),
            Error::InvalidField,
        ),
        (
            Body::Info(Info {
                block_size: 8192,
                ..info()
            }),
            Error::InvalidField,
        ),
        (
            Body::Info(Info {
                block_count: 0,
                ..info()
            }),
            Error::InvalidField,
        ),
        (
            Body::Info(Info {
                max_transfer_blocks: 0,
                ..info()
            }),
            Error::InvalidField,
        ),
        (Body::Attach { byte_len: 0 }, Error::InvalidField),
        (Body::Attach { byte_len: 4097 }, Error::InvalidField),
        (
            Body::Read(Transfer {
                block_count: 0,
                ..transfer()
            }),
            Error::InvalidField,
        ),
        (
            Body::Write(Transfer {
                block_count: 0,
                ..transfer()
            }),
            Error::InvalidField,
        ),
    ];
    for (body, error) in bad_bodies {
        let mut bytes = [0u8; MAX_BYTES];
        assert_eq!(
            encode(
                Message {
                    transaction_id: 1,
                    body
                },
                &mut bytes
            ),
            Err(error)
        );
        // The same body forged on the wire is refused by the parser.
        let mut forged = wire(match body {
            Body::Info(_) => Body::Info(info()),
            Body::Attach { .. } => Body::Attach { byte_len: 4096 },
            Body::Read(_) => Body::Read(transfer()),
            _ => Body::Write(transfer()),
        });
        match body {
            Body::Info(bad) => {
                forged[32..36].copy_from_slice(&bad.block_size.to_le_bytes());
                forged[36..40].copy_from_slice(&bad.flags.to_le_bytes());
                forged[40..48].copy_from_slice(&bad.block_count.to_le_bytes());
                forged[48..52].copy_from_slice(&bad.max_transfer_blocks.to_le_bytes());
            }
            Body::Attach { byte_len } => forged[32..40].copy_from_slice(&byte_len.to_le_bytes()),
            Body::Read(bad) | Body::Write(bad) => {
                forged[40..44].copy_from_slice(&bad.block_count.to_le_bytes());
            }
            _ => unreachable!(),
        }
        assert_eq!(parse(&forged, body.handle_count()), Err(error));
    }
}

#[test]
fn encode_refuses_a_zero_transaction_and_a_short_buffer() {
    let mut bytes = [0u8; MAX_BYTES];
    assert_eq!(
        encode(
            Message {
                transaction_id: 0,
                body: Body::Flush
            },
            &mut bytes
        ),
        Err(Error::ZeroTransaction)
    );
    assert_eq!(
        encode(
            Message {
                transaction_id: 1,
                body: Body::Read(transfer())
            },
            &mut bytes[..HEADER_BYTES]
        ),
        Err(Error::WrongSize)
    );
}
