extern crate std;

use std::vec::Vec;

use crate::namespace::{self, MOUNT_READ_ONLY};
use crate::node::{
    self, ACCESS_READ, ACCESS_WRITE, Attr, Body, Entries, EntryWriter, FS_DURABLE_SYNC,
    FS_READ_ONLY, FsInfo, Kind, Lock, LockMode, MAX_BYTES, MAX_DIRENT_BYTES, MAX_IO_BYTES, Message,
};
use crate::*;

const ATTR: Attr = Attr {
    kind: Kind::File,
    access: ACCESS_READ | ACCESS_WRITE,
    size: 0x1_0000_0001,
    id: 42,
    filesystem: 0x1234_5678_9abc_def0,
};

const LOCK: Lock = Lock {
    start: 100,
    length: 0,
    mode: LockMode::Exclusive,
};

fn node_bytes(body: Body<'_>) -> Vec<u8> {
    let mut output = [0u8; MAX_BYTES];
    let size = node::encode(
        &Message {
            transaction_id: 7,
            body,
        },
        &mut output,
    )
    .unwrap();
    output[..size].to_vec()
}

fn ns_bytes(body: namespace::Body<'_>) -> Vec<u8> {
    let mut output = [0u8; namespace::MAX_BYTES];
    let size = namespace::encode(
        &namespace::Message {
            transaction_id: 9,
            body,
        },
        &mut output,
    )
    .unwrap();
    output[..size].to_vec()
}

fn entries(list: &[(Kind, &[u8])]) -> Vec<u8> {
    let mut buffer = [0u8; MAX_DIRENT_BYTES];
    let mut writer = EntryWriter::new(&mut buffer);
    for &(kind, name) in list {
        assert!(writer.push(kind, name));
    }
    writer.entries().as_bytes().to_vec()
}

#[test]
fn every_node_message_round_trips_with_its_handle_count() {
    let listing = entries(&[(Kind::Directory, b"EFI"), (Kind::File, b"kernel.elf")]);
    let data = [0x5au8; MAX_IO_BYTES];
    let bodies = [
        Body::Open {
            flags: OPEN_READ | OPEN_FILE,
            path: b"EFI/BOOT/BOOTX64.EFI",
        },
        Body::Open {
            flags: OPEN_READ,
            path: b"",
        },
        Body::GetAttr,
        Body::ReadDir { cookie: 3 },
        Body::Read {
            offset: 1 << 40,
            length: MAX_IO_BYTES as u32,
        },
        Body::Write {
            offset: 5,
            data: &data,
        },
        Body::Truncate { size: 12 },
        Body::Unlink { name: b"old" },
        Body::Sync,
        Body::QueryFilesystem,
        Body::OnOpen {
            status: Status::Ok,
            attr: Some(ATTR),
        },
        Body::OnOpen {
            status: Status::NotFound,
            attr: None,
        },
        Body::Status {
            status: Status::Ok,
            value: 8192,
        },
        Body::Attr(ATTR),
        Body::Dirents {
            next_cookie: 2,
            entries: Entries::new(&listing).unwrap(),
        },
        Body::Dirents {
            next_cookie: 0,
            entries: Entries::EMPTY,
        },
        Body::Data(&data[..100]),
        Body::Data(&[]),
        Body::FsInfo(FsInfo {
            flags: FS_READ_ONLY | FS_DURABLE_SYNC,
            name_max: 255,
            block_size: 4096,
            total_bytes: 100,
            free_bytes: 100,
        }),
        Body::Lock(LOCK),
        Body::Lock(Lock {
            start: 0,
            length: u64::MAX,
            mode: LockMode::Unlock,
        }),
        Body::TestLock(Lock {
            mode: LockMode::Shared,
            length: 9,
            ..LOCK
        }),
        Body::LockInfo(Some(LOCK)),
        Body::LockInfo(None),
    ];
    for body in bodies {
        let bytes = node_bytes(body);
        assert_eq!(bytes.len(), body.wire_size());
        let parsed = node::parse(&bytes, body.handle_count()).unwrap();
        assert_eq!(parsed.transaction_id, 7);
        assert_eq!(parsed.body, body);
        let other = 1 - body.handle_count();
        assert_eq!(
            node::parse(&bytes, other),
            Err(Error::WrongHandleCount),
            "{body:?}"
        );
    }
}

#[test]
fn directory_entries_iterate_in_order_and_writer_refuses_bad_or_oversized_names() {
    let listing = entries(&[(Kind::Directory, b"a"), (Kind::File, b"b.txt")]);
    let parsed = Entries::new(&listing).unwrap();
    let names: Vec<_> = parsed.iter().collect();
    assert_eq!(
        names,
        [(Kind::Directory, &b"a"[..]), (Kind::File, &b"b.txt"[..])]
    );

    let mut small = [0u8; 8];
    let mut writer = EntryWriter::new(&mut small);
    assert!(writer.push(Kind::File, b"abcdef"));
    assert!(!writer.push(Kind::File, b"x"));
    assert!(!writer.push(Kind::File, b".."));
    let mut buffer = [0u8; 64];
    let mut writer = EntryWriter::new(&mut buffer);
    assert!(!writer.push(Kind::File, b"a/b"));
    assert!(!writer.push(Kind::File, b""));
    assert!(writer.entries().is_empty());

    for bad in [
        &[3u8, 1, b'a'][..],       // unknown kind
        &[1, 2, b'a'][..],         // name runs past the end
        &[1, 1, b'.'][..],         // reserved name
        &[1, 0][..],               // empty name
        &[1, 1, 0][..],            // NUL
        &[1, 1, b'a', 2][..],      // trailing partial entry
        &[1, 3, b'a', b'/', b'b'], // separator inside a name
    ] {
        assert_eq!(Entries::new(bad), Err(Error::InvalidField), "{bad:?}");
    }
}

#[test]
fn paths_are_canonical_byte_strings() {
    for good in [&b""[..], b"a", b"a/b", b"\xff\xfe", b"...", b".a"] {
        assert_eq!(check_relative(good), Ok(()), "{good:?}");
    }
    let long_name = [b'n'; MAX_NAME_BYTES];
    assert_eq!(check_relative(&long_name), Ok(()));
    let too_long_name = [b'n'; MAX_NAME_BYTES + 1];
    let mut too_long_path = Vec::new();
    while too_long_path.len() <= MAX_PATH_BYTES {
        too_long_path.extend_from_slice(b"abc/");
    }
    too_long_path.pop();
    for bad in [
        &b"/a"[..],
        b"a/",
        b"a//b",
        b".",
        b"..",
        b"a/./b",
        b"a/../b",
        b"a\0b",
        &too_long_name,
        &too_long_path,
    ] {
        assert_eq!(check_relative(bad), Err(Error::InvalidPath), "{bad:?}");
    }
    for good in [&b"/"[..], b"/boot", b"/boot/EFI/BOOT"] {
        assert_eq!(check_absolute(good), Ok(()), "{good:?}");
    }
    for bad in [&b""[..], b"boot", b"//", b"/boot/", b"/./x", b"/.."] {
        assert_eq!(check_absolute(bad), Err(Error::InvalidPath), "{bad:?}");
    }
}

#[test]
fn open_flags_must_be_coherent() {
    for good in [
        OPEN_READ,
        OPEN_WRITE,
        OPEN_READ | OPEN_DIRECTORY,
        OPEN_READ | OPEN_WRITE | OPEN_FILE | OPEN_CREATE | OPEN_EXCLUSIVE,
        OPEN_WRITE | OPEN_DIRECTORY | OPEN_CREATE,
        OPEN_WRITE | OPEN_TRUNCATE,
        OPEN_WRITE | OPEN_FILE | OPEN_TRUNCATE,
    ] {
        assert_eq!(check_open_flags(good, b"x"), Ok(()), "{good:#x}");
    }
    for bad in [
        0,
        OPEN_DIRECTORY,
        OPEN_READ | 1 << 7,
        OPEN_READ | OPEN_DIRECTORY | OPEN_FILE,
        OPEN_WRITE | OPEN_CREATE,
        OPEN_READ | OPEN_EXCLUSIVE,
        OPEN_READ | OPEN_TRUNCATE,
        OPEN_WRITE | OPEN_DIRECTORY | OPEN_TRUNCATE,
    ] {
        assert_eq!(
            check_open_flags(bad, b"x"),
            Err(Error::UnknownFlags),
            "{bad:#x}"
        );
    }
    assert_eq!(
        check_open_flags(OPEN_WRITE | OPEN_FILE | OPEN_CREATE, b""),
        Err(Error::UnknownFlags)
    );
}

#[test]
fn header_damage_is_refused_before_the_body_is_read() {
    let good = node_bytes(Body::Read {
        offset: 0,
        length: 1,
    });
    let damaged = |offset: usize, value: u8| {
        let mut bytes = good.clone();
        bytes[offset] = value;
        node::parse(&bytes, 0).map(|_| ())
    };
    assert_eq!(damaged(0, b'X'), Err(Error::WrongMagic));
    assert_eq!(damaged(4, 2), Err(Error::WrongVersion));
    // A 1.0 peer is refused, as is a later minor.
    assert_eq!(damaged(6, 0), Err(Error::WrongVersion));
    assert_eq!(damaged(6, 2), Err(Error::WrongVersion));
    assert_eq!(damaged(8, 99), Err(Error::UnknownMessage));
    assert_eq!(damaged(12, 47), Err(Error::WrongSize));
    assert_eq!(damaged(16, 1), Err(Error::WrongHandleCount));
    assert_eq!(damaged(20, 1), Err(Error::NonzeroReserved));
    assert_eq!(damaged(44, 1), Err(Error::NonzeroReserved));
    let mut zero_transaction = good.clone();
    zero_transaction[24] = 0;
    assert_eq!(
        node::parse(&zero_transaction, 0),
        Err(Error::ZeroTransaction)
    );
    assert_eq!(node::parse(&good[..31], 0), Err(Error::WrongSize));

    // A header that claims a fixed-size type at the header's own length is
    // refused on size, never read past the end.
    for message_type in [3u8, 4, 6, 16, 17, 18, 21] {
        let mut short = good[..32].to_vec();
        short[8] = message_type;
        short[12] = 32;
        assert_eq!(
            node::parse(&short, 0),
            Err(Error::WrongSize),
            "{message_type}"
        );
    }
    // Variable types: a length field disagreeing with the size.
    let mut open = node_bytes(Body::Open {
        flags: OPEN_READ,
        path: b"abc",
    });
    open[36] = 4;
    assert_eq!(node::parse(&open, 1), Err(Error::WrongSize));
    let mut stub = good[..32].to_vec();
    stub[8] = 1;
    stub[12] = 32;
    stub[16] = 1;
    assert_eq!(node::parse(&stub, 1), Err(Error::WrongSize));
}

#[test]
fn node_bodies_with_bad_fields_are_refused_both_ways() {
    let encode = |body: Body<'_>| {
        let mut output = [0u8; MAX_BYTES];
        node::encode(
            &Message {
                transaction_id: 1,
                body,
            },
            &mut output,
        )
    };
    let big = [0u8; MAX_IO_BYTES + 1];
    let cases: [(Body<'_>, Error); 16] = [
        (
            Body::Lock(Lock {
                start: 1,
                length: u64::MAX,
                mode: LockMode::Shared,
            }),
            Error::InvalidField,
        ),
        (
            Body::TestLock(Lock {
                mode: LockMode::Unlock,
                ..LOCK
            }),
            Error::InvalidField,
        ),
        (
            Body::LockInfo(Some(Lock {
                mode: LockMode::Unlock,
                ..LOCK
            })),
            Error::InvalidField,
        ),
        (
            Body::LockInfo(Some(Lock {
                start: u64::MAX,
                length: 1,
                mode: LockMode::Shared,
            })),
            Error::InvalidField,
        ),
        (
            Body::Open {
                flags: OPEN_READ,
                path: b"/abs",
            },
            Error::InvalidPath,
        ),
        (
            Body::Open {
                flags: 0,
                path: b"a",
            },
            Error::UnknownFlags,
        ),
        (
            Body::Read {
                offset: 0,
                length: 0,
            },
            Error::InvalidField,
        ),
        (
            Body::Read {
                offset: 0,
                length: MAX_IO_BYTES as u32 + 1,
            },
            Error::InvalidField,
        ),
        (
            Body::Write {
                offset: 0,
                data: &[],
            },
            Error::InvalidField,
        ),
        (Body::Unlink { name: b"a/b" }, Error::InvalidPath),
        (
            Body::OnOpen {
                status: Status::Ok,
                attr: None,
            },
            Error::InvalidField,
        ),
        (
            Body::OnOpen {
                status: Status::IoError,
                attr: Some(ATTR),
            },
            Error::InvalidField,
        ),
        (Body::Attr(Attr { access: 0, ..ATTR }), Error::InvalidField),
        (Body::Attr(Attr { access: 4, ..ATTR }), Error::InvalidField),
        (
            Body::Dirents {
                next_cookie: 5,
                entries: Entries::EMPTY,
            },
            Error::InvalidField,
        ),
        (
            Body::FsInfo(FsInfo {
                flags: 1 << 4,
                name_max: 255,
                block_size: 4096,
                total_bytes: 0,
                free_bytes: 0,
            }),
            Error::UnknownFlags,
        ),
    ];
    for (body, error) in cases {
        assert_eq!(encode(body), Err(error), "{body:?}");
    }
    for info in [
        FsInfo {
            flags: 0,
            name_max: 0,
            block_size: 4096,
            total_bytes: 0,
            free_bytes: 0,
        },
        FsInfo {
            flags: 0,
            name_max: 255,
            block_size: 256,
            total_bytes: 0,
            free_bytes: 0,
        },
        FsInfo {
            flags: 0,
            name_max: 255,
            block_size: 4096,
            total_bytes: 1,
            free_bytes: 2,
        },
    ] {
        assert_eq!(encode(Body::FsInfo(info)), Err(Error::InvalidField));
    }
    assert_eq!(
        encode(Body::Write {
            offset: 0,
            data: &big
        }),
        Err(Error::WrongSize)
    );

    // The same refusals on the parse side, by patching good encodings.
    let mut on_open = node_bytes(Body::OnOpen {
        status: Status::NotFound,
        attr: None,
    });
    on_open[40] = 1;
    assert_eq!(node::parse(&on_open, 0), Err(Error::NonzeroReserved));
    let mut status = node_bytes(Body::Status {
        status: Status::Ok,
        value: 0,
    });
    status[32] = 15;
    assert_eq!(node::parse(&status, 0), Err(Error::UnknownStatus));
    let mut attr = node_bytes(Body::Attr(ATTR));
    attr[32] = 3;
    assert_eq!(node::parse(&attr, 0), Err(Error::InvalidField));
    let mut open = node_bytes(Body::Open {
        flags: OPEN_READ,
        path: b"a/b",
    });
    open[42] = b'.';
    assert_eq!(node::parse(&open, 1), Err(Error::InvalidPath));
    let mut listing = node_bytes(Body::Dirents {
        next_cookie: 1,
        entries: Entries::new(&entries(&[(Kind::File, b"x")])).unwrap(),
    });
    listing[50] = b'/';
    assert_eq!(node::parse(&listing, 0), Err(Error::InvalidField));
    let mut lock = node_bytes(Body::Lock(LOCK));
    lock[32] = 3;
    assert_eq!(node::parse(&lock, 0), Err(Error::InvalidField));
    let mut lock = node_bytes(Body::Lock(LOCK));
    lock[36] = 1;
    assert_eq!(node::parse(&lock, 0), Err(Error::NonzeroReserved));
    let mut lock = node_bytes(Body::Lock(LOCK));
    lock[40..48].copy_from_slice(&u64::MAX.to_le_bytes());
    lock[48] = 2;
    assert_eq!(node::parse(&lock, 0), Err(Error::InvalidField));
    let mut none = node_bytes(Body::LockInfo(None));
    none[48] = 1;
    assert_eq!(node::parse(&none, 0), Err(Error::NonzeroReserved));
}

#[test]
fn every_namespace_message_round_trips_and_bad_ones_are_refused() {
    let bodies = [
        namespace::Body::Open {
            flags: OPEN_READ | OPEN_DIRECTORY,
            path: b"/",
        },
        namespace::Body::Open {
            flags: OPEN_WRITE | OPEN_FILE | OPEN_CREATE,
            path: b"/state/log",
        },
        namespace::Body::Mount {
            flags: MOUNT_READ_ONLY,
            path: b"/boot",
        },
        namespace::Body::Unmount { path: b"/boot" },
        namespace::Body::Status(Status::Busy),
    ];
    for body in bodies {
        let bytes = ns_bytes(body);
        let parsed = namespace::parse(&bytes, body.handle_count()).unwrap();
        assert_eq!(parsed.body, body);
        assert_eq!(parsed.transaction_id, 9);
        assert_eq!(
            namespace::parse(&bytes, 1 - body.handle_count()),
            Err(Error::WrongHandleCount)
        );
        // WRFS and WRNS never mistake each other's messages.
        assert_eq!(
            node::parse(&bytes, body.handle_count()),
            Err(Error::WrongMagic)
        );
    }
    let encode = |body: namespace::Body<'_>| {
        let mut output = [0u8; namespace::MAX_BYTES];
        namespace::encode(
            &namespace::Message {
                transaction_id: 1,
                body,
            },
            &mut output,
        )
    };
    for (body, error) in [
        (
            namespace::Body::Open {
                flags: OPEN_READ,
                path: b"relative",
            },
            Error::InvalidPath,
        ),
        (
            namespace::Body::Open {
                flags: OPEN_WRITE | OPEN_DIRECTORY | OPEN_CREATE,
                path: b"/",
            },
            Error::UnknownFlags,
        ),
        (
            namespace::Body::Mount {
                flags: 2,
                path: b"/boot",
            },
            Error::UnknownFlags,
        ),
        (
            namespace::Body::Unmount { path: b"/boot/" },
            Error::InvalidPath,
        ),
    ] {
        assert_eq!(encode(body), Err(error), "{body:?}");
    }
    let mut unmount = ns_bytes(namespace::Body::Unmount { path: b"/a" });
    unmount[36] = 1;
    assert_eq!(namespace::parse(&unmount, 0), Err(Error::NonzeroReserved));
    let mut status = ns_bytes(namespace::Body::Status(Status::Ok));
    status[12] = 48;
    status.resize(48, 0);
    assert_eq!(namespace::parse(&status, 0), Err(Error::WrongSize));
}
