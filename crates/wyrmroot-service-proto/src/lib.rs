//! WRSV 1.0: init's one-message stage of a service role (root
//! `STORAGE_PLAN.md` W6).
//!
//! Init launches a bootfs service with the loader's self-root-plus-control
//! startup profile, then sends one STAGE on the control Channel. STAGE
//! carries everything the service may use, and nothing else:
//!
//! - a registry publication endpoint and its grant, if the role publishes;
//! - a registry client endpoint, if the role looks services up;
//! - up to [`MAX_CHANNELS`] role Channels, each with a slot number, flags
//!   and a short label the role interprets (vfsd reads a mount path and
//!   [`CHANNEL_READ_ONLY`]).
//!
//! Handles travel in that order. The control Channel then stays open for
//! the service's life; its closure asks the service to retire.

#![no_std]
#![forbid(unsafe_code)]

pub const MAGIC: [u8; 4] = *b"WRSV";
pub const MAJOR: u16 = 1;
pub const MINOR: u16 = 0;
pub const HEADER_BYTES: usize = 32;
pub const MAX_CHANNELS: usize = 4;
pub const MAX_LABEL_BYTES: usize = 64;
const FIXED_BYTES: usize = HEADER_BYTES + 88;
const CHANNEL_BYTES: usize = 16 + MAX_LABEL_BYTES;
/// The largest STAGE, for receive buffers.
pub const MAX_BYTES: usize = FIXED_BYTES + MAX_CHANNELS * CHANNEL_BYTES;
/// The most handles a STAGE carries.
pub const MAX_HANDLES: usize = 2 + MAX_CHANNELS;

const TYPE_STAGE: u32 = 1;
const HAS_PUBLICATION: u32 = 1 << 0;
const HAS_CLIENT: u32 = 1 << 1;

/// Channel flag: the role must not write through this Channel's peer.
pub const CHANNEL_READ_ONLY: u32 = 1 << 0;
const CHANNEL_FLAGS: u32 = CHANNEL_READ_ONLY;

/// Init's grant of one installed registry publication.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Publication {
    pub registry_generation: u64,
    pub endpoint_id: u64,
    pub endpoint_generation: u64,
    /// The transaction the service's PUBLISH uses.
    pub transaction_id: u64,
    pub service_generation: u64,
}

/// The identity of an installed registry client endpoint.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Client {
    pub registry_generation: u64,
    pub endpoint_id: u64,
    pub endpoint_generation: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Channel<'a> {
    pub slot: u32,
    pub flags: u32,
    pub label: &'a [u8],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Stage<'a> {
    pub transaction_id: u64,
    /// The role and attempt the loader's INIT named.
    pub role_id: u64,
    pub attempt_generation: u64,
    pub publication: Option<Publication>,
    pub client: Option<Client>,
    pub channels: &'a [Channel<'a>],
}

impl Stage<'_> {
    pub fn handle_count(&self) -> usize {
        usize::from(self.publication.is_some())
            + usize::from(self.client.is_some())
            + self.channels.len()
    }

    pub fn wire_size(&self) -> usize {
        FIXED_BYTES + self.channels.len() * CHANNEL_BYTES
    }
}

/// A parsed STAGE: its channels live in a fixed array.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ParsedStage<'a> {
    pub transaction_id: u64,
    pub role_id: u64,
    pub attempt_generation: u64,
    pub publication: Option<Publication>,
    pub client: Option<Client>,
    channels: [Channel<'a>; MAX_CHANNELS],
    channel_count: usize,
}

impl<'a> ParsedStage<'a> {
    pub fn channels(&self) -> &[Channel<'a>] {
        &self.channels[..self.channel_count]
    }

    /// Where channel `index`'s handle sits among the received handles.
    pub fn channel_handle_index(&self, index: usize) -> usize {
        usize::from(self.publication.is_some()) + usize::from(self.client.is_some()) + index
    }

    pub fn handle_count(&self) -> usize {
        self.channel_handle_index(self.channel_count)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    WrongSize,
    WrongMagic,
    WrongVersion,
    UnknownMessage,
    WrongHandleCount,
    ZeroTransaction,
    NonzeroReserved,
    UnknownFlags,
    InvalidField,
}

pub fn encode(stage: &Stage<'_>, output: &mut [u8]) -> Result<usize, Error> {
    let size = stage.wire_size();
    if stage.channels.len() > MAX_CHANNELS {
        return Err(Error::InvalidField);
    }
    let output = output.get_mut(..size).ok_or(Error::WrongSize)?;
    if stage.transaction_id == 0 {
        return Err(Error::ZeroTransaction);
    }
    check_identity(stage.role_id, stage.attempt_generation)?;
    if stage.publication.is_some_and(|p| !publication_valid(p))
        || stage.client.is_some_and(|c| !client_valid(c))
    {
        return Err(Error::InvalidField);
    }
    for channel in stage.channels {
        check_channel(channel)?;
    }
    output.fill(0);
    output[..4].copy_from_slice(&MAGIC);
    output[4..6].copy_from_slice(&MAJOR.to_le_bytes());
    output[6..8].copy_from_slice(&MINOR.to_le_bytes());
    put32(output, 8, TYPE_STAGE);
    put32(output, 12, size as u32);
    put32(output, 16, stage.handle_count() as u32);
    put64(output, 24, stage.transaction_id);
    put64(output, 32, stage.role_id);
    put64(output, 40, stage.attempt_generation);
    let flags = if stage.publication.is_some() {
        HAS_PUBLICATION
    } else {
        0
    } | if stage.client.is_some() {
        HAS_CLIENT
    } else {
        0
    };
    put32(output, 48, flags);
    put32(output, 52, stage.channels.len() as u32);
    let p = stage.publication.unwrap_or_default();
    for (i, value) in [
        p.registry_generation,
        p.endpoint_id,
        p.endpoint_generation,
        p.transaction_id,
        p.service_generation,
    ]
    .into_iter()
    .enumerate()
    {
        put64(output, 56 + i * 8, value);
    }
    let c = stage.client.unwrap_or_default();
    for (i, value) in [c.registry_generation, c.endpoint_id, c.endpoint_generation]
        .into_iter()
        .enumerate()
    {
        put64(output, 96 + i * 8, value);
    }
    for (i, channel) in stage.channels.iter().enumerate() {
        let at = FIXED_BYTES + i * CHANNEL_BYTES;
        put32(output, at, channel.slot);
        put32(output, at + 4, channel.flags);
        put32(output, at + 8, channel.label.len() as u32);
        output[at + 16..at + 16 + channel.label.len()].copy_from_slice(channel.label);
    }
    Ok(size)
}

/// Parses one STAGE of `bytes` that arrived with `handle_count` handles.
pub fn parse(bytes: &[u8], handle_count: usize) -> Result<ParsedStage<'_>, Error> {
    if bytes.len() < FIXED_BYTES || get32(bytes, 12) as usize != bytes.len() {
        return Err(Error::WrongSize);
    }
    if bytes[..4] != MAGIC {
        return Err(Error::WrongMagic);
    }
    if get16(bytes, 4) != MAJOR || get16(bytes, 6) != MINOR {
        return Err(Error::WrongVersion);
    }
    if get32(bytes, 8) != TYPE_STAGE {
        return Err(Error::UnknownMessage);
    }
    if get32(bytes, 20) != 0 {
        return Err(Error::NonzeroReserved);
    }
    let transaction_id = get64(bytes, 24);
    if transaction_id == 0 {
        return Err(Error::ZeroTransaction);
    }
    let flags = get32(bytes, 48);
    if flags & !(HAS_PUBLICATION | HAS_CLIENT) != 0 {
        return Err(Error::UnknownFlags);
    }
    let channel_count = get32(bytes, 52) as usize;
    if channel_count > MAX_CHANNELS || bytes.len() != FIXED_BYTES + channel_count * CHANNEL_BYTES {
        return Err(Error::WrongSize);
    }
    let role_id = get64(bytes, 32);
    let attempt_generation = get64(bytes, 40);
    check_identity(role_id, attempt_generation)?;
    let publication = Publication {
        registry_generation: get64(bytes, 56),
        endpoint_id: get64(bytes, 64),
        endpoint_generation: get64(bytes, 72),
        transaction_id: get64(bytes, 80),
        service_generation: get64(bytes, 88),
    };
    let publication = if flags & HAS_PUBLICATION != 0 {
        if !publication_valid(publication) {
            return Err(Error::InvalidField);
        }
        Some(publication)
    } else if publication != Publication::default() {
        return Err(Error::NonzeroReserved);
    } else {
        None
    };
    let client = Client {
        registry_generation: get64(bytes, 96),
        endpoint_id: get64(bytes, 104),
        endpoint_generation: get64(bytes, 112),
    };
    let client = if flags & HAS_CLIENT != 0 {
        if !client_valid(client) {
            return Err(Error::InvalidField);
        }
        Some(client)
    } else if client != Client::default() {
        return Err(Error::NonzeroReserved);
    } else {
        None
    };
    let mut channels = [Channel {
        slot: 0,
        flags: 0,
        label: &[],
    }; MAX_CHANNELS];
    for (i, channel) in channels.iter_mut().take(channel_count).enumerate() {
        let at = FIXED_BYTES + i * CHANNEL_BYTES;
        let label_len = get32(bytes, at + 8) as usize;
        if get32(bytes, at + 12) != 0 {
            return Err(Error::NonzeroReserved);
        }
        if label_len > MAX_LABEL_BYTES {
            return Err(Error::InvalidField);
        }
        let label_area = &bytes[at + 16..at + CHANNEL_BYTES];
        if label_area[label_len..].iter().any(|&byte| byte != 0) {
            return Err(Error::NonzeroReserved);
        }
        *channel = Channel {
            slot: get32(bytes, at),
            flags: get32(bytes, at + 4),
            label: &label_area[..label_len],
        };
        check_channel(channel)?;
    }
    let parsed = ParsedStage {
        transaction_id,
        role_id,
        attempt_generation,
        publication,
        client,
        channels,
        channel_count,
    };
    let declared = get32(bytes, 16) as usize;
    if declared != parsed.handle_count() || handle_count != declared {
        return Err(Error::WrongHandleCount);
    }
    Ok(parsed)
}

fn check_identity(role_id: u64, attempt_generation: u64) -> Result<(), Error> {
    if role_id == 0 || attempt_generation == 0 {
        Err(Error::InvalidField)
    } else {
        Ok(())
    }
}

fn publication_valid(p: Publication) -> bool {
    p.registry_generation != 0
        && p.endpoint_id != 0
        && p.endpoint_generation != 0
        && p.transaction_id != 0
        && p.service_generation != 0
}

fn client_valid(c: Client) -> bool {
    c.registry_generation != 0 && c.endpoint_id != 0 && c.endpoint_generation != 0
}

fn check_channel(channel: &Channel<'_>) -> Result<(), Error> {
    if channel.flags & !CHANNEL_FLAGS != 0 {
        return Err(Error::UnknownFlags);
    }
    if channel.label.len() > MAX_LABEL_BYTES || channel.label.contains(&0) {
        return Err(Error::InvalidField);
    }
    Ok(())
}

fn get16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([bytes[offset], bytes[offset + 1]])
}

fn get32(bytes: &[u8], offset: usize) -> u32 {
    let mut value = [0; 4];
    value.copy_from_slice(&bytes[offset..offset + 4]);
    u32::from_le_bytes(value)
}

fn get64(bytes: &[u8], offset: usize) -> u64 {
    let mut value = [0; 8];
    value.copy_from_slice(&bytes[offset..offset + 8]);
    u64::from_le_bytes(value)
}

fn put32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn put64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::vec::Vec;

    const PUBLICATION: Publication = Publication {
        registry_generation: 1,
        endpoint_id: 2,
        endpoint_generation: 3,
        transaction_id: 4,
        service_generation: 5,
    };
    const CLIENT: Client = Client {
        registry_generation: 1,
        endpoint_id: 7,
        endpoint_generation: 8,
    };

    fn encoded(stage: &Stage<'_>) -> Vec<u8> {
        let mut out = [0u8; MAX_BYTES];
        let size = encode(stage, &mut out).unwrap();
        out[..size].to_vec()
    }

    fn full<'a>(channels: &'a [Channel<'a>]) -> Stage<'a> {
        Stage {
            transaction_id: 9,
            role_id: 0x51,
            attempt_generation: 1,
            publication: Some(PUBLICATION),
            client: Some(CLIENT),
            channels,
        }
    }

    #[test]
    fn stages_round_trip_with_their_handle_order() {
        let long_label = [b'x'; MAX_LABEL_BYTES];
        let channels = [
            Channel {
                slot: 1,
                flags: CHANNEL_READ_ONLY,
                label: b"/boot",
            },
            Channel {
                slot: 2,
                flags: 0,
                label: &long_label,
            },
        ];
        for stage in [
            full(&channels),
            Stage {
                publication: None,
                ..full(&channels)
            },
            Stage {
                client: None,
                channels: &[],
                ..full(&channels)
            },
        ] {
            let bytes = encoded(&stage);
            let parsed = parse(&bytes, stage.handle_count()).unwrap();
            assert_eq!(parsed.publication, stage.publication);
            assert_eq!(parsed.client, stage.client);
            assert_eq!(parsed.channels(), stage.channels);
            assert_eq!(parsed.role_id, 0x51);
            assert_eq!(parsed.handle_count(), stage.handle_count());
            assert_eq!(
                parse(&bytes, stage.handle_count() + 1),
                Err(Error::WrongHandleCount)
            );
        }
        let stage = Stage {
            publication: None,
            ..full(&channels)
        };
        let bytes = encoded(&stage);
        let parsed = parse(&bytes, 3).unwrap();
        assert_eq!(parsed.channel_handle_index(0), 1);
        assert_eq!(parsed.channel_handle_index(1), 2);
    }

    #[test]
    fn malformed_stages_are_refused() {
        let channels = [Channel {
            slot: 1,
            flags: 0,
            label: b"/boot",
        }];
        let good = encoded(&full(&channels));
        let patched = |offset: usize, value: u8| {
            let mut bytes = good.clone();
            bytes[offset] = value;
            parse(&bytes, 3).map(|_| ())
        };
        assert_eq!(patched(0, 0), Err(Error::WrongMagic));
        assert_eq!(patched(4, 2), Err(Error::WrongVersion));
        assert_eq!(patched(8, 2), Err(Error::UnknownMessage));
        assert_eq!(patched(12, 1), Err(Error::WrongSize));
        assert_eq!(patched(20, 1), Err(Error::NonzeroReserved));
        assert_eq!(patched(48, 4), Err(Error::UnknownFlags));
        assert_eq!(patched(52, 2), Err(Error::WrongSize));
        assert_eq!(patched(32, 0), Err(Error::InvalidField));
        assert_eq!(patched(56, 0), Err(Error::InvalidField));
        assert_eq!(patched(FIXED_BYTES + 4, 2), Err(Error::UnknownFlags));
        assert_eq!(patched(FIXED_BYTES + 8, 65), Err(Error::InvalidField));
        assert_eq!(patched(FIXED_BYTES + 12, 1), Err(Error::NonzeroReserved));
        assert_eq!(
            patched(FIXED_BYTES + 16 + 10, 1),
            Err(Error::NonzeroReserved)
        );
        let mut zero = good.clone();
        zero[24] = 0;
        assert_eq!(parse(&zero, 3), Err(Error::ZeroTransaction));
        assert_eq!(parse(&good[..FIXED_BYTES - 1], 3), Err(Error::WrongSize));
        // Absent grants must be all zero.
        let mut stray = encoded(&Stage {
            publication: None,
            ..full(&channels)
        });
        stray[64] = 1;
        assert_eq!(parse(&stray, 2), Err(Error::NonzeroReserved));
        let mut out = [0u8; MAX_BYTES];
        assert_eq!(
            encode(
                &Stage {
                    channels: &[Channel {
                        slot: 1,
                        flags: 0,
                        label: b"a\0b"
                    }],
                    ..full(&channels)
                },
                &mut out
            ),
            Err(Error::InvalidField)
        );
    }
}
