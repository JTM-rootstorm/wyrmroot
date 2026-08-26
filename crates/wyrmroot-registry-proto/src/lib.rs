//! Allocation-free WRRG version 1 codec.
//!
//! Authority is carried by controller-installed Channel endpoints. Numeric
//! identities in this protocol are correlation data and cannot install an
//! endpoint or manufacture publication/client authority.

#![no_std]
#![forbid(unsafe_code)]

pub const HEADER_BYTES: usize = 64;
pub const MAX_SERVICES: usize = 32;
pub const MAX_SERVICE_NAME_BYTES: usize = 128;
pub const MAX_PROTOCOL_VERSIONS: usize = 4;
pub const MAX_OUTSTANDING_PER_CLIENT: usize = 16;
pub const MAX_CLIENT_REPLAY: usize = 32;
pub const MAX_PUBLICATION_REPLAY: usize = 8;

const MAGIC: [u8; 4] = *b"WRRG";
const MAJOR: u16 = 1;
const MINOR: u16 = 0;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum MessageType {
    InstallPublication = 1,
    InstallClient = 2,
    Publish = 3,
    Published = 4,
    Retire = 5,
    Retired = 6,
    LookupConnect = 7,
    ConnectOffer = 8,
    Connected = 9,
    Enumerate = 10,
    ServiceList = 11,
    Watch = 12,
    GenerationChanged = 13,
    Cancel = 14,
    Cancelled = 15,
    Error = 16,
}

impl MessageType {
    fn parse(value: u32) -> Result<Self, Error> {
        Ok(match value {
            1 => Self::InstallPublication,
            2 => Self::InstallClient,
            3 => Self::Publish,
            4 => Self::Published,
            5 => Self::Retire,
            6 => Self::Retired,
            7 => Self::LookupConnect,
            8 => Self::ConnectOffer,
            9 => Self::Connected,
            10 => Self::Enumerate,
            11 => Self::ServiceList,
            12 => Self::Watch,
            13 => Self::GenerationChanged,
            14 => Self::Cancel,
            15 => Self::Cancelled,
            16 => Self::Error,
            _ => return Err(Error::UnknownMessageType),
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Header {
    pub message_type: MessageType,
    pub registry_generation: u64,
    pub endpoint_id: u64,
    pub endpoint_generation: u64,
    pub transaction_id: u64,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Ord, PartialOrd)]
pub struct ProtocolVersion {
    pub major: u16,
    pub minor: u16,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EnumerationScope {
    None,
    BootstrapMetadata,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InstallPublication<'a> {
    pub supervisor_role_id: u32,
    pub publication_id: u64,
    pub service_generation: u64,
    pub protocol_id: u64,
    pub versions: VersionList<'a>,
    pub service_name: &'a [u8],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InstallClient {
    pub client_id: u64,
    pub client_generation: u64,
    pub scope: EnumerationScope,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Lookup<'a> {
    pub protocol_id: u64,
    pub version: ProtocolVersion,
    pub service_name: &'a [u8],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Watch<'a> {
    pub protocol_id: u64,
    pub last_observed_generation: u64,
    pub service_name: &'a [u8],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Message<'a> {
    InstallPublication(InstallPublication<'a>),
    InstallClient(InstallClient),
    Publish,
    Published,
    Retire,
    Retired,
    LookupConnect(Lookup<'a>),
    ConnectOffer(Lookup<'a>),
    Connected,
    Enumerate,
    ServiceList(&'a [u8]),
    Watch(Watch<'a>),
    GenerationChanged { service_generation: u64 },
    Cancel { target_transaction_id: u64 },
    Cancelled { target_transaction_id: u64 },
    Error { code: u32 },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ParsedMessage<'a> {
    pub header: Header,
    pub message: Message<'a>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VersionList<'a> {
    bytes: &'a [u8],
}

impl<'a> VersionList<'a> {
    pub const fn len(self) -> usize {
        self.bytes.len() / 4
    }

    pub const fn is_empty(self) -> bool {
        self.bytes.is_empty()
    }

    pub fn get(self, index: usize) -> Option<ProtocolVersion> {
        let offset = index.checked_mul(4)?;
        Some(ProtocolVersion {
            major: get_u16(self.bytes, offset)?,
            minor: get_u16(self.bytes, offset + 2)?,
        })
    }

    pub fn contains(self, version: ProtocolVersion) -> bool {
        (0..self.len()).any(|index| self.get(index) == Some(version))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    WrongSize,
    WrongMagic,
    UnsupportedVersion,
    UnknownMessageType,
    NonzeroFlags,
    NonzeroReserved,
    WrongHandleCount,
    ZeroIdentity,
    WrongEndpointScope,
    InvalidScope,
    InvalidServiceName,
    InvalidProtocolId,
    InvalidVersionList,
    NoncanonicalVersions,
    ArithmeticOverflow,
}

/// Parses one complete Channel datagram and validates its exact moved-handle
/// count. Object metadata and rights remain transport-owned validation.
pub fn parse(bytes: &[u8], received_handle_count: usize) -> Result<ParsedMessage<'_>, Error> {
    if bytes.len() < HEADER_BYTES {
        return Err(Error::WrongSize);
    }
    if bytes[..4] != MAGIC {
        return Err(Error::WrongMagic);
    }
    if read_u16(bytes, 4)? != MAJOR || read_u16(bytes, 6)? != MINOR {
        return Err(Error::UnsupportedVersion);
    }
    let message_type = MessageType::parse(read_u32(bytes, 8)?)?;
    if read_u32(bytes, 12)? != 0 {
        return Err(Error::NonzeroFlags);
    }
    let declared_size = usize::try_from(read_u32(bytes, 16)?).map_err(|_| Error::WrongSize)?;
    if declared_size != bytes.len() {
        return Err(Error::WrongSize);
    }
    let declared_handles =
        usize::try_from(read_u32(bytes, 20)?).map_err(|_| Error::WrongHandleCount)?;
    if declared_handles != received_handle_count {
        return Err(Error::WrongHandleCount);
    }
    let header = Header {
        message_type,
        registry_generation: read_u64(bytes, 24)?,
        endpoint_id: read_u64(bytes, 32)?,
        endpoint_generation: read_u64(bytes, 40)?,
        transaction_id: read_u64(bytes, 48)?,
    };
    if read_u64(bytes, 56)? != 0 {
        return Err(Error::NonzeroReserved);
    }
    if header.registry_generation == 0 || header.transaction_id == 0 {
        return Err(Error::ZeroIdentity);
    }

    let on_supervisor = matches!(
        message_type,
        MessageType::InstallPublication | MessageType::InstallClient
    );
    if on_supervisor {
        if header.endpoint_id != 0 || header.endpoint_generation != 0 {
            return Err(Error::WrongEndpointScope);
        }
    } else if header.endpoint_id == 0 || header.endpoint_generation == 0 {
        return Err(Error::WrongEndpointScope);
    }

    let message = match message_type {
        MessageType::InstallPublication => {
            require_handles(received_handle_count, 1)?;
            Message::InstallPublication(parse_install_publication(bytes)?)
        }
        MessageType::InstallClient => {
            require_handles(received_handle_count, 1)?;
            require_size(bytes, 88)?;
            let scope = match read_u32(bytes, 80)? {
                0 => EnumerationScope::None,
                1 => EnumerationScope::BootstrapMetadata,
                _ => return Err(Error::InvalidScope),
            };
            if read_u32(bytes, 84)? != 0 {
                return Err(Error::NonzeroReserved);
            }
            let value = InstallClient {
                client_id: read_u64(bytes, 64)?,
                client_generation: read_u64(bytes, 72)?,
                scope,
            };
            if value.client_id == 0 || value.client_generation == 0 {
                return Err(Error::ZeroIdentity);
            }
            Message::InstallClient(value)
        }
        MessageType::Publish => exact_header(bytes, received_handle_count, Message::Publish)?,
        MessageType::Published => exact_header(bytes, received_handle_count, Message::Published)?,
        MessageType::Retire => exact_header(bytes, received_handle_count, Message::Retire)?,
        MessageType::Retired => exact_header(bytes, received_handle_count, Message::Retired)?,
        MessageType::LookupConnect => {
            require_handles(received_handle_count, 1)?;
            Message::LookupConnect(parse_lookup(bytes)?)
        }
        MessageType::ConnectOffer => {
            require_handles(received_handle_count, 1)?;
            Message::ConnectOffer(parse_lookup(bytes)?)
        }
        MessageType::Connected => exact_header(bytes, received_handle_count, Message::Connected)?,
        MessageType::Enumerate => exact_header(bytes, received_handle_count, Message::Enumerate)?,
        MessageType::ServiceList => {
            require_handles(received_handle_count, 0)?;
            Message::ServiceList(&bytes[HEADER_BYTES..])
        }
        MessageType::Watch => {
            require_handles(received_handle_count, 0)?;
            Message::Watch(parse_watch(bytes)?)
        }
        MessageType::GenerationChanged => {
            require_handles(received_handle_count, 0)?;
            require_size(bytes, 72)?;
            Message::GenerationChanged {
                service_generation: read_u64(bytes, 64)?,
            }
        }
        MessageType::Cancel | MessageType::Cancelled => {
            require_handles(received_handle_count, 0)?;
            require_size(bytes, 72)?;
            let target_transaction_id = read_u64(bytes, 64)?;
            if target_transaction_id == 0 {
                return Err(Error::ZeroIdentity);
            }
            if message_type == MessageType::Cancel {
                Message::Cancel {
                    target_transaction_id,
                }
            } else {
                Message::Cancelled {
                    target_transaction_id,
                }
            }
        }
        MessageType::Error => {
            require_handles(received_handle_count, 0)?;
            require_size(bytes, 72)?;
            if read_u32(bytes, 68)? != 0 {
                return Err(Error::NonzeroReserved);
            }
            Message::Error {
                code: read_u32(bytes, 64)?,
            }
        }
    };
    Ok(ParsedMessage { header, message })
}

pub fn encode_header(
    header: Header,
    handles: usize,
    total_size: usize,
    out: &mut [u8],
) -> Result<(), Error> {
    if out.len() < total_size || total_size < HEADER_BYTES {
        return Err(Error::WrongSize);
    }
    if header.registry_generation == 0 || header.transaction_id == 0 {
        return Err(Error::ZeroIdentity);
    }
    let supervisor = matches!(
        header.message_type,
        MessageType::InstallPublication | MessageType::InstallClient
    );
    if supervisor != (header.endpoint_id == 0 && header.endpoint_generation == 0) {
        return Err(Error::WrongEndpointScope);
    }
    out[..total_size].fill(0);
    out[..4].copy_from_slice(&MAGIC);
    put_u16(out, 4, MAJOR)?;
    put_u16(out, 6, MINOR)?;
    put_u32(out, 8, header.message_type as u32)?;
    put_u32(
        out,
        16,
        u32::try_from(total_size).map_err(|_| Error::WrongSize)?,
    )?;
    put_u32(
        out,
        20,
        u32::try_from(handles).map_err(|_| Error::WrongHandleCount)?,
    )?;
    put_u64(out, 24, header.registry_generation)?;
    put_u64(out, 32, header.endpoint_id)?;
    put_u64(out, 40, header.endpoint_generation)?;
    put_u64(out, 48, header.transaction_id)?;
    Ok(())
}

/// Encodes one exact header-only WRRG message.
pub fn encode_empty(header: Header, out: &mut [u8]) -> Result<usize, Error> {
    if !matches!(
        header.message_type,
        MessageType::Publish
            | MessageType::Published
            | MessageType::Retire
            | MessageType::Retired
            | MessageType::Connected
            | MessageType::Enumerate
    ) {
        return Err(Error::UnknownMessageType);
    }
    encode_header(header, 0, HEADER_BYTES, out)?;
    Ok(HEADER_BYTES)
}

/// Encodes a generation-change reply.
pub fn encode_generation_changed(
    header: Header,
    generation: u64,
    out: &mut [u8],
) -> Result<usize, Error> {
    if header.message_type != MessageType::GenerationChanged {
        return Err(Error::UnknownMessageType);
    }
    encode_header(header, 0, 72, out)?;
    put_u64(out, 64, generation)?;
    Ok(72)
}

/// Encodes a cancellation request or acknowledgement.
pub fn encode_cancel(header: Header, target: u64, out: &mut [u8]) -> Result<usize, Error> {
    if !matches!(
        header.message_type,
        MessageType::Cancel | MessageType::Cancelled
    ) || target == 0
    {
        return Err(Error::ZeroIdentity);
    }
    encode_header(header, 0, 72, out)?;
    put_u64(out, 64, target)?;
    Ok(72)
}

/// Encodes a bounded registry error response.
pub fn encode_error(header: Header, code: u32, out: &mut [u8]) -> Result<usize, Error> {
    if header.message_type != MessageType::Error || code == 0 {
        return Err(Error::ZeroIdentity);
    }
    encode_header(header, 0, 72, out)?;
    put_u32(out, 64, code)?;
    Ok(72)
}

/// Encodes `LOOKUP_CONNECT` or `CONNECT_OFFER`; both share one canonical body.
pub fn encode_lookup(header: Header, lookup: Lookup<'_>, out: &mut [u8]) -> Result<usize, Error> {
    if !matches!(
        header.message_type,
        MessageType::LookupConnect | MessageType::ConnectOffer
    ) || lookup.protocol_id == 0
    {
        return Err(Error::InvalidProtocolId);
    }
    validate_name(lookup.service_name)?;
    let size = 80usize
        .checked_add(lookup.service_name.len())
        .ok_or(Error::ArithmeticOverflow)?;
    encode_header(header, 1, size, out)?;
    put_u64(out, 64, lookup.protocol_id)?;
    put_u16(out, 72, lookup.version.major)?;
    put_u16(out, 74, lookup.version.minor)?;
    put_u16(out, 76, lookup.service_name.len() as u16)?;
    out[80..size].copy_from_slice(lookup.service_name);
    Ok(size)
}

pub fn encode_install_publication(
    header: Header,
    supervisor_role_id: u32,
    publication_id: u64,
    service_generation: u64,
    protocol_id: u64,
    versions: &[ProtocolVersion],
    name: &[u8],
    out: &mut [u8],
) -> Result<usize, Error> {
    if header.message_type != MessageType::InstallPublication
        || supervisor_role_id == 0
        || publication_id == 0
        || service_generation == 0
        || protocol_id == 0
    {
        return Err(Error::ZeroIdentity);
    }
    validate_name(name)?;
    validate_versions(versions)?;
    let size = 104usize
        .checked_add(
            versions
                .len()
                .checked_mul(4)
                .ok_or(Error::ArithmeticOverflow)?,
        )
        .and_then(|value| value.checked_add(name.len()))
        .ok_or(Error::ArithmeticOverflow)?;
    encode_header(header, 1, size, out)?;
    put_u32(out, 64, supervisor_role_id)?;
    put_u64(out, 72, publication_id)?;
    put_u64(out, 80, service_generation)?;
    put_u64(out, 88, protocol_id)?;
    put_u16(out, 96, versions.len() as u16)?;
    put_u16(out, 98, name.len() as u16)?;
    for (index, version) in versions.iter().enumerate() {
        put_u16(out, 104 + index * 4, version.major)?;
        put_u16(out, 106 + index * 4, version.minor)?;
    }
    let name_offset = 104 + versions.len() * 4;
    out[name_offset..size].copy_from_slice(name);
    Ok(size)
}

pub fn validate_name(name: &[u8]) -> Result<(), Error> {
    if name.is_empty() || name.len() > MAX_SERVICE_NAME_BYTES || !name[0].is_ascii_lowercase() {
        return Err(Error::InvalidServiceName);
    }
    if !name[1..].iter().all(|byte| {
        byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'-')
    }) {
        return Err(Error::InvalidServiceName);
    }
    Ok(())
}

fn parse_install_publication(bytes: &[u8]) -> Result<InstallPublication<'_>, Error> {
    if bytes.len() < 108 {
        return Err(Error::WrongSize);
    }
    if read_u32(bytes, 68)? != 0 || read_u32(bytes, 100)? != 0 {
        return Err(Error::NonzeroReserved);
    }
    let count = usize::from(read_u16(bytes, 96)?);
    let name_len = usize::from(read_u16(bytes, 98)?);
    if !(1..=MAX_PROTOCOL_VERSIONS).contains(&count) {
        return Err(Error::InvalidVersionList);
    }
    let versions_end = 104usize
        .checked_add(count.checked_mul(4).ok_or(Error::ArithmeticOverflow)?)
        .ok_or(Error::ArithmeticOverflow)?;
    let total = versions_end
        .checked_add(name_len)
        .ok_or(Error::ArithmeticOverflow)?;
    if total != bytes.len() {
        return Err(Error::WrongSize);
    }
    let versions = VersionList {
        bytes: &bytes[104..versions_end],
    };
    validate_version_list(versions)?;
    let service_name = &bytes[versions_end..];
    validate_name(service_name)?;
    let value = InstallPublication {
        supervisor_role_id: read_u32(bytes, 64)?,
        publication_id: read_u64(bytes, 72)?,
        service_generation: read_u64(bytes, 80)?,
        protocol_id: read_u64(bytes, 88)?,
        versions,
        service_name,
    };
    if value.supervisor_role_id == 0 || value.publication_id == 0 || value.service_generation == 0 {
        return Err(Error::ZeroIdentity);
    }
    if value.protocol_id == 0 {
        return Err(Error::InvalidProtocolId);
    }
    Ok(value)
}

fn parse_lookup(bytes: &[u8]) -> Result<Lookup<'_>, Error> {
    if bytes.len() < 81 {
        return Err(Error::WrongSize);
    }
    let name_len = usize::from(read_u16(bytes, 76)?);
    if read_u16(bytes, 78)? != 0 || bytes.len() != 80 + name_len {
        return Err(if read_u16(bytes, 78)? != 0 {
            Error::NonzeroReserved
        } else {
            Error::WrongSize
        });
    }
    let protocol_id = read_u64(bytes, 64)?;
    if protocol_id == 0 {
        return Err(Error::InvalidProtocolId);
    }
    let service_name = &bytes[80..];
    validate_name(service_name)?;
    Ok(Lookup {
        protocol_id,
        version: ProtocolVersion {
            major: read_u16(bytes, 72)?,
            minor: read_u16(bytes, 74)?,
        },
        service_name,
    })
}

fn parse_watch(bytes: &[u8]) -> Result<Watch<'_>, Error> {
    if bytes.len() < 89 {
        return Err(Error::WrongSize);
    }
    let name_len = usize::from(read_u16(bytes, 80)?);
    if read_u16(bytes, 82)? != 0 || read_u32(bytes, 84)? != 0 {
        return Err(Error::NonzeroReserved);
    }
    if bytes.len() != 88 + name_len {
        return Err(Error::WrongSize);
    }
    let protocol_id = read_u64(bytes, 64)?;
    if protocol_id == 0 {
        return Err(Error::InvalidProtocolId);
    }
    validate_name(&bytes[88..])?;
    Ok(Watch {
        protocol_id,
        last_observed_generation: read_u64(bytes, 72)?,
        service_name: &bytes[88..],
    })
}

fn validate_versions(versions: &[ProtocolVersion]) -> Result<(), Error> {
    if versions.is_empty() || versions.len() > MAX_PROTOCOL_VERSIONS {
        return Err(Error::InvalidVersionList);
    }
    for window in versions.windows(2) {
        if window[0] >= window[1] {
            return Err(Error::NoncanonicalVersions);
        }
    }
    Ok(())
}

fn validate_version_list(versions: VersionList<'_>) -> Result<(), Error> {
    let mut previous = None;
    for index in 0..versions.len() {
        let current = versions.get(index).ok_or(Error::InvalidVersionList)?;
        if previous.is_some_and(|value| value >= current) {
            return Err(Error::NoncanonicalVersions);
        }
        previous = Some(current);
    }
    Ok(())
}

fn exact_header<'a>(
    bytes: &[u8],
    handles: usize,
    value: Message<'a>,
) -> Result<Message<'a>, Error> {
    require_handles(handles, 0)?;
    require_size(bytes, HEADER_BYTES)?;
    Ok(value)
}

fn require_size(bytes: &[u8], expected: usize) -> Result<(), Error> {
    if bytes.len() == expected {
        Ok(())
    } else {
        Err(Error::WrongSize)
    }
}

fn require_handles(actual: usize, expected: usize) -> Result<(), Error> {
    if actual == expected {
        Ok(())
    } else {
        Err(Error::WrongHandleCount)
    }
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, Error> {
    get_u16(bytes, offset).ok_or(Error::WrongSize)
}
fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, Error> {
    let value = bytes
        .get(offset..offset.checked_add(4).ok_or(Error::ArithmeticOverflow)?)
        .ok_or(Error::WrongSize)?;
    Ok(u32::from_le_bytes(
        value.try_into().map_err(|_| Error::WrongSize)?,
    ))
}
fn read_u64(bytes: &[u8], offset: usize) -> Result<u64, Error> {
    let value = bytes
        .get(offset..offset.checked_add(8).ok_or(Error::ArithmeticOverflow)?)
        .ok_or(Error::WrongSize)?;
    Ok(u64::from_le_bytes(
        value.try_into().map_err(|_| Error::WrongSize)?,
    ))
}
fn get_u16(bytes: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_le_bytes(
        bytes.get(offset..offset.checked_add(2)?)?.try_into().ok()?,
    ))
}
fn put_u16(bytes: &mut [u8], offset: usize, value: u16) -> Result<(), Error> {
    bytes
        .get_mut(offset..offset.checked_add(2).ok_or(Error::ArithmeticOverflow)?)
        .ok_or(Error::WrongSize)?
        .copy_from_slice(&value.to_le_bytes());
    Ok(())
}
fn put_u32(bytes: &mut [u8], offset: usize, value: u32) -> Result<(), Error> {
    bytes
        .get_mut(offset..offset.checked_add(4).ok_or(Error::ArithmeticOverflow)?)
        .ok_or(Error::WrongSize)?
        .copy_from_slice(&value.to_le_bytes());
    Ok(())
}
fn put_u64(bytes: &mut [u8], offset: usize, value: u64) -> Result<(), Error> {
    bytes
        .get_mut(offset..offset.checked_add(8).ok_or(Error::ArithmeticOverflow)?)
        .ok_or(Error::WrongSize)?
        .copy_from_slice(&value.to_le_bytes());
    Ok(())
}

#[cfg(test)]
mod tests {
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
        let mut bytes = [0u8; 140];
        let size = encode_install_publication(
            header(MessageType::InstallPublication),
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

        endpoint.message_type = MessageType::Cancelled;
        let size = encode_cancel(endpoint, 17, &mut bytes).unwrap();
        assert_eq!(
            parse(&bytes[..size], 0).unwrap().message,
            Message::Cancelled {
                target_transaction_id: 17
            }
        );
    }
}
