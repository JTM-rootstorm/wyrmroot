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
pub const MAX_PENDING_WATCHES: usize = 32;
pub const SERVICE_LIST_PREFIX_BYTES: usize = 80;
pub const SERVICE_LIST_RECORD_BYTES: usize = 168;
pub const MAX_SERVICE_LIST_RECORDS: usize = 2;
pub const MAX_SERVICE_LIST_PAGES: usize = 16;
pub const CORRELATION_ENVIRONMENT_COUNT: usize = 3;
pub const MAX_CORRELATION_ENVIRONMENT_BYTES: usize = 64;
pub const REGISTRY_GENERATION_ENV: &str = "WYR_REGISTRY_GENERATION=";
pub const ENDPOINT_ID_ENV: &str = "WYR_REGISTRY_ENDPOINT_ID=";
pub const ENDPOINT_GENERATION_ENV: &str = "WYR_REGISTRY_ENDPOINT_GENERATION=";

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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ParsedHeader {
    pub header: Header,
    pub declared_size: usize,
    pub declared_handle_count: usize,
}

/// Minimal recoverable correlation fields. This decoder intentionally does
/// not validate framing fields so an installed endpoint can receive a typed
/// error using its controller-installed identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DecodedHeader {
    pub major: u16,
    pub minor: u16,
    pub message_type: Option<MessageType>,
    pub flags: u32,
    pub declared_size: u32,
    pub declared_handle_count: u32,
    pub registry_generation: u64,
    pub endpoint_id: u64,
    pub endpoint_generation: u64,
    pub transaction_id: u64,
    pub reserved: u64,
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
    pub endpoint_id: u64,
    pub endpoint_generation: u64,
    pub supervisor_role_id: u32,
    pub publication_id: u64,
    pub service_generation: u64,
    pub protocol_id: u64,
    pub versions: VersionList<'a>,
    pub service_name: &'a [u8],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InstallClient {
    pub endpoint_id: u64,
    pub endpoint_generation: u64,
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
pub struct ServiceListRecord<'a> {
    pub protocol_id: u64,
    pub service_generation: u64,
    pub versions: [ProtocolVersion; MAX_PROTOCOL_VERSIONS],
    pub version_count: u8,
    pub service_name: &'a [u8],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ServiceListPage<'a> {
    bytes: &'a [u8],
    pub page_index: u16,
    pub page_count: u16,
    pub record_count: u16,
    pub total_count: u16,
}

impl<'a> ServiceListPage<'a> {
    pub fn record(&self, index: usize) -> Option<ServiceListRecord<'a>> {
        if index >= usize::from(self.record_count) {
            return None;
        }
        let base = SERVICE_LIST_PREFIX_BYTES + index * SERVICE_LIST_RECORD_BYTES;
        let name_len = usize::from(get_u16(self.bytes, base + 16)?);
        let version_count = usize::from(*self.bytes.get(base + 18)?);
        let mut versions = [ProtocolVersion::default(); MAX_PROTOCOL_VERSIONS];
        for (version, target) in versions.iter_mut().enumerate().take(version_count) {
            *target = ProtocolVersion {
                major: get_u16(self.bytes, base + 24 + version * 4)?,
                minor: get_u16(self.bytes, base + 26 + version * 4)?,
            };
        }
        Some(ServiceListRecord {
            protocol_id: get_u64(self.bytes, base)?,
            service_generation: get_u64(self.bytes, base + 8)?,
            versions,
            version_count: version_count as u8,
            service_name: self.bytes.get(base + 40..base + 40 + name_len)?,
        })
    }
}

impl ServiceListPage<'_> {
    pub fn version(&self, record: usize, version: usize) -> Option<ProtocolVersion> {
        if record >= usize::from(self.record_count) {
            return None;
        }
        let base = SERVICE_LIST_PREFIX_BYTES + record * SERVICE_LIST_RECORD_BYTES;
        let count = usize::from(*self.bytes.get(base + 18)?);
        if version >= count {
            return None;
        }
        Some(ProtocolVersion {
            major: get_u16(self.bytes, base + 24 + version * 4)?,
            minor: get_u16(self.bytes, base + 26 + version * 4)?,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum ErrorCode {
    MalformedRequest = 1,
    CorrelationMismatch = 2,
    WrongEndpointKind = 3,
    TransactionLive = 4,
    TransactionReplay = 5,
    OutstandingLimit = 6,
    Capacity = 7,
    NotPublished = 8,
    UnsupportedVersion = 9,
    EnumerationDenied = 10,
    UnknownTransaction = 11,
    InvalidState = 12,
    ForwardFailed = 13,
}

impl ErrorCode {
    fn parse(value: u32) -> Result<Self, Error> {
        Ok(match value {
            1 => Self::MalformedRequest,
            2 => Self::CorrelationMismatch,
            3 => Self::WrongEndpointKind,
            4 => Self::TransactionLive,
            5 => Self::TransactionReplay,
            6 => Self::OutstandingLimit,
            7 => Self::Capacity,
            8 => Self::NotPublished,
            9 => Self::UnsupportedVersion,
            10 => Self::EnumerationDenied,
            11 => Self::UnknownTransaction,
            12 => Self::InvalidState,
            13 => Self::ForwardFailed,
            _ => return Err(Error::InvalidErrorCode),
        })
    }
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
    ServiceList(ServiceListPage<'a>),
    Watch(Watch<'a>),
    GenerationChanged { service_generation: u64 },
    Cancel { target_transaction_id: u64 },
    Cancelled { target_transaction_id: u64 },
    Error { code: ErrorCode },
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
    InvalidCorrelationEnvironment,
    InvalidServiceList,
    InvalidErrorCode,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Correlation {
    pub registry_generation: u64,
    pub endpoint_id: u64,
    pub endpoint_generation: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CorrelationEnvironment {
    bytes: [[u8; MAX_CORRELATION_ENVIRONMENT_BYTES]; CORRELATION_ENVIRONMENT_COUNT],
    lengths: [u8; CORRELATION_ENVIRONMENT_COUNT],
}

impl CorrelationEnvironment {
    pub fn new(correlation: Correlation) -> Result<Self, Error> {
        if correlation.registry_generation == 0
            || correlation.endpoint_id == 0
            || correlation.endpoint_generation == 0
        {
            return Err(Error::InvalidCorrelationEnvironment);
        }
        let mut value = Self {
            bytes: [[0; MAX_CORRELATION_ENVIRONMENT_BYTES]; CORRELATION_ENVIRONMENT_COUNT],
            lengths: [0; CORRELATION_ENVIRONMENT_COUNT],
        };
        value.write(0, REGISTRY_GENERATION_ENV, correlation.registry_generation)?;
        value.write(1, ENDPOINT_ID_ENV, correlation.endpoint_id)?;
        value.write(2, ENDPOINT_GENERATION_ENV, correlation.endpoint_generation)?;
        Ok(value)
    }

    pub fn entry(&self, index: usize) -> Option<&str> {
        let length = usize::from(*self.lengths.get(index)?);
        core::str::from_utf8(self.bytes.get(index)?.get(..length)?).ok()
    }

    fn write(&mut self, index: usize, prefix: &str, number: u64) -> Result<(), Error> {
        let output = self
            .bytes
            .get_mut(index)
            .ok_or(Error::InvalidCorrelationEnvironment)?;
        output[..prefix.len()].copy_from_slice(prefix.as_bytes());
        let digits = decimal(number, &mut output[prefix.len()..])?;
        self.lengths[index] = u8::try_from(prefix.len() + digits)
            .map_err(|_| Error::InvalidCorrelationEnvironment)?;
        Ok(())
    }
}

pub fn parse_correlation_environment(entries: &[&str]) -> Result<Correlation, Error> {
    if entries.len() != CORRELATION_ENVIRONMENT_COUNT {
        return Err(Error::InvalidCorrelationEnvironment);
    }
    Ok(Correlation {
        registry_generation: parse_decimal(
            entries[0]
                .strip_prefix(REGISTRY_GENERATION_ENV)
                .ok_or(Error::InvalidCorrelationEnvironment)?,
        )?,
        endpoint_id: parse_decimal(
            entries[1]
                .strip_prefix(ENDPOINT_ID_ENV)
                .ok_or(Error::InvalidCorrelationEnvironment)?,
        )?,
        endpoint_generation: parse_decimal(
            entries[2]
                .strip_prefix(ENDPOINT_GENERATION_ENV)
                .ok_or(Error::InvalidCorrelationEnvironment)?,
        )?,
    })
}

/// Parses one complete Channel datagram and validates its exact moved-handle
/// count. Object metadata and rights remain transport-owned validation.
pub fn parse_header(bytes: &[u8]) -> Result<ParsedHeader, Error> {
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
    if declared_size != bytes.len() || declared_size < HEADER_BYTES {
        return Err(Error::WrongSize);
    }
    let declared_handles =
        usize::try_from(read_u32(bytes, 20)?).map_err(|_| Error::WrongHandleCount)?;
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

    Ok(ParsedHeader {
        header,
        declared_size,
        declared_handle_count: declared_handles,
    })
}

pub fn decode_header(bytes: &[u8]) -> Result<DecodedHeader, Error> {
    if bytes.len() < HEADER_BYTES {
        return Err(Error::WrongSize);
    }
    if bytes[..4] != MAGIC {
        return Err(Error::WrongMagic);
    }
    let transaction_id = read_u64(bytes, 48)?;
    if transaction_id == 0 {
        return Err(Error::ZeroIdentity);
    }
    Ok(DecodedHeader {
        major: read_u16(bytes, 4)?,
        minor: read_u16(bytes, 6)?,
        message_type: MessageType::parse(read_u32(bytes, 8)?).ok(),
        flags: read_u32(bytes, 12)?,
        declared_size: read_u32(bytes, 16)?,
        declared_handle_count: read_u32(bytes, 20)?,
        registry_generation: read_u64(bytes, 24)?,
        endpoint_id: read_u64(bytes, 32)?,
        endpoint_generation: read_u64(bytes, 40)?,
        transaction_id,
        reserved: read_u64(bytes, 56)?,
    })
}

pub fn parse(bytes: &[u8], received_handle_count: usize) -> Result<ParsedMessage<'_>, Error> {
    let framing = parse_header(bytes)?;
    if framing.declared_handle_count != received_handle_count {
        return Err(Error::WrongHandleCount);
    }
    let header = framing.header;
    let message_type = header.message_type;
    let message = match message_type {
        MessageType::InstallPublication => {
            require_handles(received_handle_count, 1)?;
            Message::InstallPublication(parse_install_publication(bytes)?)
        }
        MessageType::InstallClient => {
            require_handles(received_handle_count, 1)?;
            require_size(bytes, 104)?;
            let scope = match read_u32(bytes, 96)? {
                0 => EnumerationScope::None,
                1 => EnumerationScope::BootstrapMetadata,
                _ => return Err(Error::InvalidScope),
            };
            if read_u32(bytes, 100)? != 0 {
                return Err(Error::NonzeroReserved);
            }
            let value = InstallClient {
                endpoint_id: read_u64(bytes, 64)?,
                endpoint_generation: read_u64(bytes, 72)?,
                client_id: read_u64(bytes, 80)?,
                client_generation: read_u64(bytes, 88)?,
                scope,
            };
            if value.endpoint_id == 0
                || value.endpoint_generation == 0
                || value.client_id == 0
                || value.client_generation == 0
            {
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
            Message::ServiceList(parse_service_list(bytes)?)
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
                code: ErrorCode::parse(read_u32(bytes, 64)?)?,
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
pub fn encode_error(header: Header, code: ErrorCode, out: &mut [u8]) -> Result<usize, Error> {
    if header.message_type != MessageType::Error {
        return Err(Error::UnknownMessageType);
    }
    encode_header(header, 0, 72, out)?;
    put_u32(out, 64, code as u32)?;
    Ok(72)
}

/// Encodes one canonical fixed-record service-list page.
pub fn encode_service_list(
    header: Header,
    page_index: u16,
    page_count: u16,
    total_count: u16,
    records: &[ServiceListRecord<'_>],
    out: &mut [u8],
) -> Result<usize, Error> {
    if header.message_type != MessageType::ServiceList
        || records.len() > MAX_SERVICE_LIST_RECORDS
        || page_count == 0
        || usize::from(page_count) > MAX_SERVICE_LIST_PAGES
        || page_index >= page_count
        || usize::from(total_count) > MAX_SERVICES
    {
        return Err(Error::InvalidServiceList);
    }
    validate_page_shape(page_index, page_count, total_count, records.len())?;
    let size = SERVICE_LIST_PREFIX_BYTES + records.len() * SERVICE_LIST_RECORD_BYTES;
    encode_header(header, 0, size, out)?;
    put_u16(out, 64, page_index)?;
    put_u16(out, 66, page_count)?;
    put_u16(out, 68, records.len() as u16)?;
    put_u16(out, 70, total_count)?;
    let mut previous: Option<&[u8]> = None;
    for (index, record) in records.iter().enumerate() {
        if record.protocol_id == 0 || record.service_generation == 0 {
            return Err(Error::InvalidServiceList);
        }
        validate_name(record.service_name)?;
        let count = usize::from(record.version_count);
        validate_versions(
            record
                .versions
                .get(..count)
                .ok_or(Error::InvalidVersionList)?,
        )?;
        if previous.is_some_and(|name| name >= record.service_name) {
            return Err(Error::InvalidServiceList);
        }
        previous = Some(record.service_name);
        let base = SERVICE_LIST_PREFIX_BYTES + index * SERVICE_LIST_RECORD_BYTES;
        put_u64(out, base, record.protocol_id)?;
        put_u64(out, base + 8, record.service_generation)?;
        put_u16(out, base + 16, record.service_name.len() as u16)?;
        out[base + 18] = record.version_count;
        for (version, value) in record.versions.iter().enumerate().take(count) {
            put_u16(out, base + 24 + version * 4, value.major)?;
            put_u16(out, base + 26 + version * 4, value.minor)?;
        }
        out[base + 40..base + 40 + record.service_name.len()].copy_from_slice(record.service_name);
    }
    Ok(size)
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
    endpoint_id: u64,
    endpoint_generation: u64,
    supervisor_role_id: u32,
    publication_id: u64,
    service_generation: u64,
    protocol_id: u64,
    versions: &[ProtocolVersion],
    name: &[u8],
    out: &mut [u8],
) -> Result<usize, Error> {
    if header.message_type != MessageType::InstallPublication
        || endpoint_id == 0
        || endpoint_generation == 0
        || supervisor_role_id == 0
        || publication_id == 0
        || service_generation == 0
        || protocol_id == 0
    {
        return Err(Error::ZeroIdentity);
    }
    validate_name(name)?;
    validate_versions(versions)?;
    let size = 120usize
        .checked_add(
            versions
                .len()
                .checked_mul(4)
                .ok_or(Error::ArithmeticOverflow)?,
        )
        .and_then(|value| value.checked_add(name.len()))
        .ok_or(Error::ArithmeticOverflow)?;
    encode_header(header, 1, size, out)?;
    put_u64(out, 64, endpoint_id)?;
    put_u64(out, 72, endpoint_generation)?;
    put_u32(out, 80, supervisor_role_id)?;
    put_u64(out, 88, publication_id)?;
    put_u64(out, 96, service_generation)?;
    put_u64(out, 104, protocol_id)?;
    put_u16(out, 112, versions.len() as u16)?;
    put_u16(out, 114, name.len() as u16)?;
    for (index, version) in versions.iter().enumerate() {
        put_u16(out, 120 + index * 4, version.major)?;
        put_u16(out, 122 + index * 4, version.minor)?;
    }
    let name_offset = 120 + versions.len() * 4;
    out[name_offset..size].copy_from_slice(name);
    Ok(size)
}

pub fn encode_install_client(
    header: Header,
    install: InstallClient,
    out: &mut [u8],
) -> Result<usize, Error> {
    if header.message_type != MessageType::InstallClient
        || install.endpoint_id == 0
        || install.endpoint_generation == 0
        || install.client_id == 0
        || install.client_generation == 0
    {
        return Err(Error::ZeroIdentity);
    }
    encode_header(header, 1, 104, out)?;
    put_u64(out, 64, install.endpoint_id)?;
    put_u64(out, 72, install.endpoint_generation)?;
    put_u64(out, 80, install.client_id)?;
    put_u64(out, 88, install.client_generation)?;
    put_u32(
        out,
        96,
        match install.scope {
            EnumerationScope::None => 0,
            EnumerationScope::BootstrapMetadata => 1,
        },
    )?;
    Ok(104)
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
    if bytes.len() < 124 {
        return Err(Error::WrongSize);
    }
    if read_u32(bytes, 84)? != 0 || read_u32(bytes, 116)? != 0 {
        return Err(Error::NonzeroReserved);
    }
    let count = usize::from(read_u16(bytes, 112)?);
    let name_len = usize::from(read_u16(bytes, 114)?);
    if !(1..=MAX_PROTOCOL_VERSIONS).contains(&count) {
        return Err(Error::InvalidVersionList);
    }
    let versions_end = 120usize
        .checked_add(count.checked_mul(4).ok_or(Error::ArithmeticOverflow)?)
        .ok_or(Error::ArithmeticOverflow)?;
    let total = versions_end
        .checked_add(name_len)
        .ok_or(Error::ArithmeticOverflow)?;
    if total != bytes.len() {
        return Err(Error::WrongSize);
    }
    let versions = VersionList {
        bytes: &bytes[120..versions_end],
    };
    validate_version_list(versions)?;
    let service_name = &bytes[versions_end..];
    validate_name(service_name)?;
    let value = InstallPublication {
        endpoint_id: read_u64(bytes, 64)?,
        endpoint_generation: read_u64(bytes, 72)?,
        supervisor_role_id: read_u32(bytes, 80)?,
        publication_id: read_u64(bytes, 88)?,
        service_generation: read_u64(bytes, 96)?,
        protocol_id: read_u64(bytes, 104)?,
        versions,
        service_name,
    };
    if value.endpoint_id == 0
        || value.endpoint_generation == 0
        || value.supervisor_role_id == 0
        || value.publication_id == 0
        || value.service_generation == 0
    {
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

fn parse_service_list(bytes: &[u8]) -> Result<ServiceListPage<'_>, Error> {
    if bytes.len() != SERVICE_LIST_PREFIX_BYTES
        && bytes.len() != SERVICE_LIST_PREFIX_BYTES + SERVICE_LIST_RECORD_BYTES
        && bytes.len() != SERVICE_LIST_PREFIX_BYTES + 2 * SERVICE_LIST_RECORD_BYTES
    {
        return Err(Error::WrongSize);
    }
    let page_index = read_u16(bytes, 64)?;
    let page_count = read_u16(bytes, 66)?;
    let record_count = read_u16(bytes, 68)?;
    let total_count = read_u16(bytes, 70)?;
    if read_u32(bytes, 72)? != 0 || read_u32(bytes, 76)? != 0 {
        return Err(Error::NonzeroReserved);
    }
    if usize::from(record_count) > MAX_SERVICE_LIST_RECORDS
        || usize::from(page_count) > MAX_SERVICE_LIST_PAGES
        || usize::from(total_count) > MAX_SERVICES
        || page_count == 0
        || page_index >= page_count
        || bytes.len()
            != SERVICE_LIST_PREFIX_BYTES + usize::from(record_count) * SERVICE_LIST_RECORD_BYTES
    {
        return Err(Error::InvalidServiceList);
    }
    validate_page_shape(
        page_index,
        page_count,
        total_count,
        usize::from(record_count),
    )?;
    let mut previous: Option<&[u8]> = None;
    for index in 0..usize::from(record_count) {
        let base = SERVICE_LIST_PREFIX_BYTES + index * SERVICE_LIST_RECORD_BYTES;
        let protocol_id = read_u64(bytes, base)?;
        let service_generation = read_u64(bytes, base + 8)?;
        let name_len = usize::from(read_u16(bytes, base + 16)?);
        let version_count = usize::from(bytes[base + 18]);
        if protocol_id == 0
            || service_generation == 0
            || bytes[base + 19] != 0
            || read_u32(bytes, base + 20)? != 0
            || !(1..=MAX_PROTOCOL_VERSIONS).contains(&version_count)
            || !(1..=MAX_SERVICE_NAME_BYTES).contains(&name_len)
        {
            return Err(Error::InvalidServiceList);
        }
        let mut previous_version = None;
        for version in 0..MAX_PROTOCOL_VERSIONS {
            let value = ProtocolVersion {
                major: read_u16(bytes, base + 24 + version * 4)?,
                minor: read_u16(bytes, base + 26 + version * 4)?,
            };
            if version < version_count {
                if previous_version.is_some_and(|prior| prior >= value) {
                    return Err(Error::NoncanonicalVersions);
                }
                previous_version = Some(value);
            } else if value != ProtocolVersion::default() {
                return Err(Error::InvalidServiceList);
            }
        }
        let name = &bytes[base + 40..base + 40 + name_len];
        validate_name(name)?;
        if bytes[base + 40 + name_len..base + SERVICE_LIST_RECORD_BYTES]
            .iter()
            .any(|byte| *byte != 0)
            || previous.is_some_and(|prior| prior >= name)
        {
            return Err(Error::InvalidServiceList);
        }
        previous = Some(name);
    }
    Ok(ServiceListPage {
        bytes,
        page_index,
        page_count,
        record_count,
        total_count,
    })
}

fn validate_page_shape(
    page_index: u16,
    page_count: u16,
    total_count: u16,
    record_count: usize,
) -> Result<(), Error> {
    let expected_pages = if total_count == 0 {
        1
    } else {
        (total_count + 1) / 2
    };
    let expected_records = if total_count == 0 {
        0
    } else if page_index + 1 < page_count {
        2
    } else {
        usize::from(total_count - 2 * (page_count - 1))
    };
    if page_count != expected_pages || record_count != expected_records {
        return Err(Error::InvalidServiceList);
    }
    Ok(())
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
fn get_u64(bytes: &[u8], offset: usize) -> Option<u64> {
    Some(u64::from_le_bytes(
        bytes.get(offset..offset.checked_add(8)?)?.try_into().ok()?,
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

fn decimal(mut value: u64, output: &mut [u8]) -> Result<usize, Error> {
    if value == 0 {
        return Err(Error::InvalidCorrelationEnvironment);
    }
    let mut reversed = [0u8; 20];
    let mut count = 0;
    while value != 0 {
        reversed[count] = b'0' + (value % 10) as u8;
        count += 1;
        value /= 10;
    }
    if output.len() < count {
        return Err(Error::InvalidCorrelationEnvironment);
    }
    for index in 0..count {
        output[index] = reversed[count - index - 1];
    }
    Ok(count)
}

fn parse_decimal(value: &str) -> Result<u64, Error> {
    if value.is_empty()
        || value.starts_with('0')
        || !value.as_bytes().iter().all(u8::is_ascii_digit)
    {
        return Err(Error::InvalidCorrelationEnvironment);
    }
    value.as_bytes().iter().try_fold(0u64, |current, digit| {
        current
            .checked_mul(10)
            .and_then(|current| current.checked_add(u64::from(digit - b'0')))
            .ok_or(Error::InvalidCorrelationEnvironment)
    })
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
}
