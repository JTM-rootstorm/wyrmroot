// SPDX-License-Identifier: GPL-3.0-or-later

use wyrmroot_console_proto::{
    ErrorCode as ConsoleErrorCode, Header as ConsoleHeader, Message as ConsoleMessage, Snapshot,
};
use wyrmroot_launch_proto::{
    ErrorCode as LaunchErrorCode, JobIds, Message as LaunchMessage, Reservation,
};
use wyrmroot_registry_proto::{
    ErrorCode as RegistryErrorCode, Header as RegistryHeader, Message as RegistryMessage,
    MessageType as RegistryMessageType,
};

use crate::ShellIdentity;

pub(crate) const STATUS_TIMEOUT_NS: u64 = 1_000_000_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum InspectionError {
    CounterOverflow,
    Encode,
    Malformed,
    Correlation,
    Sequence,
    Registry(RegistryErrorCode),
    Launch(LaunchErrorCode),
    Console(ConsoleErrorCode),
}

pub(crate) struct TransactionIds {
    registry: u64,
    launch: u64,
    status: u64,
}

impl TransactionIds {
    pub(crate) const fn new() -> Self {
        Self {
            registry: 2,
            launch: 1,
            status: 1,
        }
    }

    pub(crate) fn registry(&mut self) -> Result<u64, InspectionError> {
        take(&mut self.registry)
    }

    pub(crate) fn launch(&mut self) -> Result<u64, InspectionError> {
        take(&mut self.launch)
    }

    pub(crate) fn status(&mut self) -> Result<u64, InspectionError> {
        take(&mut self.status)
    }
}

fn take(next: &mut u64) -> Result<u64, InspectionError> {
    let value = *next;
    *next = value
        .checked_add(1)
        .ok_or(InspectionError::CounterOverflow)?;
    if value == 0 {
        return Err(InspectionError::CounterOverflow);
    }
    Ok(value)
}

pub(crate) fn encode_registry_request(
    identity: ShellIdentity,
    transaction: u64,
    output: &mut [u8],
) -> Result<usize, InspectionError> {
    wyrmroot_registry_proto::encode_empty(
        RegistryHeader {
            message_type: RegistryMessageType::Enumerate,
            registry_generation: identity.registry_generation,
            endpoint_id: identity.registry_endpoint_id,
            endpoint_generation: identity.registry_endpoint_generation,
            transaction_id: transaction,
        },
        output,
    )
    .map_err(|_| InspectionError::Encode)
}

pub(crate) fn encode_launch_request(
    identity: ShellIdentity,
    transaction: u64,
    output: &mut [u8],
) -> Result<usize, InspectionError> {
    wyrmroot_launch_proto::encode_list_jobs(launch_reservation(identity, transaction), output)
        .map_err(|_| InspectionError::Encode)
}

pub(crate) fn encode_status_request(
    identity: ShellIdentity,
    transaction: u64,
    output: &mut [u8],
) -> Result<usize, InspectionError> {
    wyrmroot_console_proto::encode_query(status_header(identity, transaction), output)
        .map_err(|_| InspectionError::Encode)
}

pub(crate) struct RegistrySequence {
    expected_page: u16,
    page_count: Option<u16>,
    total_count: Option<u16>,
    observed_total: u16,
    previous_name: [u8; wyrmroot_registry_proto::MAX_SERVICE_NAME_BYTES],
    previous_name_len: usize,
    records: [ServiceRecord; wyrmroot_registry_proto::MAX_SERVICES],
    record_count: usize,
}

impl RegistrySequence {
    pub(crate) const fn new() -> Self {
        Self {
            expected_page: 0,
            page_count: None,
            total_count: None,
            observed_total: 0,
            previous_name: [0; wyrmroot_registry_proto::MAX_SERVICE_NAME_BYTES],
            previous_name_len: 0,
            records: [ServiceRecord::EMPTY; wyrmroot_registry_proto::MAX_SERVICES],
            record_count: 0,
        }
    }

    pub(crate) fn accept(
        &mut self,
        identity: ShellIdentity,
        transaction: u64,
        bytes: &[u8],
        handles: usize,
    ) -> Result<bool, InspectionError> {
        let parsed = wyrmroot_registry_proto::parse(bytes, handles)
            .map_err(|_| InspectionError::Malformed)?;
        if parsed.header.registry_generation != identity.registry_generation
            || parsed.header.endpoint_id != identity.registry_endpoint_id
            || parsed.header.endpoint_generation != identity.registry_endpoint_generation
            || parsed.header.transaction_id != transaction
        {
            return Err(InspectionError::Correlation);
        }
        let page = match parsed.message {
            RegistryMessage::ServiceList(page) => page,
            RegistryMessage::Error { code } => return Err(InspectionError::Registry(code)),
            _ => return Err(InspectionError::Malformed),
        };
        if page.page_index != self.expected_page
            || self
                .page_count
                .is_some_and(|count| count != page.page_count)
            || self
                .total_count
                .is_some_and(|count| count != page.total_count)
        {
            return Err(InspectionError::Sequence);
        }
        for index in 0..usize::from(page.record_count) {
            let record = page.record(index).ok_or(InspectionError::Malformed)?;
            if self.previous_name_len != 0
                && self.previous_name[..self.previous_name_len] >= *record.service_name
            {
                return Err(InspectionError::Sequence);
            }
            self.previous_name[..record.service_name.len()].copy_from_slice(record.service_name);
            self.previous_name_len = record.service_name.len();
            let target = self
                .records
                .get_mut(self.record_count)
                .ok_or(InspectionError::Sequence)?;
            *target = ServiceRecord::from_wire(record);
            self.record_count = self
                .record_count
                .checked_add(1)
                .ok_or(InspectionError::Sequence)?;
        }
        self.page_count = Some(page.page_count);
        self.total_count = Some(page.total_count);
        self.observed_total = self
            .observed_total
            .checked_add(page.record_count)
            .ok_or(InspectionError::Sequence)?;
        self.expected_page = self
            .expected_page
            .checked_add(1)
            .ok_or(InspectionError::Sequence)?;
        let complete = self.expected_page == page.page_count;
        if complete && self.observed_total != page.total_count {
            return Err(InspectionError::Sequence);
        }
        if !complete
            && usize::from(self.expected_page) >= wyrmroot_registry_proto::MAX_SERVICE_LIST_PAGES
        {
            return Err(InspectionError::Sequence);
        }
        Ok(complete)
    }

    pub(crate) const fn len(&self) -> usize {
        self.record_count
    }

    pub(crate) fn record(&self, index: usize) -> Option<&ServiceRecord> {
        self.records
            .get(index)
            .filter(|_| index < self.record_count)
    }
}

#[derive(Clone, Copy)]
pub(crate) struct ServiceRecord {
    pub(crate) protocol_id: u64,
    pub(crate) service_generation: u64,
    pub(crate) versions:
        [wyrmroot_registry_proto::ProtocolVersion; wyrmroot_registry_proto::MAX_PROTOCOL_VERSIONS],
    pub(crate) version_count: u8,
    name: [u8; wyrmroot_registry_proto::MAX_SERVICE_NAME_BYTES],
    name_len: u8,
}

impl ServiceRecord {
    const EMPTY: Self = Self {
        protocol_id: 0,
        service_generation: 0,
        versions: [wyrmroot_registry_proto::ProtocolVersion { major: 0, minor: 0 };
            wyrmroot_registry_proto::MAX_PROTOCOL_VERSIONS],
        version_count: 0,
        name: [0; wyrmroot_registry_proto::MAX_SERVICE_NAME_BYTES],
        name_len: 0,
    };

    fn from_wire(value: wyrmroot_registry_proto::ServiceListRecord<'_>) -> Self {
        let mut result = Self::EMPTY;
        result.protocol_id = value.protocol_id;
        result.service_generation = value.service_generation;
        result.versions = value.versions;
        result.version_count = value.version_count;
        result.name[..value.service_name.len()].copy_from_slice(value.service_name);
        result.name_len = value.service_name.len() as u8;
        result
    }

    pub(crate) fn name(&self) -> &[u8] {
        &self.name[..usize::from(self.name_len)]
    }
}

pub(crate) fn decode_jobs<'a>(
    identity: ShellIdentity,
    transaction: u64,
    bytes: &'a [u8],
    handles: usize,
) -> Result<JobIds<'a>, InspectionError> {
    let parsed = wyrmroot_launch_proto::parse_message(bytes, handles)
        .map_err(|_| InspectionError::Malformed)?;
    if parsed.reservation != launch_reservation(identity, transaction) {
        return Err(InspectionError::Correlation);
    }
    match parsed.message {
        LaunchMessage::JobList(ids) => Ok(ids),
        LaunchMessage::Error { code } => Err(InspectionError::Launch(code)),
        _ => Err(InspectionError::Malformed),
    }
}

pub(crate) fn decode_status(
    identity: ShellIdentity,
    transaction: u64,
    bytes: &[u8],
    handles: usize,
) -> Result<Snapshot, InspectionError> {
    let expected = status_header(identity, transaction);
    match wyrmroot_console_proto::decode(bytes, handles).map_err(|_| InspectionError::Malformed)? {
        ConsoleMessage::Snapshot(header, snapshot) if header == expected => {
            if snapshot.flags & wyrmroot_console_proto::FLAG_CHILD_PRESENT != 0
                && (snapshot.child_generation != identity.child_generation
                    || snapshot.outer_launch_transaction != identity.outer_launch_transaction)
            {
                return Err(InspectionError::Correlation);
            }
            Ok(snapshot)
        }
        ConsoleMessage::Error(header, code) if header == expected => {
            Err(InspectionError::Console(code))
        }
        ConsoleMessage::Snapshot(_, _) | ConsoleMessage::Error(_, _) => {
            Err(InspectionError::Correlation)
        }
        ConsoleMessage::Query(_) => Err(InspectionError::Malformed),
    }
}

const fn launch_reservation(identity: ShellIdentity, transaction: u64) -> Reservation {
    Reservation {
        connection_id: identity.launch_connection_id,
        generation: identity.launch_connection_generation,
        transaction_id: transaction,
    }
}

const fn status_header(identity: ShellIdentity, transaction: u64) -> ConsoleHeader {
    ConsoleHeader {
        transaction_id: transaction,
        console_generation: identity.console_generation,
        status_generation: identity.status_generation,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const IDENTITY: ShellIdentity = ShellIdentity {
        transaction_id: 1,
        registry_generation: 2,
        registry_endpoint_id: 3,
        registry_endpoint_generation: 4,
        launch_connection_id: 5,
        launch_connection_generation: 6,
        console_generation: 7,
        status_generation: 8,
        child_generation: 9,
        outer_launch_transaction: 10,
    };

    #[test]
    fn transaction_namespaces_are_independent_checked_and_registry_starts_at_two() {
        let mut ids = TransactionIds::new();
        assert_eq!(ids.registry(), Ok(2));
        assert_eq!(ids.launch(), Ok(1));
        assert_eq!(ids.status(), Ok(1));
        ids.status = u64::MAX;
        assert_eq!(ids.status(), Err(InspectionError::CounterOverflow));
        assert_eq!(ids.status, u64::MAX);
    }

    #[test]
    fn request_encoders_produce_canonical_codec_parseable_messages() {
        let mut bytes = [0_u8; 64];
        let size = encode_registry_request(IDENTITY, 2, &mut bytes).unwrap();
        assert!(matches!(
            wyrmroot_registry_proto::parse(&bytes[..size], 0)
                .unwrap()
                .message,
            RegistryMessage::Enumerate
        ));

        let size = encode_launch_request(IDENTITY, 1, &mut bytes).unwrap();
        assert!(matches!(
            wyrmroot_launch_proto::parse_message(&bytes[..size], 0)
                .unwrap()
                .message,
            LaunchMessage::ListJobs
        ));

        let size = encode_status_request(IDENTITY, 1, &mut bytes).unwrap();
        assert!(matches!(
            wyrmroot_console_proto::decode(&bytes[..size], 0).unwrap(),
            ConsoleMessage::Query(_)
        ));
    }
}
