//! Selector-33 observer-only WRE1 evidence encoding.
//!
//! These records describe controller transitions already committed by system-init.
//! They do not add authority to WRLJ, infer shell text, or change production policy.

use deepwyrm_syscall::DwReceivedHandleInfoV1;
use wyrmroot_launch_proto::{
    Message, MessageType, Reservation, TerminationClassification, TerminationResult, parse_message,
};

use crate::InitError;

pub(crate) const RECORD_BYTES: usize = 192;
const MAGIC: [u8; 4] = *b"WRE1";
const MAJOR: u16 = 1;
const MINOR: u16 = 0;
const TYPE_SHELL_READY: u32 = 1;
const TYPE_SHELLJOBS_TRANSACTION: u32 = 2;
const TYPE_SHELL_EXITED: u32 = 3;
const TYPE_TERMINAL: u32 = 255;
const ERROR_OUTCOME_BIT: u32 = 0x8000_0000;
const MAX_RECORDS: u64 = 128;
const EXIT_DIGEST_DOMAIN: &[u8; 13] = b"WRE1-EXIT-V1\0";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ShellTuple {
    pub(crate) console_generation: u64,
    pub(crate) status_generation: u64,
    pub(crate) shell_generation: u64,
    pub(crate) outer_launch_transaction: u64,
    pub(crate) outer_job_id: u64,
    pub(crate) registry_generation: u64,
    pub(crate) registry_endpoint_id: u64,
    pub(crate) registry_endpoint_generation: u64,
    pub(crate) shell_jobs_connection_id: u64,
    pub(crate) shell_jobs_generation: u64,
}

impl ShellTuple {
    fn valid(self) -> bool {
        self.console_generation != 0
            && self.status_generation != 0
            && self.shell_generation != 0
            && self.outer_launch_transaction != 0
            && self.outer_job_id != 0
            && self.registry_generation != 0
            && self.registry_endpoint_id != 0
            && self.registry_endpoint_generation != 0
            && self.shell_jobs_connection_id != 0
            && self.shell_jobs_generation != 0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct SerialFacts {
    publication_generation: u64,
    driver_attempt_generation: u64,
    supervisor_generation: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Observer {
    nonce: u64,
    next_sequence: u64,
    serial: Option<SerialFacts>,
    tuple: Option<ShellTuple>,
    outer_result: Option<TerminationResult>,
    terminal: bool,
}

impl Observer {
    pub(crate) fn new() -> Result<Self, InitError> {
        let nonce = embedded_nonce().ok_or(InitError::Accounting)?;
        Ok(Self {
            nonce,
            next_sequence: 1,
            serial: None,
            tuple: None,
            outer_result: None,
            terminal: false,
        })
    }

    pub(crate) fn observe_serial(
        &mut self,
        publication_generation: u64,
        driver_attempt_generation: u64,
        supervisor_generation: u64,
    ) -> Result<(), InitError> {
        if publication_generation == 0
            || driver_attempt_generation == 0
            || supervisor_generation == 0
            || self.tuple.is_some()
            || self.terminal
        {
            return Err(InitError::Accounting);
        }
        self.serial = Some(SerialFacts {
            publication_generation,
            driver_attempt_generation,
            supervisor_generation,
        });
        Ok(())
    }

    #[cfg(all(test, feature = "wyr1e-selector33"))]
    pub(crate) const fn armed(&self) -> bool {
        self.serial.is_some()
    }

    #[cfg(all(test, feature = "wyr1e-selector33"))]
    pub(crate) const fn ready(&self) -> bool {
        self.tuple.is_some()
    }

    pub(crate) fn shell_ready(
        &mut self,
        tuple: ShellTuple,
        submit: impl FnOnce(&[u8; RECORD_BYTES]) -> Result<(), InitError>,
    ) -> Result<(), InitError> {
        if !tuple.valid() || self.tuple.is_some() || self.terminal {
            return Err(InitError::Accounting);
        }
        let serial = self.serial.ok_or(InitError::WrongActivationOrder)?;
        self.tuple = Some(tuple);
        let record = self.record(
            TYPE_SHELL_READY,
            0,
            0,
            0,
            0,
            [
                serial.publication_generation,
                serial.driver_attempt_generation,
                serial.supervisor_generation,
            ],
            [0; 32],
        )?;
        submit(&record)?;
        self.advance()
    }

    /// Records a launch transaction whose reply was written on a later tick.
    ///
    /// Reset card R6B-2. The one-frame path is [`Self::shell_jobs_transaction`]
    /// and this records the same thing about the same launch; what differs is
    /// only that the request bytes are gone by now, replaced by the
    /// [`LaunchRequestFacts`] taken while they were in hand. The reservation the
    /// response has to echo is checked against the request's exactly as
    /// `classify` checks it, and the digest is finished from the same preimage.
    ///
    /// A launch answers `LAUNCH_ACCEPTED` or `ERROR`; nothing else can reach
    /// here, because a deferred reply is written by the publication half and
    /// those are the only two things it sends.
    // Its only caller is the `wyr1e-selector33` deferred-reply path, but the
    // module is also compiled under plain `test` for its own units, and no
    // unit reaches this recorder. F2B leaves that gap named rather than
    // covered by a test written to the implementation.
    #[allow(
        dead_code,
        reason = "recorded only by the selector-33 deferred-reply path"
    )]
    pub(crate) fn shell_jobs_launch_response(
        &mut self,
        facts: crate::launch_request_facts::LaunchRequestFacts,
        response: &[u8],
        submit: impl FnOnce(&[u8; RECORD_BYTES]) -> Result<(), InitError>,
    ) -> Result<(), InitError> {
        let (transaction, job, kind, outcome, values) =
            classify_launch_response(facts.reservation(), response)?;
        let record = self.record(
            TYPE_SHELLJOBS_TRANSACTION,
            transaction,
            job,
            kind,
            outcome,
            values,
            facts.combine(response),
        )?;
        submit(&record)?;
        self.advance()
    }

    pub(crate) fn shell_jobs_transaction(
        &mut self,
        request: &[u8],
        response: &[u8],
        handles: &[DwReceivedHandleInfoV1],
        submit: impl FnOnce(&[u8; RECORD_BYTES]) -> Result<(), InitError>,
    ) -> Result<(), InitError> {
        let (transaction, job, kind, outcome, values) = classify(request, response, handles.len())?;
        let digest = transaction_digest(request, response, handles)?;
        let record = self.record(
            TYPE_SHELLJOBS_TRANSACTION,
            transaction,
            job,
            kind,
            outcome,
            values,
            digest,
        )?;
        submit(&record)?;
        self.advance()
    }

    pub(crate) fn observe_outer_response(
        &mut self,
        request: &[u8],
        response: &[u8],
        submit: impl FnMut(&[u8; RECORD_BYTES]) -> Result<(), InitError>,
    ) -> Result<(), InitError> {
        let parsed_request = parse_message(request, 0).map_err(|_| InitError::Accounting)?;
        let parsed_response = parse_message(response, 0).map_err(|_| InitError::Accounting)?;
        let tuple = self.tuple.ok_or(InitError::WrongActivationOrder)?;
        if parsed_request.reservation != parsed_response.reservation {
            return Err(InitError::Accounting);
        }
        match (parsed_request.message, parsed_response.message) {
            (Message::Wait { job_id: requested }, Message::JobResult { job_id, result })
                if requested == tuple.outer_job_id && job_id == requested =>
            {
                self.outer_result = Some(result);
                Ok(())
            }
            (Message::CloseJob { job_id: requested }, Message::Closed { job_id })
                if requested == tuple.outer_job_id && job_id == requested =>
            {
                self.finish_shell_exit(parsed_request.reservation.transaction_id, submit)
            }
            _ => Ok(()),
        }
    }

    fn finish_shell_exit(
        &mut self,
        close_transaction: u64,
        mut submit: impl FnMut(&[u8; RECORD_BYTES]) -> Result<(), InitError>,
    ) -> Result<(), InitError> {
        let result = self.outer_result.ok_or(InitError::WrongActivationOrder)?;
        if result.classification != TerminationClassification::NormalExit
            || result.application_code != 0
            || result.exception_class != 0
            || result.exception_detail != 0
            || result.exception_address != 0
            || result.cleanup_result != 0
            || self.terminal
        {
            return Err(InitError::Supervision);
        }
        let values = result_values(result);
        let digest = exit_digest(
            self.tuple.ok_or(InitError::WrongActivationOrder)?,
            close_transaction,
            result,
        );
        let exited = self.record(
            TYPE_SHELL_EXITED,
            close_transaction,
            self.tuple
                .ok_or(InitError::WrongActivationOrder)?
                .outer_job_id,
            MessageType::CloseJob as u32,
            result.classification.as_u32(),
            values,
            digest,
        )?;
        submit(&exited)?;
        self.advance()?;
        let terminal = self.record(TYPE_TERMINAL, 0, 0, 0, 0, [0; 3], [0; 32])?;
        submit(&terminal)?;
        self.advance()?;
        self.terminal = true;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn record(
        self,
        record_type: u32,
        operation_transaction: u64,
        job_id: u64,
        protocol_kind: u32,
        outcome_class: u32,
        values: [u64; 3],
        digest: [u8; 32],
    ) -> Result<[u8; RECORD_BYTES], InitError> {
        if self.next_sequence == 0 || self.next_sequence > MAX_RECORDS || self.terminal {
            return Err(InitError::Accounting);
        }
        let tuple = self.tuple.ok_or(InitError::WrongActivationOrder)?;
        let mut out = [0u8; RECORD_BYTES];
        out[0..4].copy_from_slice(&MAGIC);
        put_u16(&mut out, 4, MAJOR);
        put_u16(&mut out, 6, MINOR);
        put_u32(&mut out, 8, record_type);
        put_u32(&mut out, 12, RECORD_BYTES as u32);
        put_u64(&mut out, 16, self.next_sequence);
        put_u64(&mut out, 24, self.nonce);
        for (offset, value) in [
            (32, tuple.console_generation),
            (40, tuple.status_generation),
            (48, tuple.shell_generation),
            (56, tuple.outer_launch_transaction),
            (64, tuple.outer_job_id),
            (72, tuple.registry_generation),
            (80, tuple.registry_endpoint_id),
            (88, tuple.registry_endpoint_generation),
            (96, tuple.shell_jobs_connection_id),
            (104, tuple.shell_jobs_generation),
            (112, operation_transaction),
            (120, job_id),
            (136, values[0]),
            (144, values[1]),
            (152, values[2]),
        ] {
            put_u64(&mut out, offset, value);
        }
        put_u32(&mut out, 128, protocol_kind);
        put_u32(&mut out, 132, outcome_class);
        out[160..192].copy_from_slice(&digest);
        Ok(out)
    }

    fn advance(&mut self) -> Result<(), InitError> {
        self.next_sequence = self
            .next_sequence
            .checked_add(1)
            .ok_or(InitError::Accounting)?;
        Ok(())
    }
}

/// The response half of [`classify`], for a launch whose request is gone.
///
/// Reset card R6B-2. Every request-derived value `classify` would compute is
/// either carried in the facts or constant for a launch: the kind is `Launch`,
/// and the requested job id -- which an `ERROR` reply reports back -- is zero.
#[allow(
    dead_code,
    reason = "the response half of `classify`, reached only through `shell_jobs_launch_response`"
)]
fn classify_launch_response(
    reservation: Reservation,
    response: &[u8],
) -> Result<(u64, u64, u32, u32, [u64; 3]), InitError> {
    let response = parse_message(response, 0).map_err(|_| InitError::Accounting)?;
    if response.reservation != reservation {
        return Err(InitError::Accounting);
    }
    let (job, outcome) = match response.message {
        Message::LaunchAccepted { job_id } if job_id != 0 => {
            (job_id, MessageType::LaunchAccepted as u32)
        }
        Message::Error { code } => (0, ERROR_OUTCOME_BIT | code.as_u32()),
        _ => return Err(InitError::Accounting),
    };
    Ok((
        reservation.transaction_id,
        job,
        MessageType::Launch as u32,
        outcome,
        [0; 3],
    ))
}

fn classify(
    request: &[u8],
    response: &[u8],
    request_handles: usize,
) -> Result<(u64, u64, u32, u32, [u64; 3]), InitError> {
    let request = parse_message(request, request_handles).map_err(|_| InitError::Accounting)?;
    let response = parse_message(response, 0).map_err(|_| InitError::Accounting)?;
    if request.reservation != response.reservation {
        return Err(InitError::Accounting);
    }
    let (request_kind, request_job) = match request.message {
        Message::Launch(_) => (MessageType::Launch, 0),
        Message::Wait { job_id } => (MessageType::Wait, job_id),
        Message::Terminate { job_id } => (MessageType::Terminate, job_id),
        Message::ListJobs => (MessageType::ListJobs, 0),
        Message::CloseJob { job_id } => (MessageType::CloseJob, job_id),
        _ => return Err(InitError::Accounting),
    };
    let (job, outcome, values) = match response.message {
        Message::LaunchAccepted { job_id }
            if request_kind == MessageType::Launch && job_id != 0 =>
        {
            (job_id, MessageType::LaunchAccepted as u32, [0; 3])
        }
        Message::JobResult { job_id, result }
            if request_kind == MessageType::Wait && job_id == request_job =>
        {
            (
                job_id,
                (MessageType::JobResult as u32) | (result.classification.as_u32() << 16),
                result_values(result),
            )
        }
        Message::TerminationAccepted { job_id }
            if request_kind == MessageType::Terminate && job_id == request_job =>
        {
            (job_id, MessageType::TerminationAccepted as u32, [0; 3])
        }
        Message::JobList(ids) if request_kind == MessageType::ListJobs => {
            (0, MessageType::JobList as u32, [ids.len() as u64, 0, 0])
        }
        Message::Closed { job_id }
            if request_kind == MessageType::CloseJob && job_id == request_job =>
        {
            (job_id, MessageType::Closed as u32, [0; 3])
        }
        Message::Error { code } => (request_job, ERROR_OUTCOME_BIT | code.as_u32(), [0; 3]),
        _ => return Err(InitError::Accounting),
    };
    Ok((
        request.reservation.transaction_id,
        job,
        request_kind as u32,
        outcome,
        values,
    ))
}

fn result_values(result: TerminationResult) -> [u64; 3] {
    [
        u64::from(result.application_code) | (u64::from(result.exception_class) << 32),
        u64::from(result.exception_detail) | (u64::from(result.cleanup_result) << 32),
        result.exception_address,
    ]
}

fn transaction_digest(
    request: &[u8],
    response: &[u8],
    handles: &[DwReceivedHandleInfoV1],
) -> Result<[u8; 32], InitError> {
    crate::launch_request_facts::transaction_digest(request, response, handles)
}

fn exit_digest(tuple: ShellTuple, close_transaction: u64, result: TerminationResult) -> [u8; 32] {
    let mut result_bytes = [0u8; 28];
    put_u32(&mut result_bytes, 0, result.classification.as_u32());
    put_u32(&mut result_bytes, 4, result.application_code);
    put_u32(&mut result_bytes, 8, result.exception_class);
    put_u32(&mut result_bytes, 12, result.exception_detail);
    put_u64(&mut result_bytes, 16, result.exception_address);
    put_u32(&mut result_bytes, 24, result.cleanup_result);
    let mut preimage = [0u8; 129];
    preimage[..EXIT_DIGEST_DOMAIN.len()].copy_from_slice(EXIT_DIGEST_DOMAIN);
    for (index, value) in [
        tuple.console_generation,
        tuple.status_generation,
        tuple.shell_generation,
        tuple.outer_launch_transaction,
        tuple.outer_job_id,
        tuple.registry_generation,
        tuple.registry_endpoint_id,
        tuple.registry_endpoint_generation,
        tuple.shell_jobs_connection_id,
        tuple.shell_jobs_generation,
    ]
    .into_iter()
    .enumerate()
    {
        put_u64(&mut preimage, 13 + index * 8, value);
    }
    put_u64(&mut preimage, 93, close_transaction);
    preimage[101..129].copy_from_slice(&result_bytes);
    wyrmroot_runtime::sha256::digest(&preimage)
}

#[cfg(test)]
fn embedded_nonce() -> Option<u64> {
    Some(0x1122_3344_5566_7788)
}

#[cfg(not(test))]
fn embedded_nonce() -> Option<u64> {
    parse_nonce(option_env!("WYRMROOT_WYR1E7_EVIDENCE_NONCE")?)
}

fn parse_nonce(text: &str) -> Option<u64> {
    if text.len() != 16
        || !text
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'A'..=b'F').contains(byte))
    {
        return None;
    }
    let value = u64::from_str_radix(text, 16).ok()?;
    (value != 0).then_some(value)
}

fn put_u16(out: &mut [u8], offset: usize, value: u16) {
    out[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn put_u32(out: &mut [u8], offset: usize, value: u32) {
    out[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn put_u64(out: &mut [u8], offset: usize, value: u64) {
    out[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;
    use wyrmroot_launch_proto::{Reservation, encode_job_message};

    fn tuple() -> ShellTuple {
        ShellTuple {
            console_generation: 1,
            status_generation: 2,
            shell_generation: 3,
            outer_launch_transaction: 4,
            outer_job_id: 5,
            registry_generation: 6,
            registry_endpoint_id: 7,
            registry_endpoint_generation: 8,
            shell_jobs_connection_id: 9,
            shell_jobs_generation: 10,
        }
    }

    #[test]
    fn nonce_is_exact_uppercase_nonzero_hex() {
        assert_eq!(parse_nonce("1122334455667788"), Some(0x1122_3344_5566_7788));
        assert_eq!(parse_nonce("0000000000000000"), None);
        assert_eq!(parse_nonce("11223344556677aa"), None);
        assert_eq!(parse_nonce("112233445566778"), None);
    }

    #[test]
    fn ready_and_normal_exit_are_strictly_ordered_and_tuple_stable() {
        let mut observer = Observer::new().unwrap();
        observer.observe_serial(11, 12, 13).unwrap();
        let mut records = [[0u8; RECORD_BYTES]; 3];
        let mut count = 0;
        observer
            .shell_ready(tuple(), |record| {
                records[count] = *record;
                count += 1;
                Ok(())
            })
            .unwrap();
        let reservation = Reservation {
            connection_id: 20,
            generation: 21,
            transaction_id: 22,
        };
        let mut wait = [0u8; 56];
        let wait_len = encode_job_message(reservation, MessageType::Wait, 5, &mut wait).unwrap();
        let result = TerminationResult {
            classification: TerminationClassification::NormalExit,
            application_code: 0,
            exception_class: 0,
            exception_detail: 0,
            exception_address: 0,
            cleanup_result: 0,
        };
        let mut reply = [0u8; 88];
        let reply_len =
            wyrmroot_launch_proto::encode_job_result(reservation, 5, result, &mut reply).unwrap();
        observer
            .observe_outer_response(&wait[..wait_len], &reply[..reply_len], |_| Ok(()))
            .unwrap();
        let close_reservation = Reservation {
            transaction_id: 23,
            ..reservation
        };
        let mut close = [0u8; 56];
        let close_len =
            encode_job_message(close_reservation, MessageType::CloseJob, 5, &mut close).unwrap();
        let mut closed = [0u8; 56];
        let closed_len =
            encode_job_message(close_reservation, MessageType::Closed, 5, &mut closed).unwrap();
        observer
            .observe_outer_response(&close[..close_len], &closed[..closed_len], |record| {
                records[count] = *record;
                count += 1;
                Ok(())
            })
            .unwrap();
        assert_eq!(count, 3);
        assert_eq!(&records[0][0..4], b"WRE1");
        assert_eq!(u16::from_le_bytes(records[0][4..6].try_into().unwrap()), 1);
        assert_eq!(u16::from_le_bytes(records[0][6..8].try_into().unwrap()), 0);
        assert_eq!(
            u32::from_le_bytes(records[0][12..16].try_into().unwrap()),
            192
        );
        assert_eq!(
            u64::from_le_bytes(records[0][16..24].try_into().unwrap()),
            1
        );
        assert_eq!(
            u64::from_le_bytes(records[0][24..32].try_into().unwrap()),
            0x1122_3344_5566_7788
        );
        assert_eq!(
            u32::from_le_bytes(records[0][8..12].try_into().unwrap()),
            TYPE_SHELL_READY
        );
        assert_eq!(
            u32::from_le_bytes(records[1][8..12].try_into().unwrap()),
            TYPE_SHELL_EXITED
        );
        assert_eq!(
            u32::from_le_bytes(records[2][8..12].try_into().unwrap()),
            TYPE_TERMINAL
        );
        assert_eq!(&records[0][32..112], &records[2][32..112]);
        assert_eq!(
            [
                u64::from_le_bytes(records[0][136..144].try_into().unwrap()),
                u64::from_le_bytes(records[0][144..152].try_into().unwrap()),
                u64::from_le_bytes(records[0][152..160].try_into().unwrap()),
            ],
            [11, 12, 13]
        );
        assert_eq!(
            &records[1][160..192],
            &[
                0xce, 0x61, 0x7a, 0xb2, 0x56, 0x01, 0x2f, 0x9e, 0x41, 0x4d, 0xfd, 0xda, 0xc6, 0x77,
                0xc0, 0x2a, 0x8b, 0xc2, 0xc6, 0x0c, 0x90, 0x4b, 0x27, 0xe9, 0xfd, 0x13, 0xb0, 0x01,
                0xe5, 0x82, 0xa0, 0x4c,
            ]
        );
    }

    #[test]
    fn empty_list_transaction_digest_vector_is_stable() {
        let mut observer = Observer::new().unwrap();
        observer.observe_serial(11, 12, 13).unwrap();
        observer.shell_ready(tuple(), |_| Ok(())).unwrap();
        let reservation = Reservation {
            connection_id: 9,
            generation: 10,
            transaction_id: 24,
        };
        let mut request = [0u8; 56];
        let request_len =
            wyrmroot_launch_proto::encode_list_jobs(reservation, &mut request).unwrap();
        let mut response = [0u8; 320];
        let response_len =
            wyrmroot_launch_proto::encode_job_list(reservation, &[], &mut response).unwrap();
        let mut record = [0u8; RECORD_BYTES];
        observer
            .shell_jobs_transaction(
                &request[..request_len],
                &response[..response_len],
                &[],
                |value| {
                    record = *value;
                    Ok(())
                },
            )
            .unwrap();
        assert_eq!(
            &record[160..192],
            &[
                0xac, 0xcf, 0x29, 0x56, 0x3f, 0x0b, 0x19, 0x9f, 0x3a, 0x2e, 0x0f, 0xc2, 0xc6, 0x18,
                0x7b, 0x0b, 0xd3, 0x40, 0x68, 0xf9, 0xe0, 0x02, 0x5f, 0xd3, 0xdc, 0xc4, 0x9e, 0x4e,
                0x4a, 0x51, 0x29, 0xdf,
            ]
        );
    }

    #[test]
    fn zero_stream_launch_shape_is_distinct_and_admitted() {
        let mut observer = Observer::new().unwrap();
        observer.observe_serial(11, 12, 13).unwrap();
        observer.shell_ready(tuple(), |_| Ok(())).unwrap();
        let reservation = Reservation {
            connection_id: 9,
            generation: 10,
            transaction_id: 25,
        };
        let mut request = [0u8; wyrmroot_launch_proto::MAX_LAUNCH_MESSAGE_BYTES];
        let request_len = wyrmroot_launch_proto::encode_launch(
            reservation,
            "bin/cpu-hog",
            &["bin/cpu-hog"],
            &[],
            false,
            &mut request,
        )
        .unwrap();
        let mut response = [0u8; 56];
        let response_len =
            encode_job_message(reservation, MessageType::LaunchAccepted, 26, &mut response)
                .unwrap();
        observer
            .shell_jobs_transaction(
                &request[..request_len],
                &response[..response_len],
                &[],
                |_| Ok(()),
            )
            .unwrap();
    }

    #[test]
    fn transaction_rejects_a_reply_for_another_request_or_job() {
        let mut observer = Observer::new().unwrap();
        observer.observe_serial(11, 12, 13).unwrap();
        observer.shell_ready(tuple(), |_| Ok(())).unwrap();
        let reservation = Reservation {
            connection_id: 9,
            generation: 10,
            transaction_id: 26,
        };
        let mut request = [0u8; 56];
        let request_len =
            wyrmroot_launch_proto::encode_list_jobs(reservation, &mut request).unwrap();
        let mut response = [0u8; 56];
        let response_len =
            encode_job_message(reservation, MessageType::LaunchAccepted, 27, &mut response)
                .unwrap();
        assert_eq!(
            observer.shell_jobs_transaction(
                &request[..request_len],
                &response[..response_len],
                &[],
                |_| Ok(()),
            ),
            Err(InitError::Accounting)
        );

        let wait_len =
            encode_job_message(reservation, MessageType::Wait, 28, &mut request).unwrap();
        let result = TerminationResult {
            classification: TerminationClassification::NormalExit,
            application_code: 0,
            exception_class: 0,
            exception_detail: 0,
            exception_address: 0,
            cleanup_result: 0,
        };
        let mut result_response = [0u8; 88];
        let result_len =
            wyrmroot_launch_proto::encode_job_result(reservation, 29, result, &mut result_response)
                .unwrap();
        assert_eq!(
            observer.shell_jobs_transaction(
                &request[..wait_len],
                &result_response[..result_len],
                &[],
                |_| Ok(()),
            ),
            Err(InitError::Accounting)
        );
    }
}
