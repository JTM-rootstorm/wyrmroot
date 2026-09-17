//! What a deferred launch reply still needs from the request that provoked it.
//!
//! Reset card R6B-2. The evidence join wants the request bytes and the response
//! bytes in one frame: `transaction_digest` hashes both, and `classify` reads
//! the envelope off each and refuses if they disagree. While construction and
//! publication shared a frame that cost nothing, because the request buffer was
//! still a local. A launch that returns to the event loop in between no longer
//! has it, and cannot keep it -- `MAX_LAUNCH_MESSAGE_BYTES` is 17,760, which
//! reset plan §7.1 measured and ruled out at R6B.
//!
//! It does not have to. `transaction_digest` hashes the request, the response
//! and the moved-handle shape *independently* before combining them, so the
//! request's whole contribution to the record is two 32-byte digests. Add the
//! reservation the response must echo and that is 88 bytes standing in for
//! 17,760 -- and, unlike the bytes, a size that does not depend on the request.
//!
//! The rest of what `classify` reads from a launch request is constant. The
//! arena only ever holds `LAUNCH` messages, so the message kind is `Launch` and
//! the requested job id is zero; both are asserted here rather than assumed, by
//! refusing to build facts for any other message.
//!
//! # Not a new digest
//!
//! The values this produces are the same bytes the one-frame path produced, and
//! must stay that way: `tools/verify-vm-request.py` and the E8 producer fixture
//! both check recorded digests against independently computed ones. The
//! preimage layout below is `transaction_digest`'s, moved rather than rewritten,
//! and both evidence modules now compute through here so there is one copy to
//! drift from instead of two.

use deepwyrm_syscall::DwReceivedHandleInfoV1;
use wyrmroot_launch_proto::{Message, Reservation, parse_message};

use crate::InitError;

const TX_DIGEST_DOMAIN: &[u8; 11] = b"WRE1-TX-V1\0";
const HANDLE_DIGEST_DOMAIN: &[u8; 16] = b"WRE1-HANDLES-V1\0";

/// The largest moved-handle count a launch request may carry.
const MAX_REQUEST_HANDLES: usize = 3;

/// The request-derived half of one launch transaction's evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct LaunchRequestFacts {
    reservation: Reservation,
    request_digest: [u8; 32],
    shape_digest: [u8; 32],
}

impl LaunchRequestFacts {
    /// Reads everything the join will still need, at the moment the bytes are
    /// in hand.
    ///
    /// Refuses anything that is not a `LAUNCH`: the arena holds launches, and a
    /// `WAIT` or `CLOSE_JOB` reaching here would mean its constant kind and
    /// zero job id were being asserted about the wrong message.
    pub(crate) fn of(
        request: &[u8],
        handles: &[DwReceivedHandleInfoV1],
    ) -> Result<Self, InitError> {
        if handles.len() > MAX_REQUEST_HANDLES {
            return Err(InitError::Accounting);
        }
        let parsed = parse_message(request, handles.len()).map_err(InitError::LaunchProtocol)?;
        if !matches!(parsed.message, Message::Launch(_)) {
            return Err(InitError::Accounting);
        }
        Ok(Self {
            reservation: parsed.reservation,
            request_digest: wyrmroot_runtime::sha256::digest(request),
            shape_digest: handle_shape_digest(handles),
        })
    }

    pub(crate) const fn reservation(self) -> Reservation {
        self.reservation
    }

    /// Finishes the transaction digest once the response exists.
    ///
    /// Shares [`combine`] with the one-frame path, so a deferred reply and an
    /// immediate one cannot drift apart in what they record.
    pub(crate) fn combine(self, response: &[u8]) -> [u8; 32] {
        combine(
            &self.request_digest,
            &wyrmroot_runtime::sha256::digest(response),
            &self.shape_digest,
        )
    }
}

/// The whole digest, for callers that still hold both halves at once.
///
/// This is `transaction_digest` as both evidence modules wrote it inline. They
/// now call through here instead of each keeping a copy.
pub(crate) fn transaction_digest(
    request: &[u8],
    response: &[u8],
    handles: &[DwReceivedHandleInfoV1],
) -> Result<[u8; 32], InitError> {
    if handles.len() > MAX_REQUEST_HANDLES {
        return Err(InitError::Accounting);
    }
    Ok(combine(
        &wyrmroot_runtime::sha256::digest(request),
        &wyrmroot_runtime::sha256::digest(response),
        &handle_shape_digest(handles),
    ))
}

/// Domain, request digest, response digest, handle-shape digest, in that order.
fn combine(request: &[u8; 32], response: &[u8; 32], shape: &[u8; 32]) -> [u8; 32] {
    let mut preimage = [0u8; 107];
    preimage[..TX_DIGEST_DOMAIN.len()].copy_from_slice(TX_DIGEST_DOMAIN);
    preimage[11..43].copy_from_slice(request);
    preimage[43..75].copy_from_slice(response);
    preimage[75..107].copy_from_slice(shape);
    wyrmroot_runtime::sha256::digest(&preimage)
}

/// The moved-handle shape digest, identical to what both evidence modules
/// computed inline before R6B-2 moved it here.
pub(crate) fn handle_shape_digest(handles: &[DwReceivedHandleInfoV1]) -> [u8; 32] {
    let mut shape = [0u8; 72];
    shape[..HANDLE_DIGEST_DOMAIN.len()].copy_from_slice(HANDLE_DIGEST_DOMAIN);
    let count = handles.len().min(MAX_REQUEST_HANDLES);
    shape[16..20].copy_from_slice(&(handles.len() as u32).to_le_bytes());
    for (index, handle) in handles.iter().take(MAX_REQUEST_HANDLES).enumerate() {
        let offset = 20 + index * 16;
        shape[offset..offset + 4].copy_from_slice(&handle.object_type.0.to_le_bytes());
        shape[offset + 4..offset + 12].copy_from_slice(&handle.rights.0.to_le_bytes());
        shape[offset + 12..offset + 16].copy_from_slice(&(index as u32 + 1).to_le_bytes());
    }
    wyrmroot_runtime::sha256::digest(&shape[..20 + count * 16])
}

#[cfg(test)]
mod tests {
    use super::*;
    use wyrmroot_launch_proto::{MessageType, encode_job_message, encode_launch};

    fn reservation() -> Reservation {
        Reservation {
            connection_id: 7,
            generation: 3,
            transaction_id: 11,
        }
    }

    /// The whole of R6B-2's claim about evidence, in one assertion: a record
    /// written a tick after the request it describes is byte-identical to one
    /// written in the same frame. If this ever stops holding, every recorded
    /// transaction digest stops matching what `tools/verify-vm-request.py`
    /// recomputes from the log, and the failure would show up as unreadable
    /// evidence rather than as a broken test.
    #[test]
    fn a_deferred_digest_is_the_same_bytes_as_a_one_frame_digest() {
        let mut request = [0u8; 256];
        let request_size = encode_launch(
            reservation(),
            "bin/hello",
            &["bin/hello"],
            &[],
            false,
            &mut request,
        )
        .expect("encode launch");
        let mut response = [0u8; 88];
        let response_size =
            encode_job_message(reservation(), MessageType::LaunchAccepted, 9, &mut response)
                .expect("encode reply");
        let handles: [DwReceivedHandleInfoV1; 0] = [];

        let one_frame = transaction_digest(
            &request[..request_size],
            &response[..response_size],
            &handles,
        )
        .expect("one-frame digest");
        let deferred = LaunchRequestFacts::of(&request[..request_size], &handles)
            .expect("facts")
            .combine(&response[..response_size]);

        assert_eq!(deferred, one_frame);
    }

    /// The facts stand in for a launch and only a launch. Anything else
    /// reaching them would mean the constant message kind and zero job id the
    /// deferred classifier asserts were being asserted about the wrong message.
    #[test]
    fn facts_refuse_a_message_that_is_not_a_launch() {
        let mut request = [0u8; 88];
        let size = encode_job_message(reservation(), MessageType::Wait, 4, &mut request)
            .expect("encode wait");
        let handles: [DwReceivedHandleInfoV1; 0] = [];
        assert_eq!(
            LaunchRequestFacts::of(&request[..size], &handles),
            Err(InitError::Accounting)
        );
    }

    /// The shared helper must produce the byte-for-byte digest the two evidence
    /// modules produced inline, or every recorded transaction digest changes
    /// and `tools/verify-vm-request.py` stops agreeing with the guest.
    #[test]
    fn the_shape_digest_matches_the_inline_preimage_it_replaced() {
        let handles: [DwReceivedHandleInfoV1; 0] = [];
        let mut shape = [0u8; 72];
        shape[..HANDLE_DIGEST_DOMAIN.len()].copy_from_slice(HANDLE_DIGEST_DOMAIN);
        shape[16..20].copy_from_slice(&0_u32.to_le_bytes());
        assert_eq!(
            handle_shape_digest(&handles),
            wyrmroot_runtime::sha256::digest(&shape[..20])
        );
    }
}
