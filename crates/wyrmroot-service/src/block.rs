//! A synchronous WRBD client: one request outstanding, each answered before
//! the next is sent.

use deepwyrm_syscall::{
    DW_HANDLE_TRANSFER_MOVE, DwDeadline, DwHandle, DwHandleTransferV1, DwReceivedHandleInfoV1,
    DwRights,
};
use wyrmroot_block_proto::{self as wrbd, Body, Info, MAX_BYTES, Message, Status, Transfer};

use crate::{ServicePlatform, close_all, wait_readable};

pub struct BlockClient {
    pub channel: DwHandle,
    pub info: Info,
    next_transaction: u64,
}

impl BlockClient {
    /// Asks the device for its geometry. Steps 60..=66.
    pub fn open<P: ServicePlatform + ?Sized>(
        platform: &mut P,
        channel: DwHandle,
        deadline: DwDeadline,
    ) -> Result<Self, u32> {
        let mut client = Self {
            channel,
            info: Info {
                block_size: 512,
                flags: 0,
                block_count: 1,
                max_transfer_blocks: 1,
            },
            next_transaction: 1,
        };
        match client.request(platform, Body::GetInfo, None, deadline)? {
            Body::Info(info) => {
                client.info = info;
                Ok(client)
            }
            _ => Err(66),
        }
    }

    /// Attaches the buffer `memory`, moved with `rights`. Step 67 is a
    /// refusal by the device.
    pub fn attach<P: ServicePlatform + ?Sized>(
        &mut self,
        platform: &mut P,
        memory: DwHandle,
        rights: DwRights,
        byte_len: u64,
        deadline: DwDeadline,
    ) -> Result<(), u32> {
        match self.request(
            platform,
            Body::Attach { byte_len },
            Some((memory, rights)),
            deadline,
        )? {
            Body::Complete(Status::Ok) => Ok(()),
            _ => Err(67),
        }
    }

    /// Reads `block_count` blocks from `lba` into the attached buffer at
    /// `buffer_offset`; the device's refusal or error is `Ok(status)`.
    pub fn read<P: ServicePlatform + ?Sized>(
        &mut self,
        platform: &mut P,
        lba: u64,
        block_count: u32,
        buffer_offset: u64,
        deadline: DwDeadline,
    ) -> Result<Status, u32> {
        match self.request(
            platform,
            Body::Read(Transfer {
                lba,
                block_count,
                buffer_offset,
            }),
            None,
            deadline,
        )? {
            Body::Complete(status) => Ok(status),
            _ => Err(68),
        }
    }

    /// Writes `block_count` blocks at `lba` from the attached buffer at
    /// `buffer_offset`; the device's refusal or error is `Ok(status)`.
    pub fn write<P: ServicePlatform + ?Sized>(
        &mut self,
        platform: &mut P,
        lba: u64,
        block_count: u32,
        buffer_offset: u64,
        deadline: DwDeadline,
    ) -> Result<Status, u32> {
        match self.request(
            platform,
            Body::Write(Transfer {
                lba,
                block_count,
                buffer_offset,
            }),
            None,
            deadline,
        )? {
            Body::Complete(status) => Ok(status),
            _ => Err(68),
        }
    }

    /// Makes every completed write durable; the device's answer is
    /// `Ok(status)`.
    pub fn flush<P: ServicePlatform + ?Sized>(
        &mut self,
        platform: &mut P,
        deadline: DwDeadline,
    ) -> Result<Status, u32> {
        match self.request(platform, Body::Flush, None, deadline)? {
            Body::Complete(status) => Ok(status),
            _ => Err(68),
        }
    }

    /// Sends one request and returns the reply body. Steps 60..=65.
    fn request<P: ServicePlatform + ?Sized>(
        &mut self,
        platform: &mut P,
        body: Body,
        handle: Option<(DwHandle, DwRights)>,
        deadline: DwDeadline,
    ) -> Result<Body, u32> {
        let transaction_id = self.next_transaction;
        self.next_transaction += 1;
        let mut bytes = [0u8; MAX_BYTES];
        let size = wrbd::encode(
            Message {
                transaction_id,
                body,
            },
            &mut bytes,
        )
        .map_err(|_| 60u32)?;
        let transfers = handle.map(|(handle, requested_rights)| DwHandleTransferV1 {
            handle,
            requested_rights,
            operation: DW_HANDLE_TRANSFER_MOVE,
            reserved0: 0,
            reserved: [0; 2],
        });
        platform
            .send_channel(self.channel, &bytes[..size], transfers.as_slice())
            .map_err(|_| 61u32)?;
        wait_readable(platform, self.channel, deadline, 62)?;
        let mut handles = [DwReceivedHandleInfoV1::default(); 1];
        let counts = platform
            .receive_channel(self.channel, &mut bytes, &mut handles)
            .map_err(|_| 63u32)?;
        if counts.handles != 0 {
            close_all(platform, &handles[..counts.handles.min(1)]);
            return Err(64);
        }
        let reply = wrbd::parse(&bytes[..counts.bytes], 0).map_err(|_| 65u32)?;
        if reply.transaction_id != transaction_id || reply.body.is_request() {
            return Err(65);
        }
        Ok(reply.body)
    }
}
