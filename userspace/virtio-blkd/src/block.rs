//! WRBD requests checked and turned into virtio requests.

use wyrmroot_block_proto::{INFO_FLUSH, INFO_READ_ONLY, Info, Status, Transfer};

use crate::virtio::{Geometry, Request, SECTOR_BYTES};

/// The most bytes one READ or WRITE moves.
pub const MAX_TRANSFER_BYTES: u32 = 128 * 1024;
/// The largest buffer a client may attach. Each mapping's page tables come
/// from the kernel's fixed 64-frame IOMMU pool, so buffers stay small.
pub const MAX_ATTACH_BYTES: u64 = 1024 * 1024;

/// A client's attached buffer: its length and where the device sees it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Buffer {
    pub iova: u64,
    pub bytes: u64,
}

/// What INFO reports for `geometry`.
pub const fn info(geometry: Geometry) -> Info {
    let mut flags = 0;
    if geometry.read_only {
        flags |= INFO_READ_ONLY;
    }
    if geometry.flush {
        flags |= INFO_FLUSH;
    }
    Info {
        block_size: geometry.block_size,
        flags,
        block_count: geometry.block_count,
        max_transfer_blocks: MAX_TRANSFER_BYTES / geometry.block_size,
    }
}

/// Checks one READ or WRITE against the device and the attached buffer.
pub fn plan_transfer(
    geometry: Geometry,
    buffer: Option<Buffer>,
    transfer: Transfer,
    write: bool,
) -> Result<Request, Status> {
    let buffer = buffer.ok_or(Status::NoBuffer)?;
    if write && geometry.read_only {
        return Err(Status::ReadOnly);
    }
    let block_size = u64::from(geometry.block_size);
    if transfer.block_count == 0
        || transfer.block_count > info(geometry).max_transfer_blocks
        || !transfer.buffer_offset.is_multiple_of(block_size)
    {
        return Err(Status::Invalid);
    }
    let blocks = u64::from(transfer.block_count);
    let end = transfer.lba.checked_add(blocks).ok_or(Status::OutOfRange)?;
    let bytes = blocks * block_size;
    let buffer_end = transfer
        .buffer_offset
        .checked_add(bytes)
        .ok_or(Status::OutOfRange)?;
    if end > geometry.block_count || buffer_end > buffer.bytes {
        return Err(Status::OutOfRange);
    }
    // In range of the device, so the sector number cannot overflow.
    let sector = transfer.lba * (block_size / SECTOR_BYTES);
    let data_iova = buffer.iova + transfer.buffer_offset;
    let bytes = bytes as u32;
    Ok(if write {
        Request::Write {
            sector,
            data_iova,
            bytes,
        }
    } else {
        Request::Read {
            sector,
            data_iova,
            bytes,
        }
    })
}

/// Checks a FLUSH against the device.
pub const fn plan_flush(geometry: Geometry) -> Result<Request, Status> {
    if geometry.flush {
        Ok(Request::Flush)
    } else {
        Err(Status::Unsupported)
    }
}

/// Checks an ATTACH's length against the limit. The kernel's `dma_map`
/// checks it against the object itself.
pub const fn check_attach(byte_len: u64) -> Result<(), Status> {
    if byte_len > MAX_ATTACH_BYTES {
        return Err(Status::Invalid);
    }
    Ok(())
}
