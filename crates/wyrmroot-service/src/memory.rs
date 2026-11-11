//! Shared buffers: a MemoryObject the role keeps mapped, with a second,
//! narrower handle to hand to a block device.
//!
//! Mapping is a seam ([`Mapper`]) because host tests cannot map: they supply
//! a mapper over the model's shared bytes.

use deepwyrm_syscall::{
    DW_RIGHT_DUPLICATE, DW_RIGHT_INSPECT, DW_RIGHT_MAP, DW_RIGHT_READ, DW_RIGHT_TRANSFER,
    DW_RIGHT_WRITE, DwHandle, DwRights,
};
use wyrmroot_runtime::{HandlePlatform, MemoryPlatform, NativeError, OwnedMemoryMapping};

/// Byte access to one mapped buffer.
pub trait View {
    fn len(&self) -> u64;
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
    /// `false` if the range lies outside the buffer.
    fn read(&self, offset: u64, out: &mut [u8]) -> bool;
    fn write(&mut self, offset: u64, data: &[u8]) -> bool;
}

/// Maps a MemoryObject into the role's own address space.
pub trait Mapper<P: ?Sized> {
    type View: View;
    fn map(
        &mut self,
        platform: &mut P,
        root: DwHandle,
        memory: DwHandle,
        bytes: u64,
    ) -> Result<Self::View, NativeError>;
    fn unmap(&mut self, platform: &mut P, view: Self::View) -> bool;
}

/// The role's own handle: mappable and duplicable.
pub const KEEP_RIGHTS: DwRights = DwRights(
    DW_RIGHT_READ.0 | DW_RIGHT_WRITE.0 | DW_RIGHT_MAP.0 | DW_RIGHT_DUPLICATE.0 | DW_RIGHT_INSPECT.0,
);
/// The handle a block device receives: device-readable and -writable and
/// movable once more, never mappable by the receiver.
pub const LEND_RIGHTS: DwRights =
    DwRights(DW_RIGHT_READ.0 | DW_RIGHT_WRITE.0 | DW_RIGHT_TRANSFER.0);

/// Creates a `bytes`-long MemoryObject: returns the role's handle and the
/// handle to lend.
pub fn create_buffer<P: HandlePlatform + MemoryPlatform + ?Sized>(
    platform: &mut P,
    bytes: u64,
) -> Result<(DwHandle, DwHandle), NativeError> {
    let keep =
        platform.create_memory_object(bytes, DwRights(KEEP_RIGHTS.0 | DW_RIGHT_TRANSFER.0))?;
    match platform.duplicate_handle(keep, LEND_RIGHTS) {
        Ok(lend) => Ok((keep, lend)),
        Err(error) => {
            let _ = platform.close_handle(keep);
            Err(error)
        }
    }
}

/// The production mapper: an ordinary read-write mapping, read and written
/// with bounds-checked volatile accesses.
pub struct NativeMapper;

pub struct NativeView(OwnedMemoryMapping);

impl View for NativeView {
    fn len(&self) -> u64 {
        self.0.byte_len()
    }

    fn read(&self, offset: u64, out: &mut [u8]) -> bool {
        let Some(end) = offset.checked_add(out.len() as u64) else {
            return false;
        };
        if end > self.len() {
            return false;
        }
        for (index, byte) in out.iter_mut().enumerate() {
            match self.0.read_u8(offset + index as u64) {
                Ok(value) => *byte = value,
                Err(_) => return false,
            }
        }
        true
    }

    fn write(&mut self, offset: u64, data: &[u8]) -> bool {
        let Some(end) = offset.checked_add(data.len() as u64) else {
            return false;
        };
        if end > self.len() {
            return false;
        }
        data.iter()
            .enumerate()
            .all(|(index, &byte)| self.0.write_u8(offset + index as u64, byte).is_ok())
    }
}

impl<P: MemoryPlatform + ?Sized> Mapper<P> for NativeMapper {
    type View = NativeView;

    fn map(
        &mut self,
        platform: &mut P,
        root: DwHandle,
        memory: DwHandle,
        bytes: u64,
    ) -> Result<NativeView, NativeError> {
        platform
            .map_memory_read_write(root, memory, bytes)
            .map(NativeView)
    }

    fn unmap(&mut self, platform: &mut P, view: NativeView) -> bool {
        platform.unmap_memory(view.0).is_ok()
    }
}
