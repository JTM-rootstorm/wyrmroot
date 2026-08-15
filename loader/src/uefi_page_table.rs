//! Four-level x86_64 transition page-table encoder over retained UEFI pages.
//!
//! The caller supplies a contiguous, pre-zeroed `LoaderData` allocation. This
//! encoder never allocates, never reaches outside that allocation, and maps
//! only 4 KiB supervisor pages. The unsafe conversion from retained firmware
//! pages into `PageTablePage` storage stays in the UEFI adapter.

use wyrmroot_efi_loader::transition::{MappingPermissions, TransitionMapping, TransitionPageTable};

pub const PAGE_BYTES: u64 = 4096;
const PAGE_TABLE_ENTRIES: usize = 512;
const PAGE_TABLE_LEVELS: usize = 4;
const MIN_PHYSICAL_ADDRESS_BITS: u8 = 36;
const MAX_PHYSICAL_ADDRESS_BITS: u8 = 52;
const CANONICAL_LOW_END: u64 = 0x0000_8000_0000_0000;
const CANONICAL_HIGH_START: u64 = 0xffff_8000_0000_0000;
const PRESENT: u64 = 1 << 0;
const WRITABLE: u64 = 1 << 1;
const EXECUTE_DISABLE: u64 = 1 << 63;

/// One page of 512 architectural x86_64 page-table entries.
pub type PageTablePage = [u64; PAGE_TABLE_ENTRIES];

/// Fail-closed encoder errors. A failed table must not be used for entry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UefiPageTableError {
    EmptyStorage,
    PhysicalAddressBitsInvalid,
    StoragePhysicalAddressInvalid,
    StorageNotZeroed,
    InvalidPageZeroGranule,
    PageZeroAlreadyMapped,
    PageZeroMappingForbidden,
    VirtualAddressNonCanonical,
    MappingSpansCanonicalHole,
    MappingUnaligned,
    MappingLengthInvalid,
    MappingRangeOverflow,
    PhysicalAddressInvalid,
    TableStorageExhausted,
    UnconsumedTablePages { used: usize, supplied: usize },
    DuplicateMapping,
    MappingConflict,
    CorruptIntermediateEntry,
}

/// A translation observable only for host validation and final handoff checks.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Translation {
    pub physical_address: u64,
    pub writable: bool,
    pub executable: bool,
}

/// A 4 KiB-only, four-level transition page table.
pub struct UefiPageTable<'storage> {
    physical_start: u64,
    physical_address_mask: u64,
    pages: &'storage mut [PageTablePage],
    next_free_page: usize,
    page_zero_guarded: bool,
}

impl<'storage> UefiPageTable<'storage> {
    /// Binds exact contiguous retained pages. Every entry must be zero before
    /// use, which prevents inherited firmware mappings or stale allocator data
    /// from becoming live page-table state.
    pub fn new(
        physical_start: u64,
        physical_address_bits: u8,
        pages: &'storage mut [PageTablePage],
    ) -> Result<Self, UefiPageTableError> {
        if pages.is_empty() {
            return Err(UefiPageTableError::EmptyStorage);
        }
        let Some(physical_address_mask) = physical_address_mask(physical_address_bits) else {
            return Err(UefiPageTableError::PhysicalAddressBitsInvalid);
        };
        if !valid_physical_page(physical_start, physical_address_mask) {
            return Err(UefiPageTableError::StoragePhysicalAddressInvalid);
        }
        if pages.iter().flatten().any(|entry| *entry != 0) {
            return Err(UefiPageTableError::StorageNotZeroed);
        }
        Ok(Self {
            physical_start,
            physical_address_mask,
            pages,
            next_free_page: 1,
            page_zero_guarded: false,
        })
    }

    /// Physical address for CR3. This is always the first supplied page.
    pub const fn cr3_root_physical(&self) -> u64 {
        self.physical_start
    }

    /// Exact number of supplied table pages consumed so far.
    pub const fn used_page_count(&self) -> usize {
        self.next_free_page
    }

    /// Ensures the supplied storage count exactly matches the populated
    /// hierarchy. The caller must run this after `populate_page_table`; an
    /// over-allocation means the pre-EBS count drifted from the reviewed plan.
    pub fn finish(&self) -> Result<u64, UefiPageTableError> {
        if self.next_free_page != self.pages.len() {
            return Err(UefiPageTableError::UnconsumedTablePages {
                used: self.next_free_page,
                supplied: self.pages.len(),
            });
        }
        Ok(self.cr3_root_physical())
    }

    /// Looks up a 4 KiB translation without exposing raw entries.
    pub fn translate(&self, virtual_address: u64) -> Option<Translation> {
        if !canonical_address(virtual_address) {
            return None;
        }
        let indexes = indexes_for(virtual_address);
        let mut page_index = 0;
        for index in indexes[..PAGE_TABLE_LEVELS - 1].iter().copied() {
            let entry = self.pages[page_index][index];
            if entry & PRESENT == 0 || entry & !self.table_allowed_bits() != 0 {
                return None;
            }
            page_index = self.page_index_for_physical(entry & self.physical_address_mask)?;
        }
        let entry = self.pages[page_index][indexes[PAGE_TABLE_LEVELS - 1]];
        if entry & PRESENT == 0 || entry & !self.leaf_allowed_bits() != 0 {
            return None;
        }
        Some(Translation {
            physical_address: (entry & self.physical_address_mask)
                | (virtual_address & (PAGE_BYTES - 1)),
            writable: entry & WRITABLE != 0,
            executable: entry & EXECUTE_DISABLE == 0,
        })
    }

    fn map_pages(
        &mut self,
        virtual_start: u64,
        physical_start: u64,
        byte_len: u64,
        permissions: MappingPermissions,
    ) -> Result<(), UefiPageTableError> {
        if !virtual_start.is_multiple_of(PAGE_BYTES) || !physical_start.is_multiple_of(PAGE_BYTES) {
            return Err(UefiPageTableError::MappingUnaligned);
        }
        if byte_len == 0 || !byte_len.is_multiple_of(PAGE_BYTES) {
            return Err(UefiPageTableError::MappingLengthInvalid);
        }
        let page_count = byte_len / PAGE_BYTES;
        let end = virtual_start
            .checked_add(byte_len - 1)
            .ok_or(UefiPageTableError::MappingRangeOverflow)?;
        if spans_canonical_hole(virtual_start, byte_len) {
            return Err(UefiPageTableError::MappingSpansCanonicalHole);
        }
        if !canonical_address(virtual_start) || !canonical_address(end) {
            return Err(UefiPageTableError::VirtualAddressNonCanonical);
        }
        let physical_end = physical_start
            .checked_add(byte_len - PAGE_BYTES)
            .ok_or(UefiPageTableError::PhysicalAddressInvalid)?;
        if !valid_physical_page(physical_start, self.physical_address_mask)
            || !valid_physical_page(physical_end, self.physical_address_mask)
        {
            return Err(UefiPageTableError::PhysicalAddressInvalid);
        }
        for page in 0..page_count {
            let virtual_address = virtual_start + page * PAGE_BYTES;
            if virtual_address == 0 {
                return Err(UefiPageTableError::PageZeroMappingForbidden);
            }
            self.map_page(
                virtual_address,
                physical_start + page * PAGE_BYTES,
                permissions,
            )?;
        }
        Ok(())
    }

    fn map_page(
        &mut self,
        virtual_address: u64,
        physical_address: u64,
        permissions: MappingPermissions,
    ) -> Result<(), UefiPageTableError> {
        let indexes = indexes_for(virtual_address);
        let mut page_index = 0;
        for index in indexes[..PAGE_TABLE_LEVELS - 1].iter().copied() {
            page_index = self.child_table(page_index, index)?;
        }
        let leaf = &mut self.pages[page_index][indexes[PAGE_TABLE_LEVELS - 1]];
        if *leaf != 0 {
            let expected = leaf_entry(physical_address, permissions);
            return Err(if *leaf == expected {
                UefiPageTableError::DuplicateMapping
            } else {
                UefiPageTableError::MappingConflict
            });
        }
        *leaf = leaf_entry(physical_address, permissions);
        Ok(())
    }

    fn child_table(
        &mut self,
        parent_page_index: usize,
        entry_index: usize,
    ) -> Result<usize, UefiPageTableError> {
        let entry = self.pages[parent_page_index][entry_index];
        if entry == 0 {
            let child_index = self.allocate_table_page()?;
            let child_physical = self.physical_for_index(child_index)?;
            self.pages[parent_page_index][entry_index] = child_physical | PRESENT | WRITABLE;
            return Ok(child_index);
        }
        if entry & PRESENT == 0 || entry & !self.table_allowed_bits() != 0 {
            return Err(UefiPageTableError::CorruptIntermediateEntry);
        }
        self.page_index_for_physical(entry & self.physical_address_mask)
            .ok_or(UefiPageTableError::CorruptIntermediateEntry)
    }

    fn allocate_table_page(&mut self) -> Result<usize, UefiPageTableError> {
        let page_index = self.next_free_page;
        if page_index >= self.pages.len() {
            return Err(UefiPageTableError::TableStorageExhausted);
        }
        self.next_free_page += 1;
        Ok(page_index)
    }

    fn physical_for_index(&self, page_index: usize) -> Result<u64, UefiPageTableError> {
        let offset = u64::try_from(page_index)
            .ok()
            .and_then(|index| index.checked_mul(PAGE_BYTES))
            .ok_or(UefiPageTableError::StoragePhysicalAddressInvalid)?;
        self.physical_start
            .checked_add(offset)
            .filter(|address| valid_physical_page(*address, self.physical_address_mask))
            .ok_or(UefiPageTableError::StoragePhysicalAddressInvalid)
    }

    fn page_index_for_physical(&self, physical_address: u64) -> Option<usize> {
        if !valid_physical_page(physical_address, self.physical_address_mask)
            || physical_address < self.physical_start
        {
            return None;
        }
        let offset = physical_address.checked_sub(self.physical_start)?;
        let index = usize::try_from(offset / PAGE_BYTES).ok()?;
        (index < self.next_free_page && index < self.pages.len()).then_some(index)
    }

    const fn leaf_allowed_bits(&self) -> u64 {
        self.physical_address_mask | PRESENT | WRITABLE | EXECUTE_DISABLE
    }

    const fn table_allowed_bits(&self) -> u64 {
        self.physical_address_mask | PRESENT | WRITABLE
    }
}

impl TransitionPageTable for UefiPageTable<'_> {
    type Error = UefiPageTableError;

    fn leave_page_zero_unmapped(&mut self, byte_len: u64) -> Result<(), Self::Error> {
        if byte_len != PAGE_BYTES {
            return Err(UefiPageTableError::InvalidPageZeroGranule);
        }
        if self.translate(0).is_some() || self.pages[0][0] != 0 {
            return Err(UefiPageTableError::PageZeroAlreadyMapped);
        }
        self.page_zero_guarded = true;
        Ok(())
    }

    fn map(&mut self, mapping: TransitionMapping) -> Result<(), Self::Error> {
        if !self.page_zero_guarded {
            return Err(UefiPageTableError::PageZeroMappingForbidden);
        }
        self.map_pages(
            mapping.virtual_start,
            mapping.physical_start,
            mapping.byte_len,
            mapping.permissions,
        )
    }
}

fn leaf_entry(physical_address: u64, permissions: MappingPermissions) -> u64 {
    let mut entry = physical_address | PRESENT;
    if permissions.writable {
        entry |= WRITABLE;
    }
    if !permissions.executable {
        entry |= EXECUTE_DISABLE;
    }
    entry
}

fn valid_physical_page(address: u64, address_mask: u64) -> bool {
    address != 0 && address & !address_mask == 0
}

fn canonical_address(address: u64) -> bool {
    let high = address >> 48;
    high == 0 || high == 0xffff
}

fn spans_canonical_hole(virtual_start: u64, byte_len: u64) -> bool {
    let Some(virtual_end_exclusive) = virtual_start.checked_add(byte_len) else {
        return false;
    };
    virtual_start < CANONICAL_LOW_END && virtual_end_exclusive > CANONICAL_LOW_END
        || (virtual_start < CANONICAL_HIGH_START && virtual_end_exclusive > CANONICAL_HIGH_START)
}

fn physical_address_mask(physical_address_bits: u8) -> Option<u64> {
    if !(MIN_PHYSICAL_ADDRESS_BITS..=MAX_PHYSICAL_ADDRESS_BITS).contains(&physical_address_bits) {
        return None;
    }
    Some(((1_u64 << physical_address_bits) - 1) & !(PAGE_BYTES - 1))
}

fn indexes_for(virtual_address: u64) -> [usize; PAGE_TABLE_LEVELS] {
    [
        ((virtual_address >> 39) & 0x1ff) as usize,
        ((virtual_address >> 30) & 0x1ff) as usize,
        ((virtual_address >> 21) & 0x1ff) as usize,
        ((virtual_address >> 12) & 0x1ff) as usize,
    ]
}
