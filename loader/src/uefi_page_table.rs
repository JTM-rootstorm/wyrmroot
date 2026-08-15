//! Four-level x86_64 transition page-table encoder over retained UEFI pages.
//!
//! The caller supplies a contiguous, pre-zeroed `LoaderData` allocation. This
//! encoder never allocates, never reaches outside that allocation, and maps
//! only 4 KiB supervisor pages. The unsafe conversion from retained firmware
//! pages into `PageTablePage` storage stays in the UEFI adapter.

use deepwyrm_abi::{
    DW_BOOT_X86_64_PAGING_HANDOFF_FLAGS_SUPPORTED_MASK,
    DW_BOOT_X86_64_PAGING_HANDOFF_LAYOUT_VERSION, DW_BOOT_X86_64_PAGING_HANDOFF_MAX_BYTE_LEN,
    DW_BOOT_X86_64_PAGING_HANDOFF_MAX_PHYSICAL_ADDRESS_WIDTH,
    DW_BOOT_X86_64_PAGING_HANDOFF_MAX_TABLE_FRAME_COUNT,
    DW_BOOT_X86_64_PAGING_HANDOFF_MIN_PHYSICAL_ADDRESS_WIDTH,
    DW_BOOT_X86_64_PAGING_HANDOFF_MIN_TABLE_FRAME_COUNT,
    DW_BOOT_X86_64_PAGING_HANDOFF_TABLE_FRAME_STRIDE,
    DW_BOOT_X86_64_PAGING_HANDOFF_TABLE_FRAMES_OFFSET, DW_BOOT_X86_64_PAGING_HANDOFF_V1_SIZE,
    DW_BOOT_X86_64_PAGING_HANDOFF_V1_VERSION, DwBootX86_64PagingHandoffV1,
};
use wyrmroot_efi_loader::transition::{
    MappingPermissions, TemporaryMappingReservation, TransitionMapping, TransitionPageTable,
    TransitionPlan,
};

pub const PAGE_BYTES: u64 = 4096;
const PAGE_TABLE_ENTRIES: usize = 512;
const PAGE_TABLE_LEVELS: usize = 4;
const MIN_PHYSICAL_ADDRESS_BITS: u8 =
    DW_BOOT_X86_64_PAGING_HANDOFF_MIN_PHYSICAL_ADDRESS_WIDTH as u8;
const MAX_PHYSICAL_ADDRESS_BITS: u8 =
    DW_BOOT_X86_64_PAGING_HANDOFF_MAX_PHYSICAL_ADDRESS_WIDTH as u8;
const CANONICAL_LOW_END: u64 = 0x0000_8000_0000_0000;
const CANONICAL_HIGH_START: u64 = 0xffff_8000_0000_0000;
const PRESENT: u64 = 1 << 0;
const WRITABLE: u64 = 1 << 1;
const EXECUTE_DISABLE: u64 = 1 << 63;
const MAX_TABLE_FRAMES: usize = DW_BOOT_X86_64_PAGING_HANDOFF_MAX_TABLE_FRAME_COUNT as usize;

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
    DuplicateMapping,
    MappingConflict,
    CorruptIntermediateEntry,
    CapacityLengthMismatch,
    TemporaryMappingAlreadyReserved,
    TemporaryMappingInvalid,
    TemporaryMappingConflict,
    TemporaryLeafNotZero,
    UsedPageCountMismatch { expected: usize, observed: usize },
    ReachableUnusedCapacity,
    SharedOrCyclicTable,
    UnreachableUsedTable,
    UnexpectedLeaf,
    MissingLeaf,
    LeafPlanMismatch,
    NonPresentEntryNotZero,
    IntermediateEntryFlagsInvalid,
    UnusedCapacityDirty,
    CarrierFrameCountMismatch,
    CarrierExtentInvalid,
}

/// A translation observable only for host validation and final handoff checks.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Translation {
    pub physical_address: u64,
    pub writable: bool,
    pub executable: bool,
}

/// Immutable evidence produced after consuming the only mutable encoder.
pub struct PageTableAttestation<'storage, 'plan, 'data> {
    _pages: &'storage [PageTablePage],
    _plan: &'plan TransitionPlan<'data>,
    root_physical: u64,
    used_page_count: u32,
    physical_address_width: u32,
    temporary_path_frames: [u64; 4],
}

impl<'storage, 'plan, 'data> PageTableAttestation<'storage, 'plan, 'data> {
    pub const fn root_physical(&self) -> u64 {
        self.root_physical
    }

    pub const fn used_page_count(&self) -> u32 {
        self.used_page_count
    }

    pub const fn physical_address_width(&self) -> u32 {
        self.physical_address_width
    }

    pub const fn temporary_path_frames(&self) -> [u64; 4] {
        self.temporary_path_frames
    }

    pub fn table_frame_physical(&self, index: u32) -> Option<u64> {
        (index < self.used_page_count).then(|| self.root_physical + u64::from(index) * PAGE_BYTES)
    }

    /// Exact ABI carrier extent: generated fixed header followed by the used
    /// transition-table frame list, never the unused allocation tail.
    pub fn carrier_byte_len(&self) -> Result<u32, UefiPageTableError> {
        let frames = self
            .used_page_count
            .checked_mul(DW_BOOT_X86_64_PAGING_HANDOFF_TABLE_FRAME_STRIDE)
            .ok_or(UefiPageTableError::CarrierExtentInvalid)?;
        let total = DW_BOOT_X86_64_PAGING_HANDOFF_TABLE_FRAMES_OFFSET
            .checked_add(frames)
            .ok_or(UefiPageTableError::CarrierExtentInvalid)?;
        if total > DW_BOOT_X86_64_PAGING_HANDOFF_MAX_BYTE_LEN {
            return Err(UefiPageTableError::CarrierExtentInvalid);
        }
        Ok(total)
    }

    /// Serialize the generated header and exact sorted frame list into two
    /// disjoint views of one page-backed carrier allocation.
    pub fn write_carrier(
        &self,
        header: &mut DwBootX86_64PagingHandoffV1,
        frames: &mut [u64],
    ) -> Result<u32, UefiPageTableError> {
        if frames.len() != self.used_page_count as usize {
            return Err(UefiPageTableError::CarrierFrameCountMismatch);
        }
        let total_byte_len = self.carrier_byte_len()?;
        let temporary = self.temporary_path_frames;
        *header = DwBootX86_64PagingHandoffV1 {
            size: DW_BOOT_X86_64_PAGING_HANDOFF_V1_SIZE,
            version: DW_BOOT_X86_64_PAGING_HANDOFF_V1_VERSION,
            flags: DW_BOOT_X86_64_PAGING_HANDOFF_FLAGS_SUPPORTED_MASK,
            physical_address_width: self.physical_address_width,
            cr3_root_physical: self.root_physical,
            table_frames_offset: DW_BOOT_X86_64_PAGING_HANDOFF_TABLE_FRAMES_OFFSET,
            table_frame_count: self.used_page_count,
            table_frame_stride: DW_BOOT_X86_64_PAGING_HANDOFF_TABLE_FRAME_STRIDE,
            total_byte_len,
            paging_layout_version: DW_BOOT_X86_64_PAGING_HANDOFF_LAYOUT_VERSION,
            reserved0: 0,
            temporary_virtual_address:
                deepwyrm_abi::DW_BOOT_X86_64_PAGING_HANDOFF_TEMPORARY_VIRTUAL_ADDRESS,
            pml4_index: deepwyrm_abi::DW_BOOT_X86_64_PAGING_HANDOFF_PML4_INDEX,
            pdpt_index: deepwyrm_abi::DW_BOOT_X86_64_PAGING_HANDOFF_PDPT_INDEX,
            pd_index: deepwyrm_abi::DW_BOOT_X86_64_PAGING_HANDOFF_PD_INDEX,
            pt_index: deepwyrm_abi::DW_BOOT_X86_64_PAGING_HANDOFF_PT_INDEX,
            temporary_pdpt_frame_physical: temporary[1],
            temporary_pd_frame_physical: temporary[2],
            temporary_pt_frame_physical: temporary[3],
            reserved: [0; 3],
        };
        for (index, frame) in frames.iter_mut().enumerate() {
            *frame = self
                .table_frame_physical(index as u32)
                .ok_or(UefiPageTableError::CarrierFrameCountMismatch)?;
        }
        Ok(total_byte_len)
    }

    #[cfg(not(test))]
    pub(crate) fn into_handoff_parts(
        self,
    ) -> (
        &'storage [PageTablePage],
        &'plan TransitionPlan<'data>,
        u64,
        u32,
    ) {
        (
            self._pages,
            self._plan,
            self.root_physical,
            self.used_page_count,
        )
    }
}

/// A 4 KiB-only, four-level transition page table.
pub struct UefiPageTable<'storage> {
    physical_start: u64,
    physical_address_bits: u8,
    physical_address_mask: u64,
    pages: &'storage mut [PageTablePage],
    next_free_page: usize,
    page_zero_guarded: bool,
    temporary: Option<TemporaryPath>,
}

#[derive(Clone, Copy)]
struct TemporaryPath {
    reservation: TemporaryMappingReservation,
    page_indices: [usize; 4],
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
        if pages.len() != MAX_TABLE_FRAMES {
            return Err(UefiPageTableError::CapacityLengthMismatch);
        }
        let Some(physical_address_mask) = physical_address_mask(physical_address_bits) else {
            return Err(UefiPageTableError::PhysicalAddressBitsInvalid);
        };
        let storage_last = u64::try_from(pages.len() - 1)
            .ok()
            .and_then(|index| index.checked_mul(PAGE_BYTES))
            .and_then(|offset| physical_start.checked_add(offset));
        if !valid_physical_page(physical_start, physical_address_mask)
            || !storage_last
                .is_some_and(|address| valid_physical_page(address, physical_address_mask))
        {
            return Err(UefiPageTableError::StoragePhysicalAddressInvalid);
        }
        if pages.iter().flatten().any(|entry| *entry != 0) {
            return Err(UefiPageTableError::StorageNotZeroed);
        }
        Ok(Self {
            physical_start,
            physical_address_bits,
            physical_address_mask,
            pages,
            next_free_page: 1,
            page_zero_guarded: false,
            temporary: None,
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

    /// Consume the encoder and return immutable evidence bound to the exact plan.
    pub fn attest<'plan, 'data>(
        self,
        plan: &'plan TransitionPlan<'data>,
    ) -> Result<PageTableAttestation<'storage, 'plan, 'data>, UefiPageTableError> {
        if self.physical_start != plan.pre_exit().page_table_storage.physical_start {
            return Err(UefiPageTableError::StoragePhysicalAddressInvalid);
        }
        let (used_page_count, temporary_path_frames) = self.validate_graph(plan)?;
        Ok(PageTableAttestation {
            _pages: self.pages,
            _plan: plan,
            root_physical: self.physical_start,
            used_page_count,
            physical_address_width: u32::from(self.physical_address_bits),
            temporary_path_frames,
        })
    }

    fn validate_graph(
        &self,
        plan: &TransitionPlan<'_>,
    ) -> Result<(u32, [u64; 4]), UefiPageTableError> {
        let expected_used = usize::try_from(plan.used_page_table_page_count()).map_err(|_| {
            UefiPageTableError::UsedPageCountMismatch {
                expected: MAX_TABLE_FRAMES,
                observed: self.next_free_page,
            }
        })?;
        if expected_used != self.next_free_page {
            return Err(UefiPageTableError::UsedPageCountMismatch {
                expected: expected_used,
                observed: self.next_free_page,
            });
        }
        if expected_used < DW_BOOT_X86_64_PAGING_HANDOFF_MIN_TABLE_FRAME_COUNT as usize
            || expected_used > MAX_TABLE_FRAMES
        {
            return Err(UefiPageTableError::UsedPageCountMismatch {
                expected: DW_BOOT_X86_64_PAGING_HANDOFF_MIN_TABLE_FRAME_COUNT as usize,
                observed: expected_used,
            });
        }
        let temporary = self
            .temporary
            .ok_or(UefiPageTableError::TemporaryMappingInvalid)?;
        if temporary.reservation != plan.temporary_mapping() {
            return Err(UefiPageTableError::TemporaryMappingInvalid);
        }
        self.validate_temporary_path(temporary)?;
        if self.pages[expected_used..]
            .iter()
            .flatten()
            .any(|entry| *entry != 0)
        {
            return Err(UefiPageTableError::UnusedCapacityDirty);
        }

        let mut visited = [false; MAX_TABLE_FRAMES];
        let mut stack_indices = [0usize; MAX_TABLE_FRAMES];
        let mut stack_levels = [0u8; MAX_TABLE_FRAMES];
        let mut stack_prefixes = [0u64; MAX_TABLE_FRAMES];
        let mut stack_len = 1usize;
        stack_indices[0] = 0;
        stack_levels[0] = PAGE_TABLE_LEVELS as u8;
        visited[0] = true;
        let mut visited_count = 0usize;
        let mut observed_leaves = 0u64;
        while stack_len != 0 {
            stack_len -= 1;
            let page_index = stack_indices[stack_len];
            let level = stack_levels[stack_len];
            let prefix = stack_prefixes[stack_len];
            visited_count += 1;
            for (entry_index, entry) in self.pages[page_index].iter().copied().enumerate() {
                if entry == 0 {
                    continue;
                }
                if entry & PRESENT == 0 {
                    return Err(UefiPageTableError::NonPresentEntryNotZero);
                }
                let shift = 12 + 9 * (u64::from(level) - 1);
                let child_prefix = prefix | ((entry_index as u64) << shift);
                if level > 1 {
                    if entry & !self.table_allowed_bits() != 0 || entry & WRITABLE == 0 {
                        return Err(UefiPageTableError::IntermediateEntryFlagsInvalid);
                    }
                    let child_physical = entry & self.physical_address_mask;
                    let child = self
                        .page_index_for_capacity_physical(child_physical)
                        .ok_or(UefiPageTableError::CorruptIntermediateEntry)?;
                    if child >= expected_used {
                        return Err(UefiPageTableError::ReachableUnusedCapacity);
                    }
                    if visited[child] {
                        return Err(UefiPageTableError::SharedOrCyclicTable);
                    }
                    visited[child] = true;
                    if stack_len >= MAX_TABLE_FRAMES {
                        return Err(UefiPageTableError::SharedOrCyclicTable);
                    }
                    stack_indices[stack_len] = child;
                    stack_levels[stack_len] = level - 1;
                    stack_prefixes[stack_len] = child_prefix;
                    stack_len += 1;
                } else {
                    observed_leaves = observed_leaves
                        .checked_add(1)
                        .ok_or(UefiPageTableError::MissingLeaf)?;
                    let virtual_address = canonicalize_48_bit(child_prefix);
                    let expected = expected_leaf(plan, virtual_address)
                        .ok_or(UefiPageTableError::UnexpectedLeaf)?;
                    if entry != expected {
                        return Err(UefiPageTableError::LeafPlanMismatch);
                    }
                }
            }
        }
        if visited_count != expected_used || visited[..expected_used].iter().any(|seen| !seen) {
            return Err(UefiPageTableError::UnreachableUsedTable);
        }
        let expected_leaves = expected_leaf_count(plan)?;
        if observed_leaves != expected_leaves {
            return Err(UefiPageTableError::MissingLeaf);
        }
        let temporary_path_frames = temporary.page_indices.map(|index| {
            self.physical_for_index(index)
                .expect("validated temporary path frame")
        });
        Ok((
            u32::try_from(expected_used).expect("generated maximum fits u32"),
            temporary_path_frames,
        ))
    }

    fn validate_temporary_path(&self, path: TemporaryPath) -> Result<(), UefiPageTableError> {
        let indexes = path.reservation.indices.map(usize::from);
        if indexes_for(path.reservation.virtual_address) != indexes {
            return Err(UefiPageTableError::TemporaryMappingInvalid);
        }
        let mut page_index = path.page_indices[0];
        if page_index != 0 {
            return Err(UefiPageTableError::TemporaryMappingInvalid);
        }
        for (depth, index) in indexes
            .iter()
            .copied()
            .enumerate()
            .take(PAGE_TABLE_LEVELS - 1)
        {
            let entry = self.pages[page_index][index];
            if entry & !self.table_allowed_bits() != 0
                || entry & (PRESENT | WRITABLE) != PRESENT | WRITABLE
            {
                return Err(UefiPageTableError::IntermediateEntryFlagsInvalid);
            }
            let child = self
                .page_index_for_capacity_physical(entry & self.physical_address_mask)
                .ok_or(UefiPageTableError::TemporaryMappingInvalid)?;
            if child != path.page_indices[depth + 1] {
                return Err(UefiPageTableError::TemporaryMappingInvalid);
            }
            page_index = child;
        }
        if self.pages[page_index][indexes[PAGE_TABLE_LEVELS - 1]] != 0 {
            return Err(UefiPageTableError::TemporaryLeafNotZero);
        }
        Ok(())
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

    #[cfg(test)]
    pub fn raw_entry_mut_for_test(
        &mut self,
        page_index: usize,
        entry_index: usize,
    ) -> Option<&mut u64> {
        self.pages
            .get_mut(page_index)
            .and_then(|page| page.get_mut(entry_index))
    }

    #[cfg(test)]
    pub fn raw_entry_for_test(&self, page_index: usize, entry_index: usize) -> Option<u64> {
        self.pages
            .get(page_index)
            .and_then(|page| page.get(entry_index))
            .copied()
    }

    #[cfg(test)]
    pub fn temporary_page_indices_for_test(&self) -> Option<[usize; 4]> {
        self.temporary.map(|path| path.page_indices)
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
        if self.temporary.is_some_and(|temporary| {
            let slot_len = 1_u64 << 39;
            let slot_start = temporary.reservation.virtual_address & !(slot_len - 1);
            let slot_end = slot_start + slot_len;
            virtual_start < slot_end && slot_start <= end
        }) {
            return Err(UefiPageTableError::TemporaryMappingConflict);
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
        let index = self.page_index_for_capacity_physical(physical_address)?;
        (index < self.next_free_page).then_some(index)
    }

    fn page_index_for_capacity_physical(&self, physical_address: u64) -> Option<usize> {
        if !valid_physical_page(physical_address, self.physical_address_mask)
            || physical_address < self.physical_start
        {
            return None;
        }
        let offset = physical_address.checked_sub(self.physical_start)?;
        let index = usize::try_from(offset / PAGE_BYTES).ok()?;
        (index < self.pages.len()).then_some(index)
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

    fn reserve_temporary_mapping(
        &mut self,
        reservation: TemporaryMappingReservation,
    ) -> Result<(), Self::Error> {
        if self.temporary.is_some() {
            return Err(UefiPageTableError::TemporaryMappingAlreadyReserved);
        }
        if !self.page_zero_guarded
            || !canonical_address(reservation.virtual_address)
            || !reservation.virtual_address.is_multiple_of(PAGE_BYTES)
            || indexes_for(reservation.virtual_address) != reservation.indices.map(usize::from)
        {
            return Err(UefiPageTableError::TemporaryMappingInvalid);
        }
        let indexes = reservation.indices.map(usize::from);
        if self.pages[0][indexes[0]] != 0 {
            return Err(UefiPageTableError::TemporaryMappingConflict);
        }
        let mut page_indices = [0usize; PAGE_TABLE_LEVELS];
        let mut page_index = 0usize;
        for depth in 0..PAGE_TABLE_LEVELS - 1 {
            page_index = self.child_table(page_index, indexes[depth])?;
            page_indices[depth + 1] = page_index;
        }
        if self.pages[page_index][indexes[PAGE_TABLE_LEVELS - 1]] != 0 {
            return Err(UefiPageTableError::TemporaryLeafNotZero);
        }
        self.temporary = Some(TemporaryPath {
            reservation,
            page_indices,
        });
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

fn expected_leaf(plan: &TransitionPlan<'_>, virtual_address: u64) -> Option<u64> {
    for mapping in plan
        .mappings()
        .iter()
        .copied()
        .chain(core::iter::once(plan.table_identity_mapping()))
    {
        let end = mapping.virtual_start.checked_add(mapping.byte_len)?;
        if mapping.virtual_start <= virtual_address && virtual_address < end {
            let offset = virtual_address.checked_sub(mapping.virtual_start)?;
            let physical = mapping.physical_start.checked_add(offset)?;
            return Some(leaf_entry(physical, mapping.permissions));
        }
    }
    None
}

fn expected_leaf_count(plan: &TransitionPlan<'_>) -> Result<u64, UefiPageTableError> {
    plan.mappings()
        .iter()
        .copied()
        .chain(core::iter::once(plan.table_identity_mapping()))
        .try_fold(0u64, |count, mapping| {
            count
                .checked_add(mapping.byte_len / plan.mapping_granule())
                .ok_or(UefiPageTableError::MissingLeaf)
        })
}

const fn canonicalize_48_bit(address: u64) -> u64 {
    if address & (1 << 47) != 0 {
        address | 0xffff_0000_0000_0000
    } else {
        address
    }
}

fn valid_physical_page(address: u64, address_mask: u64) -> bool {
    address != 0 && address & !address_mask == 0
}

fn canonical_address(address: u64) -> bool {
    // In four-level mode bits 63:48 must sign-extend bit 47. Checking only
    // the high 16 bits would wrongly admit the upper half of the low 48-bit
    // range (for example 0x0000_8000_0000_0000), whose bit 47 is set but
    // whose sign-extension bits are clear.
    !(CANONICAL_LOW_END..CANONICAL_HIGH_START).contains(&address)
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
