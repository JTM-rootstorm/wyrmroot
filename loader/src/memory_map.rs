//! Allocation-free normalization of the final firmware memory map.
//!
//! The UEFI adapter translates firmware-specific memory-type numbers into
//! [`boot_info::UefiMemoryKind`] before calling this module. An unknown value
//! remains `None` and is rejected here rather than being guessed at. Output
//! uses canonical representatives for categories with identical BootInfo
//! meaning, allowing a caller-provided generated-record buffer to hold a
//! coalesced map.

use deepwyrm_abi::{
    DW_BOOT_BASE_PAGE_SIZE, DW_BOOT_MEMORY_KIND_ACPI_NVS, DW_BOOT_MEMORY_KIND_ACPI_RECLAIM,
    DW_BOOT_MEMORY_KIND_MMIO, DW_BOOT_MEMORY_KIND_RESERVED, DW_BOOT_MEMORY_KIND_RUNTIME_SERVICES,
    DW_BOOT_MEMORY_KIND_UNUSABLE, DW_BOOT_MEMORY_KIND_USABLE, DW_BOOT_MEMORY_RANGE_V1_SIZE,
    DW_BOOT_MEMORY_RANGE_V1_VERSION, DwBootMemoryKind, DwBootMemoryRangeV1,
};

use crate::boot_info::UefiMemoryKind;

/// One already-translated, post-`ExitBootServices` firmware memory descriptor.
///
/// The adapter owns conversion from UEFI's numeric memory-type namespace. It
/// must use `None` for a type with no approved mapping so this boundary fails
/// closed without importing UEFI types.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FirmwareMemoryDescriptor {
    pub kind: Option<UefiMemoryKind>,
    pub physical_start: u64,
    pub page_count: u64,
    pub firmware_attributes: u64,
}

/// Failure while validating or coalescing a firmware memory map.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MemoryMapError {
    UnknownMemoryKind,
    EmptyRange,
    PhysicalAddressUnaligned,
    RangeOverflow,
    UnsortedInput,
    OverlappingInput,
    OutputExhausted,
}

/// Validates and coalesces an already-sorted firmware memory map.
///
/// Adjacent descriptors merge only when their canonical normalized kind and
/// firmware attributes are equal. The function performs no allocation and can
/// consume an adapter's streaming raw descriptors when they coalesce into `output`.
/// On error, callers must discard any partially written output.
pub fn normalize_and_coalesce<I>(
    input: I,
    output: &mut [DwBootMemoryRangeV1],
) -> Result<&[DwBootMemoryRangeV1], MemoryMapError>
where
    I: IntoIterator<Item = FirmwareMemoryDescriptor>,
{
    let page_size = u64::from(DW_BOOT_BASE_PAGE_SIZE);
    let mut output_len = 0_usize;
    let mut previous_input_start = None;
    let mut previous_input_end = None;

    for descriptor in input {
        let kind = descriptor
            .kind
            .map(normalize_kind)
            .ok_or(MemoryMapError::UnknownMemoryKind)?;
        let end = checked_end(descriptor.physical_start, descriptor.page_count, page_size)?;

        if let (Some(previous_start), Some(previous_end)) =
            (previous_input_start, previous_input_end)
        {
            if descriptor.physical_start < previous_start {
                return Err(MemoryMapError::UnsortedInput);
            }
            if descriptor.physical_start < previous_end {
                return Err(MemoryMapError::OverlappingInput);
            }
        }
        previous_input_start = Some(descriptor.physical_start);
        previous_input_end = Some(end);

        let can_merge = match output[..output_len].last() {
            Some(previous) => {
                previous.kind == kind
                    && previous.firmware_attributes == descriptor.firmware_attributes
                    && page_range_end(previous.physical_start, previous.page_count, page_size)?
                        == descriptor.physical_start
            }
            None => false,
        };
        if can_merge {
            let previous = &mut output[output_len - 1];
            previous.page_count = previous
                .page_count
                .checked_add(descriptor.page_count)
                .ok_or(MemoryMapError::RangeOverflow)?;
            continue;
        }

        let slot = output
            .get_mut(output_len)
            .ok_or(MemoryMapError::OutputExhausted)?;
        *slot = DwBootMemoryRangeV1 {
            size: DW_BOOT_MEMORY_RANGE_V1_SIZE,
            version: DW_BOOT_MEMORY_RANGE_V1_VERSION,
            kind,
            reserved0: 0,
            physical_start: descriptor.physical_start,
            page_count: descriptor.page_count,
            firmware_attributes: descriptor.firmware_attributes,
            reserved: [0; 3],
        };
        output_len = output_len
            .checked_add(1)
            .ok_or(MemoryMapError::OutputExhausted)?;
    }

    Ok(&output[..output_len])
}

fn normalize_kind(kind: UefiMemoryKind) -> DwBootMemoryKind {
    match kind {
        UefiMemoryKind::Conventional | UefiMemoryKind::BootServices => DW_BOOT_MEMORY_KIND_USABLE,
        UefiMemoryKind::Loader | UefiMemoryKind::Reserved => DW_BOOT_MEMORY_KIND_RESERVED,
        UefiMemoryKind::AcpiReclaim => DW_BOOT_MEMORY_KIND_ACPI_RECLAIM,
        UefiMemoryKind::AcpiNvs => DW_BOOT_MEMORY_KIND_ACPI_NVS,
        UefiMemoryKind::Mmio => DW_BOOT_MEMORY_KIND_MMIO,
        UefiMemoryKind::RuntimeServices => DW_BOOT_MEMORY_KIND_RUNTIME_SERVICES,
        UefiMemoryKind::Unusable => DW_BOOT_MEMORY_KIND_UNUSABLE,
    }
}

fn checked_end(
    physical_start: u64,
    page_count: u64,
    page_size: u64,
) -> Result<u64, MemoryMapError> {
    if page_count == 0 {
        return Err(MemoryMapError::EmptyRange);
    }
    if !physical_start.is_multiple_of(page_size) {
        return Err(MemoryMapError::PhysicalAddressUnaligned);
    }
    page_range_end(physical_start, page_count, page_size)
}

fn page_range_end(
    physical_start: u64,
    page_count: u64,
    page_size: u64,
) -> Result<u64, MemoryMapError> {
    let byte_len = page_count
        .checked_mul(page_size)
        .ok_or(MemoryMapError::RangeOverflow)?;
    physical_start
        .checked_add(byte_len)
        .ok_or(MemoryMapError::RangeOverflow)
}
