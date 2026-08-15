#[path = "../src/boot_info.rs"]
#[allow(dead_code)] // Imported only for the shared descriptor type before crate export integration.
mod boot_info;
#[path = "../src/memory_map.rs"]
mod memory_map;

use boot_info::UefiMemoryKind;
use deepwyrm_abi::{
    DW_BOOT_BASE_PAGE_SIZE, DW_BOOT_MEMORY_KIND_ACPI_NVS, DW_BOOT_MEMORY_KIND_ACPI_RECLAIM,
    DW_BOOT_MEMORY_KIND_MMIO, DW_BOOT_MEMORY_KIND_RESERVED, DW_BOOT_MEMORY_KIND_RUNTIME_SERVICES,
    DW_BOOT_MEMORY_KIND_UNUSABLE, DW_BOOT_MEMORY_KIND_USABLE, DwBootMemoryRangeV1,
};
use memory_map::{FirmwareMemoryDescriptor, MemoryMapError, normalize_and_coalesce};

const PAGE_SIZE: u64 = DW_BOOT_BASE_PAGE_SIZE as u64;

fn descriptor(
    kind: Option<UefiMemoryKind>,
    physical_start: u64,
    page_count: u64,
    firmware_attributes: u64,
) -> FirmwareMemoryDescriptor {
    FirmwareMemoryDescriptor {
        kind,
        physical_start,
        page_count,
        firmware_attributes,
    }
}

#[test]
fn coalesces_normalized_kinds_without_a_raw_descriptor_limit() {
    let input = (1_u64..=129).map(|page| {
        let kind = if page.is_multiple_of(2) {
            UefiMemoryKind::BootServices
        } else {
            UefiMemoryKind::Conventional
        };
        descriptor(Some(kind), PAGE_SIZE * page, 1, 0x10)
    });
    let mut output = [default_descriptor(); 1];

    let normalized = normalize_and_coalesce(input, &mut output).unwrap();

    assert_eq!(normalized.len(), 1);
    assert_eq!(normalized[0].kind, DW_BOOT_MEMORY_KIND_USABLE);
    assert_eq!(normalized[0].physical_start, PAGE_SIZE);
    assert_eq!(normalized[0].page_count, 129);
    assert_eq!(normalized[0].firmware_attributes, 0x10);
}

#[test]
fn normalizes_every_translated_firmware_memory_kind() {
    let input = [
        descriptor(Some(UefiMemoryKind::Loader), PAGE_SIZE, 1, 0),
        descriptor(Some(UefiMemoryKind::Conventional), PAGE_SIZE * 2, 1, 1),
        descriptor(Some(UefiMemoryKind::BootServices), PAGE_SIZE * 3, 1, 2),
        descriptor(Some(UefiMemoryKind::Reserved), PAGE_SIZE * 4, 1, 3),
        descriptor(Some(UefiMemoryKind::AcpiReclaim), PAGE_SIZE * 5, 1, 4),
        descriptor(Some(UefiMemoryKind::AcpiNvs), PAGE_SIZE * 6, 1, 5),
        descriptor(Some(UefiMemoryKind::Mmio), PAGE_SIZE * 7, 1, 6),
        descriptor(Some(UefiMemoryKind::RuntimeServices), PAGE_SIZE * 8, 1, 7),
        descriptor(Some(UefiMemoryKind::Unusable), PAGE_SIZE * 9, 1, 8),
    ];
    let mut output = [default_descriptor(); 9];

    let normalized = normalize_and_coalesce(input, &mut output).unwrap();

    assert_eq!(normalized.len(), 9);
    assert_eq!(normalized[0].kind, DW_BOOT_MEMORY_KIND_RESERVED);
    assert_eq!(normalized[1].kind, DW_BOOT_MEMORY_KIND_USABLE);
    assert_eq!(normalized[2].kind, DW_BOOT_MEMORY_KIND_USABLE);
    assert_eq!(normalized[3].kind, DW_BOOT_MEMORY_KIND_RESERVED);
    assert_eq!(normalized[4].kind, DW_BOOT_MEMORY_KIND_ACPI_RECLAIM);
    assert_eq!(normalized[5].kind, DW_BOOT_MEMORY_KIND_ACPI_NVS);
    assert_eq!(normalized[6].kind, DW_BOOT_MEMORY_KIND_MMIO);
    assert_eq!(normalized[7].kind, DW_BOOT_MEMORY_KIND_RUNTIME_SERVICES);
    assert_eq!(normalized[8].kind, DW_BOOT_MEMORY_KIND_UNUSABLE);
}

#[test]
fn does_not_merge_across_kind_or_attribute_boundaries() {
    let input = [
        descriptor(Some(UefiMemoryKind::Loader), PAGE_SIZE, 1, 0x10),
        descriptor(Some(UefiMemoryKind::Reserved), PAGE_SIZE * 2, 1, 0x20),
        descriptor(Some(UefiMemoryKind::Mmio), PAGE_SIZE * 3, 1, 0x20),
    ];
    let mut output = [default_descriptor(); 3];

    let normalized = normalize_and_coalesce(input, &mut output).unwrap();

    assert_eq!(normalized.len(), 3);
    assert_eq!(normalized[0].kind, DW_BOOT_MEMORY_KIND_RESERVED);
    assert_eq!(normalized[1].kind, DW_BOOT_MEMORY_KIND_RESERVED);
    assert_eq!(normalized[1].firmware_attributes, 0x20);
    assert_eq!(normalized[2].kind, DW_BOOT_MEMORY_KIND_MMIO);
}

#[test]
fn rejects_output_exhaustion_after_coalescing() {
    let input = [
        descriptor(Some(UefiMemoryKind::Conventional), PAGE_SIZE, 1, 0),
        descriptor(Some(UefiMemoryKind::Mmio), PAGE_SIZE * 2, 1, 0),
    ];
    let mut output = [default_descriptor(); 1];

    assert_eq!(
        normalize_and_coalesce(input, &mut output),
        Err(MemoryMapError::OutputExhausted)
    );
}

#[test]
fn rejects_unknown_zero_unaligned_unsorted_overlapping_and_wrapping_input() {
    let mut output = [default_descriptor(); 2];
    assert_eq!(
        normalize_and_coalesce([descriptor(None, PAGE_SIZE, 1, 0)], &mut output),
        Err(MemoryMapError::UnknownMemoryKind)
    );
    assert_eq!(
        normalize_and_coalesce(
            [descriptor(
                Some(UefiMemoryKind::Conventional),
                PAGE_SIZE,
                0,
                0
            )],
            &mut output
        ),
        Err(MemoryMapError::EmptyRange)
    );
    assert_eq!(
        normalize_and_coalesce(
            [descriptor(
                Some(UefiMemoryKind::Conventional),
                PAGE_SIZE + 1,
                1,
                0
            )],
            &mut output
        ),
        Err(MemoryMapError::PhysicalAddressUnaligned)
    );
    assert_eq!(
        normalize_and_coalesce(
            [
                descriptor(Some(UefiMemoryKind::Conventional), PAGE_SIZE * 3, 1, 0),
                descriptor(Some(UefiMemoryKind::Conventional), PAGE_SIZE, 1, 0),
            ],
            &mut output
        ),
        Err(MemoryMapError::UnsortedInput)
    );
    assert_eq!(
        normalize_and_coalesce(
            [
                descriptor(Some(UefiMemoryKind::Conventional), PAGE_SIZE, 2, 0),
                descriptor(Some(UefiMemoryKind::Conventional), PAGE_SIZE * 2, 1, 0),
            ],
            &mut output
        ),
        Err(MemoryMapError::OverlappingInput)
    );
    let highest_page = u64::MAX / PAGE_SIZE * PAGE_SIZE;
    assert_eq!(
        normalize_and_coalesce(
            [descriptor(
                Some(UefiMemoryKind::Conventional),
                highest_page,
                2,
                0
            )],
            &mut output
        ),
        Err(MemoryMapError::RangeOverflow)
    );
    assert_eq!(
        normalize_and_coalesce(
            [descriptor(
                Some(UefiMemoryKind::Conventional),
                0,
                u64::MAX,
                0
            )],
            &mut output
        ),
        Err(MemoryMapError::RangeOverflow)
    );
}

fn default_descriptor() -> DwBootMemoryRangeV1 {
    DwBootMemoryRangeV1::default()
}
