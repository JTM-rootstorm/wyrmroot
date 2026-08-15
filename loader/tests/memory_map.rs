#[path = "../src/boot_info.rs"]
#[allow(dead_code)] // Imported only for the shared descriptor type before crate export integration.
mod boot_info;
#[path = "../src/memory_map.rs"]
mod memory_map;

use boot_info::UefiMemoryKind;
use deepwyrm_abi::DW_BOOT_BASE_PAGE_SIZE;
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
    assert_eq!(normalized[0].kind, UefiMemoryKind::Conventional);
    assert_eq!(normalized[0].physical_start, PAGE_SIZE);
    assert_eq!(normalized[0].page_count, 129);
    assert_eq!(normalized[0].firmware_attributes, 0x10);
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
    assert_eq!(normalized[0].kind, UefiMemoryKind::Reserved);
    assert_eq!(normalized[1].kind, UefiMemoryKind::Reserved);
    assert_eq!(normalized[1].firmware_attributes, 0x20);
    assert_eq!(normalized[2].kind, UefiMemoryKind::Mmio);
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

fn default_descriptor() -> boot_info::UefiMemoryDescriptor {
    boot_info::UefiMemoryDescriptor {
        kind: UefiMemoryKind::Unusable,
        physical_start: 0,
        page_count: 0,
        firmware_attributes: 0,
    }
}
