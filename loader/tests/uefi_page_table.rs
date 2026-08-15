#[path = "../src/uefi_page_table.rs"]
mod uefi_page_table;

use uefi_page_table::{PAGE_BYTES, UefiPageTable, UefiPageTableError};
use wyrmroot_efi_loader::transition::{
    AllocationLifetime, MappingKind, MappingPermissions, TransitionMapping, TransitionPageTable,
};

const RETAINED: AllocationLifetime = AllocationLifetime::RetainedUntilKernelPageTableReplacement;
const PHYSICAL_ADDRESS_BITS: u8 = 48;

fn mapping(
    virtual_start: u64,
    physical_start: u64,
    byte_len: u64,
    writable: bool,
    executable: bool,
) -> TransitionMapping {
    TransitionMapping {
        kind: MappingKind::BootInfo,
        virtual_start,
        physical_start,
        byte_len,
        permissions: MappingPermissions {
            writable,
            executable,
        },
        lifetime: RETAINED,
    }
}

#[test]
fn maps_identity_and_canonical_high_pages_with_exact_permissions() {
    let mut pages = [[0_u64; 512]; 7];
    let mut table = UefiPageTable::new(0x400000, PHYSICAL_ADDRESS_BITS, &mut pages).unwrap();
    table.leave_page_zero_unmapped(PAGE_BYTES).unwrap();
    table
        .map(mapping(0x2000, 0x2000, PAGE_BYTES, true, false))
        .unwrap();
    table
        .map(mapping(
            0xffff_8000_0040_0000,
            0x500000,
            PAGE_BYTES,
            false,
            true,
        ))
        .unwrap();

    assert_eq!(table.cr3_root_physical(), 0x400000);
    assert_eq!(table.used_page_count(), 7);
    assert_eq!(table.finish(), Ok(0x400000));
    assert_eq!(
        table.translate(0x2345),
        Some(uefi_page_table::Translation {
            physical_address: 0x2345,
            writable: true,
            executable: false,
        })
    );
    assert_eq!(
        table.translate(0xffff_8000_0040_0037),
        Some(uefi_page_table::Translation {
            physical_address: 0x500037,
            writable: false,
            executable: true,
        })
    );
}

#[test]
fn page_zero_stays_absent_and_cannot_be_mapped() {
    let mut pages = [[0_u64; 512]; 4];
    let mut table = UefiPageTable::new(0x400000, PHYSICAL_ADDRESS_BITS, &mut pages).unwrap();
    table.leave_page_zero_unmapped(PAGE_BYTES).unwrap();
    assert_eq!(table.translate(0), None);
    assert_eq!(
        table.map(mapping(0, 0x2000, PAGE_BYTES, false, false)),
        Err(UefiPageTableError::PageZeroMappingForbidden)
    );
    assert_eq!(table.translate(0), None);
}

#[test]
fn rejects_duplicate_conflicting_and_invalid_physical_mappings() {
    let mut pages = [[0_u64; 512]; 4];
    let mut table = UefiPageTable::new(0x400000, PHYSICAL_ADDRESS_BITS, &mut pages).unwrap();
    table.leave_page_zero_unmapped(PAGE_BYTES).unwrap();
    let original = mapping(0x2000, 0x600000, PAGE_BYTES, false, true);
    table.map(original).unwrap();
    assert_eq!(
        table.map(original),
        Err(UefiPageTableError::DuplicateMapping)
    );
    assert_eq!(
        table.map(mapping(0x2000, 0x700000, PAGE_BYTES, false, true)),
        Err(UefiPageTableError::MappingConflict)
    );
    assert_eq!(
        table.map(mapping(
            0x3000,
            1_u64 << PHYSICAL_ADDRESS_BITS,
            PAGE_BYTES,
            false,
            false
        )),
        Err(UefiPageTableError::PhysicalAddressInvalid)
    );
}

#[test]
fn rejects_nonzero_storage_and_exhaustion() {
    let mut nonzero = [[0_u64; 512]; 1];
    nonzero[0][0] = 1;
    assert!(matches!(
        UefiPageTable::new(0x400000, PHYSICAL_ADDRESS_BITS, &mut nonzero),
        Err(UefiPageTableError::StorageNotZeroed)
    ));

    let mut pages = [[0_u64; 512]; 3];
    let mut table = UefiPageTable::new(0x400000, PHYSICAL_ADDRESS_BITS, &mut pages).unwrap();
    table.leave_page_zero_unmapped(PAGE_BYTES).unwrap();
    assert_eq!(
        table.map(mapping(0x2000, 0x2000, PAGE_BYTES, false, false)),
        Err(UefiPageTableError::TableStorageExhausted)
    );
}

#[test]
fn rejects_noncanonical_and_unaligned_requests() {
    let mut pages = [[0_u64; 512]; 4];
    let mut table = UefiPageTable::new(0x400000, PHYSICAL_ADDRESS_BITS, &mut pages).unwrap();
    table.leave_page_zero_unmapped(PAGE_BYTES).unwrap();
    assert_eq!(
        table.map(mapping(
            0x0001_0000_0000_0000,
            0x2000,
            PAGE_BYTES,
            false,
            false
        )),
        Err(UefiPageTableError::VirtualAddressNonCanonical)
    );
    assert_eq!(
        table.map(mapping(0x2001, 0x2000, PAGE_BYTES, false, false)),
        Err(UefiPageTableError::MappingUnaligned)
    );
    assert_eq!(
        table.map(mapping(
            0x0000_7fff_ffff_f000,
            0x3000,
            PAGE_BYTES * 2,
            false,
            false,
        )),
        Err(UefiPageTableError::MappingSpansCanonicalHole)
    );
}

#[test]
fn requires_valid_physical_address_width_and_exact_table_consumption() {
    let mut pages = [[0_u64; 512]; 1];
    assert!(matches!(
        UefiPageTable::new(0x400000, 35, &mut pages),
        Err(UefiPageTableError::PhysicalAddressBitsInvalid)
    ));

    let mut pages = [[0_u64; 512]; 5];
    let mut table = UefiPageTable::new(0x400000, PHYSICAL_ADDRESS_BITS, &mut pages).unwrap();
    table.leave_page_zero_unmapped(PAGE_BYTES).unwrap();
    table
        .map(mapping(0x2000, 0x2000, PAGE_BYTES, false, false))
        .unwrap();
    assert_eq!(
        table.finish(),
        Err(UefiPageTableError::UnconsumedTablePages {
            used: 4,
            supplied: 5,
        })
    );
}
