use std::panic::{AssertUnwindSafe, catch_unwind};

use wyrmroot_loader::elf::{
    self, LoadSegment, MAX_LOAD_SEGMENTS, PAGE_SIZE, STACK_GUARD_START, STACK_TOP,
    SegmentProtection, USER_END_EXCLUSIVE,
};

const PH_OFFSET: usize = 64;
const PH_SIZE: usize = 56;

#[derive(Clone, Copy)]
struct Ph {
    flags: u32,
    offset: u64,
    address: u64,
    file_size: u64,
    memory_size: u64,
}

// A small local generator keeps this test reproducible without depending on a
// property-testing crate or an ambient random source.
#[derive(Clone, Copy)]
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        let mut value = self.0;
        value ^= value << 13;
        value ^= value >> 7;
        value ^= value << 17;
        self.0 = value;
        value
    }

    fn below(&mut self, upper: u64) -> u64 {
        self.next() % upper
    }
}

fn put16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn put32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn put64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn image(headers: &[Ph], entry: u64, length: usize) -> Vec<u8> {
    let mut bytes = vec![0_u8; length];
    bytes[..4].copy_from_slice(b"\x7fELF");
    bytes[4] = 2;
    bytes[5] = 1;
    bytes[6] = 1;
    put16(&mut bytes, 16, 2);
    put16(&mut bytes, 18, 62);
    put32(&mut bytes, 20, 1);
    put64(&mut bytes, 24, entry);
    put64(&mut bytes, 32, PH_OFFSET as u64);
    put16(&mut bytes, 52, 64);
    put16(&mut bytes, 54, PH_SIZE as u16);
    put16(&mut bytes, 56, headers.len() as u16);
    for (index, ph) in headers.iter().enumerate() {
        let at = PH_OFFSET + index * PH_SIZE;
        put32(&mut bytes, at, 1);
        put32(&mut bytes, at + 4, ph.flags);
        put64(&mut bytes, at + 8, ph.offset);
        put64(&mut bytes, at + 16, ph.address);
        put64(&mut bytes, at + 24, ph.address);
        put64(&mut bytes, at + 32, ph.file_size);
        put64(&mut bytes, at + 40, ph.memory_size);
        put64(&mut bytes, at + 48, PAGE_SIZE);
    }
    bytes
}

fn empty_segment() -> LoadSegment {
    LoadSegment {
        header_index: 0,
        file_offset: 0,
        file_size: 0,
        memory_size: 0,
        virtual_address: 0,
        mapping_start: 0,
        mapping_size: 0,
        leading_bytes: 0,
        protection: SegmentProtection::Read,
    }
}

fn valid_image(rng: &mut Rng) -> Vec<u8> {
    let count = 1 + rng.below(MAX_LOAD_SEGMENTS as u64) as usize;
    let mut headers = Vec::with_capacity(count);
    let mut entry = 0;
    for index in 0..count {
        let address = 0x20_0000 + (index as u64) * 0x20_000;
        let memory_size = PAGE_SIZE + rng.below(3) * PAGE_SIZE;
        let file_size = 1 + rng.below(memory_size);
        let flags = match index {
            0 => 5,
            _ if rng.next() & 1 == 0 => 4,
            _ => 6,
        };
        if index == 0 {
            entry = address + rng.below(file_size);
        }
        headers.push(Ph {
            flags,
            offset: PAGE_SIZE * (index as u64 + 1),
            address,
            file_size,
            memory_size,
        });
    }
    image(&headers, entry, 0x10_0000)
}

#[test]
fn bounded_hostile_inputs_never_panic() {
    let mut rng = Rng(0x4d59_5df4_d0f3_1a27);
    for case in 0..512 {
        let length = rng.below(4097) as usize;
        let mut bytes = vec![0_u8; length];
        for byte in &mut bytes {
            *byte = rng.next() as u8;
        }
        let result = catch_unwind(AssertUnwindSafe(|| {
            let _ = elf::required_segment_count(&bytes);
            let mut output = [empty_segment(); MAX_LOAD_SEGMENTS];
            let _ = elf::plan(&bytes, &mut output);
        }));
        assert!(result.is_ok(), "hostile case {case} panicked");
    }
}

#[test]
fn generated_accepted_plans_preserve_layout_invariants() {
    let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
    for case in 0..256 {
        let bytes = valid_image(&mut rng);
        let mut output = [empty_segment(); MAX_LOAD_SEGMENTS];
        let plan = elf::plan(&bytes, &mut output).expect("generator emits valid ELF");
        assert!(!plan.segments.is_empty(), "case {case} has no segments");
        assert!(plan.entry > 0);
        for pair in plan.segments.windows(2) {
            assert!(pair[0].mapping_start < pair[1].mapping_start);
            assert!(pair[0].mapping_end() <= pair[1].mapping_start);
            assert!(pair[0].memory_end() <= pair[1].virtual_address);
        }
        for segment in plan.segments {
            assert!(segment.mapping_start >= PAGE_SIZE);
            assert!(segment.mapping_end() <= USER_END_EXCLUSIVE);
            assert!(
                segment.mapping_end() <= STACK_GUARD_START || segment.mapping_start >= STACK_TOP
            );
            assert!(
                segment.protection == SegmentProtection::Read
                    || segment.protection == SegmentProtection::ReadExecute
                    || segment.protection == SegmentProtection::ReadWrite
            );
        }
        assert!(plan.segments.iter().any(|segment| segment.protection
            == SegmentProtection::ReadExecute
            && plan.entry >= segment.virtual_address
            && plan.entry < segment.memory_end()));
    }
}
