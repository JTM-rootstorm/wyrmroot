//! CRC-32C (Castagnoli, reflected polynomial 0x82F63B78) as ext4 uses it:
//! a running update with no final inversion, seeded with `!0` (the
//! kernel.org ext4 documentation, "Checksums").

const TABLE: [u32; 256] = {
    let mut table = [0u32; 256];
    let mut index = 0;
    while index < 256 {
        let mut crc = index as u32;
        let mut bit = 0;
        while bit < 8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ 0x82F6_3B78
            } else {
                crc >> 1
            };
            bit += 1;
        }
        table[index] = crc;
        index += 1;
    }
    table
};

/// Continues `crc` over `bytes`.
pub fn update(mut crc: u32, bytes: &[u8]) -> u32 {
    for &byte in bytes {
        crc = TABLE[((crc ^ u32::from(byte)) & 0xFF) as usize] ^ (crc >> 8);
    }
    crc
}

/// Continues `crc` over `count` zero bytes.
pub fn update_zeros(mut crc: u32, count: usize) -> u32 {
    for _ in 0..count {
        crc = TABLE[(crc & 0xFF) as usize] ^ (crc >> 8);
    }
    crc
}
