//! RRC-A static-image audit for the final DW1-F/WYR1-F products.
//!
//! DW1-F/WYR1-F F2B. The closure verification in [`crate::wyr1c`] already
//! proves membership, identity and residence: the frozen seven, each resolved
//! by looking it up inside the retained bootfs and nowhere else. What it never
//! read is the *images*. An RRC-A member that had acquired a `PT_INTERP`
//! segment or a `DT_NEEDED` entry would still be a byte-identical retained
//! bootfs entry, and every existing check would pass, while recovery now
//! depended on a loader and a shared object that the closure does not contain.
//!
//! The closure contract forbids exactly that -- no dynamic loader or shared
//! library outside the retained closure, and no interpreter -- and nothing
//! machine-checked it. `tools/xtask/src/elf_runtime.rs` inspects the same
//! structures for the opposite purpose, on host toolchain binaries, and
//! *requires* the dynamic material this module refuses; the two are not
//! interchangeable.

use crate::error::Failure;

const ELF_HEADER_BYTES: usize = 64;
const PROGRAM_HEADER_BYTES: usize = 56;
/// A freestanding role image has single-digit segment counts. The bound exists
/// so a corrupt header cannot make this walk the whole entry.
const MAX_PROGRAM_HEADERS: u16 = 64;

const ET_EXEC: u16 = 2;
const EM_X86_64: u16 = 62;
const PT_DYNAMIC: u32 = 2;
const PT_INTERP: u32 = 3;

fn u16_at(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([bytes[offset], bytes[offset + 1]])
}

fn u32_at(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}

fn u64_at(bytes: &[u8], offset: usize) -> u64 {
    let mut value = [0u8; 8];
    value.copy_from_slice(&bytes[offset..offset + 8]);
    u64::from_le_bytes(value)
}

/// Accepts one RRC-A executable as a self-contained freestanding image.
///
/// Refuses anything that would make the image need something the closure does
/// not hold: a foreign class, encoding or machine; a relocatable or shared
/// object, which a static role executable is not; an interpreter segment; or a
/// dynamic segment, whose `DT_NEEDED`/`DT_RPATH` contents only exist when a
/// loader is expected to read them.
pub(crate) fn audit_static_image(bytes: &[u8], label: &str) -> Result<(), Failure> {
    let refuse = |reason: &str| Failure::task(format!("RRC-A member {label} {reason}"));
    if bytes.len() < ELF_HEADER_BYTES {
        return Err(refuse("is shorter than an ELF64 header"));
    }
    if bytes[..4] != [0x7f, b'E', b'L', b'F'] {
        return Err(refuse("is not an ELF image"));
    }
    if bytes[4] != 2 {
        return Err(refuse("is not ELF64"));
    }
    if bytes[5] != 1 {
        return Err(refuse("is not little-endian"));
    }
    if u16_at(bytes, 16) != ET_EXEC {
        return Err(refuse(
            "is not a fixed-address executable; a shared or position-independent \
             object is loaded, not started",
        ));
    }
    if u16_at(bytes, 18) != EM_X86_64 {
        return Err(refuse("is not an x86-64 image"));
    }
    if u16_at(bytes, 54) as usize != PROGRAM_HEADER_BYTES {
        return Err(refuse("declares a foreign program header size"));
    }
    let count = u16_at(bytes, 56);
    if count == 0 {
        return Err(refuse("declares no program headers"));
    }
    if count > MAX_PROGRAM_HEADERS {
        return Err(refuse("declares an implausible number of program headers"));
    }
    let table = u64_at(bytes, 32);
    let span = (count as u64)
        .checked_mul(PROGRAM_HEADER_BYTES as u64)
        .and_then(|span| span.checked_add(table))
        .ok_or_else(|| refuse("declares a program header table that overflows"))?;
    if span > bytes.len() as u64 {
        return Err(refuse("declares a program header table past its own end"));
    }
    let table = table as usize;
    for index in 0..count as usize {
        let header = table + index * PROGRAM_HEADER_BYTES;
        match u32_at(bytes, header) {
            PT_INTERP => {
                return Err(refuse(
                    "names an interpreter, which the retained closure does not contain",
                ));
            }
            PT_DYNAMIC => {
                return Err(refuse(
                    "carries a dynamic segment, so it expects a loader and a shared \
                     object outside the closure",
                ));
            }
            _ => {}
        }
    }
    Ok(())
}

/// A minimal image of the shape this audit accepts: ELF64, little-endian,
/// `ET_EXEC`, x86-64, one `PT_LOAD` segment and nothing dynamic.
///
/// Test-only, and shared rather than duplicated: the WYR1-F product fixtures in
/// [`crate::wyr1c`] stand in for role executables, so they have to be images
/// this audit would accept, and a second hand-rolled header there would be a
/// second thing to keep in step with the one being tested. `filler` makes each
/// fixture's bytes -- and therefore its content identity -- distinct.
#[cfg(test)]
pub(crate) fn test_static_image(filler: u8, trailing: usize) -> Vec<u8> {
    test_image_with_segment(1, filler, trailing)
}

/// The same image with a `PT_INTERP` segment, for the product-level negative:
/// a closure member that needs an interpreter, with every identity still
/// agreeing, so the audit is the only thing that can object.
#[cfg(test)]
pub(crate) fn test_interpreter_image(filler: u8, trailing: usize) -> Vec<u8> {
    test_image_with_segment(PT_INTERP, filler, trailing)
}

#[cfg(test)]
fn test_image_with_segment(segment_kind: u32, filler: u8, trailing: usize) -> Vec<u8> {
    let table = ELF_HEADER_BYTES;
    let mut bytes = vec![0u8; ELF_HEADER_BYTES + PROGRAM_HEADER_BYTES];
    bytes[..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
    bytes[4] = 2;
    bytes[5] = 1;
    bytes[16..18].copy_from_slice(&ET_EXEC.to_le_bytes());
    bytes[18..20].copy_from_slice(&EM_X86_64.to_le_bytes());
    bytes[32..40].copy_from_slice(&(table as u64).to_le_bytes());
    bytes[54..56].copy_from_slice(&(PROGRAM_HEADER_BYTES as u16).to_le_bytes());
    bytes[56..58].copy_from_slice(&1u16.to_le_bytes());
    bytes[table..table + 4].copy_from_slice(&segment_kind.to_le_bytes());
    bytes.extend(core::iter::repeat_n(filler, trailing));
    bytes
}

#[cfg(test)]
mod tests {
    use super::{ELF_HEADER_BYTES, audit_static_image, test_image_with_segment};

    /// One PT_LOAD segment, the shape every role image actually has.
    fn image(segment_kind: u32) -> Vec<u8> {
        test_image_with_segment(segment_kind, 0, 0)
    }

    #[test]
    fn a_static_freestanding_executable_is_accepted() {
        audit_static_image(&image(1), "system/registryd").expect("PT_LOAD only");
    }

    /// The two findings this audit exists for. Both images are valid ELF, both
    /// would be byte-identical retained bootfs entries, and both make recovery
    /// depend on material the closure does not hold.
    #[test]
    fn an_interpreter_or_a_dynamic_segment_is_refused() {
        let interpreter = audit_static_image(&image(3), "system/consoled")
            .expect_err("PT_INTERP must be refused");
        assert!(
            interpreter.message.contains("names an interpreter"),
            "{}",
            interpreter.message
        );
        let dynamic =
            audit_static_image(&image(2), "system/wyrmsh").expect_err("PT_DYNAMIC must be refused");
        assert!(
            dynamic.message.contains("carries a dynamic segment"),
            "{}",
            dynamic.message
        );
    }

    /// A position-independent role executable is refused as well. The kernel
    /// starts these at their linked addresses; an `ET_DYN` image is the shape
    /// that expects to be relocated by something else first.
    #[test]
    fn a_shared_or_position_independent_object_is_refused() {
        let mut bytes = image(1);
        bytes[16..18].copy_from_slice(&3u16.to_le_bytes());
        let failure = audit_static_image(&bytes, "system/devmgr").expect_err("ET_DYN is refused");
        assert!(
            failure
                .message
                .contains("is not a fixed-address executable"),
            "{}",
            failure.message
        );
    }

    #[test]
    fn a_truncated_or_foreign_image_is_refused_before_it_is_walked() {
        for (bytes, reason) in [
            (vec![0u8; 8], "is shorter than an ELF64 header"),
            (
                {
                    let mut bytes = image(1);
                    bytes[1] = b'X';
                    bytes
                },
                "is not an ELF image",
            ),
            (
                {
                    let mut bytes = image(1);
                    bytes[4] = 1;
                    bytes
                },
                "is not ELF64",
            ),
            (
                {
                    let mut bytes = image(1);
                    bytes[18..20].copy_from_slice(&40u16.to_le_bytes());
                    bytes
                },
                "is not an x86-64 image",
            ),
            (
                {
                    let mut bytes = image(1);
                    bytes[56..58].copy_from_slice(&512u16.to_le_bytes());
                    bytes
                },
                "declares an implausible number of program headers",
            ),
            (
                {
                    let mut bytes = image(1);
                    bytes[32..40].copy_from_slice(&u64::MAX.to_le_bytes());
                    bytes
                },
                "declares a program header table that overflows",
            ),
            (
                {
                    let mut bytes = image(1);
                    bytes[32..40].copy_from_slice(&(ELF_HEADER_BYTES as u64 + 8).to_le_bytes());
                    bytes
                },
                "declares a program header table past its own end",
            ),
        ] {
            let failure = audit_static_image(&bytes, "system/init").expect_err(reason);
            assert!(failure.message.contains(reason), "{}", failure.message);
        }
    }
}
