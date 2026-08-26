//! Safe parsing of the bounded WYR0 native startup block.

use deepwyrm_syscall::DwHandle;

/// The only startup ABI version currently understood by the runtime.
pub const STARTUP_ABI_V1: u64 = 1;
/// WYR1-B launched-job startup ABI.
pub const STARTUP_ABI_V2: u64 = 2;
/// Size of the primordial vector-and-string block at the initial stack pointer.
pub const STARTUP_BLOCK_SIZE: usize = 4096;
/// Startup ABI v2 occupies the highest five mapped stack pages.
pub const STARTUP_BLOCK_V2_SIZE: usize = 20 * 1024;
/// Terminal auxiliary-vector pair required by startup ABI V1.
pub const AUXILIARY_VECTOR_TERMINATOR: (u64, u64) = (0, 0);
const WORD_SIZE: usize = 8;

/// Register values whose meanings are defined by WYR0 startup ABI V1.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StartupRegisters {
    /// Raw opaque bootstrap Channel handle from RDI.
    pub startup_argument0: u64,
    /// Startup ABI version from RSI.
    pub startup_argument1: u64,
}

/// An opaque process-local bootstrap Channel handle.
///
/// This wrapper intentionally assigns no special value or global meaning to the handle.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BootstrapChannelHandle(DwHandle);

impl BootstrapChannelHandle {
    /// Returns the raw value for the future exact Deepwyrm binding; it remains opaque here.
    pub const fn raw(self) -> u64 {
        self.0.0
    }

    /// Returns the exact pinned-ABI handle value for the future G1B binding.
    pub const fn as_abi(self) -> DwHandle {
        self.0
    }
}

/// A NUL-terminated byte string borrowed from the validated startup block.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StartupString<'a>(&'a [u8]);

impl<'a> StartupString<'a> {
    /// Returns the string bytes excluding the validated terminal NUL.
    pub const fn as_bytes(self) -> &'a [u8] {
        self.0
    }

    /// Returns the startup string as validated native UTF-8 text.
    pub fn as_str(self) -> &'a str {
        core::str::from_utf8(self.0).expect("validated startup UTF-8")
    }
}

/// A validated, allocation-free view of a native startup block.
#[derive(Clone, Copy, Debug)]
pub struct StartupBlock<'a> {
    bytes: &'a [u8],
    address: u64,
    bootstrap_channel: BootstrapChannelHandle,
    argv_offset: usize,
    argc: usize,
    envp_offset: usize,
    envc: usize,
    auxv_offset: usize,
    auxc: usize,
}

/// Startup-block validation failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StartupError {
    /// RDI/RSI did not identify the supported startup ABI version.
    UnsupportedVersion,
    /// RDI carried ABI-invalid handle zero instead of a bootstrap Channel.
    InvalidBootstrapChannelHandle,
    /// RSP/startup-block base was not 16-byte aligned.
    MisalignedStack,
    /// The caller did not provide exactly one bounded startup block.
    WrongBlockSize,
    /// The bounded block's virtual range overflowed.
    AddressOverflow,
    /// A declared word/vector count could not fit in the bounded block.
    VectorOverflow,
    /// An argv or environment vector did not have the mandated NULL terminator.
    MissingVectorTerminator,
    /// An auxiliary vector did not end in `(0, 0)`.
    MissingAuxiliaryTerminator,
    /// A string pointer lay outside the bounded startup block.
    StringPointerOutOfRange,
    /// A referenced argv/environment string had no NUL before the end of the block.
    UnterminatedString,
    /// A referenced argv/environment string was not valid native UTF-8 text.
    InvalidUtf8,
    /// ABI v2 exceeded the fixed argv bound or omitted argv[0].
    ArgumentLimit,
    /// ABI v2 exceeded the fixed environment-entry bound.
    EnvironmentLimit,
    /// ABI v2 argv/environment strings exceeded 16 KiB including NULs.
    StringBytesExceeded,
    /// ABI v2 strings did not immediately follow the vectors without aliases or gaps.
    NoncanonicalStringLayout,
    /// An ABI v2 environment entry did not use canonical NAME=VALUE spelling.
    InvalidEnvironment,
    /// ABI v2 repeated an environment variable name.
    DuplicateEnvironment,
}

/// Returns a stable bounded process exit code for native-entry startup
/// validation failures. The `0x57` high byte is Wyrmroot-runtime-owned and the
/// low byte identifies the exact [`StartupError`] variant.
#[must_use]
pub const fn startup_error_exit_code(error: StartupError) -> u32 {
    const PREFIX: u32 = 0x5700_0000;
    PREFIX
        | match error {
            StartupError::UnsupportedVersion => 1,
            StartupError::InvalidBootstrapChannelHandle => 2,
            StartupError::MisalignedStack => 3,
            StartupError::WrongBlockSize => 4,
            StartupError::AddressOverflow => 5,
            StartupError::VectorOverflow => 6,
            StartupError::MissingVectorTerminator => 7,
            StartupError::MissingAuxiliaryTerminator => 8,
            StartupError::StringPointerOutOfRange => 9,
            StartupError::UnterminatedString => 10,
            StartupError::InvalidUtf8 => 11,
            StartupError::ArgumentLimit => 12,
            StartupError::EnvironmentLimit => 13,
            StartupError::StringBytesExceeded => 14,
            StartupError::NoncanonicalStringLayout => 15,
            StartupError::InvalidEnvironment => 16,
            StartupError::DuplicateEnvironment => 17,
        }
}

/// Parses the native startup page and keeps every borrow inside one non-escaping callback.
///
/// # Safety
///
/// `address` must identify the initial, immutable, readable [`STARTUP_BLOCK_SIZE`]-byte page for
/// the complete call. It must be the initial stack address supplied by Deepwyrm rather than an
/// arbitrary userspace pointer.
#[allow(
    unsafe_code,
    reason = "the native entry shim supplies the validated initial stack pointer and the higher-ranked callback prevents startup borrows from escaping"
)]
pub unsafe fn with_native_startup<R>(
    registers: StartupRegisters,
    address: u64,
    use_block: impl for<'block> FnOnce(StartupBlock<'block>) -> R,
) -> Result<R, StartupError> {
    let block_size = startup_block_size(registers.startup_argument1)?;
    if registers.startup_argument0 == 0 {
        return Err(StartupError::InvalidBootstrapChannelHandle);
    }
    if !address.is_multiple_of(16) {
        return Err(StartupError::MisalignedStack);
    }
    address
        .checked_add(block_size as u64)
        .ok_or(StartupError::AddressOverflow)?;
    let pointer = address as *const u8;
    // SAFETY: the caller guarantees that the initial startup page is readable and immutable for
    // this call. The higher-ranked callback prevents `StartupBlock` or its strings from escaping.
    let bytes = unsafe { core::slice::from_raw_parts(pointer, block_size) };
    StartupBlock::parse(registers, address, bytes).map(use_block)
}

impl<'a> StartupBlock<'a> {
    /// Parses and fully bounds-checks the ABI V1 startup block.
    pub fn parse(
        registers: StartupRegisters,
        address: u64,
        bytes: &'a [u8],
    ) -> Result<Self, StartupError> {
        let block_size = startup_block_size(registers.startup_argument1)?;
        if registers.startup_argument0 == 0 {
            return Err(StartupError::InvalidBootstrapChannelHandle);
        }
        if !address.is_multiple_of(16) {
            return Err(StartupError::MisalignedStack);
        }
        if bytes.len() != block_size {
            return Err(StartupError::WrongBlockSize);
        }
        let block_end = address
            .checked_add(block_size as u64)
            .ok_or(StartupError::AddressOverflow)?;
        let argc = usize::try_from(read_word(bytes, 0).ok_or(StartupError::VectorOverflow)?)
            .map_err(|_| StartupError::VectorOverflow)?;
        let argv_offset = WORD_SIZE;
        let argv_after = advance_words(argv_offset, argc).ok_or(StartupError::VectorOverflow)?;
        require_word(bytes, argv_after, 0, StartupError::MissingVectorTerminator)?;
        let envp_offset = argv_after
            .checked_add(WORD_SIZE)
            .ok_or(StartupError::VectorOverflow)?;
        let (envc, auxv_offset) = scan_null_terminated_vector(bytes, envp_offset)?;
        let auxc = scan_auxiliary_vector(bytes, auxv_offset)?;

        for index in 0..argc {
            validate_string(
                bytes,
                address,
                block_end,
                word_at(bytes, argv_offset, index)?,
            )?;
        }
        for index in 0..envc {
            validate_string(
                bytes,
                address,
                block_end,
                word_at(bytes, envp_offset, index)?,
            )?;
        }
        if registers.startup_argument1 == STARTUP_ABI_V2 {
            validate_v2_layout(
                bytes,
                address,
                argc,
                argv_offset,
                envc,
                envp_offset,
                auxv_offset,
            )?;
        }
        Ok(Self {
            bytes,
            address,
            bootstrap_channel: BootstrapChannelHandle(DwHandle(registers.startup_argument0)),
            argv_offset,
            argc,
            envp_offset,
            envc,
            auxv_offset,
            auxc,
        })
    }

    /// Returns the actual opaque Channel handle passed in RDI.
    pub const fn bootstrap_channel(self) -> BootstrapChannelHandle {
        self.bootstrap_channel
    }

    /// Returns the validated argument count.
    pub const fn argc(self) -> usize {
        self.argc
    }
    /// Returns the validated environment entry count.
    pub const fn envc(self) -> usize {
        self.envc
    }
    /// Returns the validated auxiliary-vector entry count, excluding its terminal pair.
    pub const fn auxc(self) -> usize {
        self.auxc
    }

    /// Returns one NUL-terminated argv string excluding its terminal NUL.
    pub fn arg(&self, index: usize) -> Option<StartupString<'a>> {
        if index >= self.argc {
            return None;
        }
        Some(self.string_at(word_at(self.bytes, self.argv_offset, index).ok()?))
    }

    /// Returns one NUL-terminated environment string excluding its terminal NUL.
    pub fn env(&self, index: usize) -> Option<StartupString<'a>> {
        if index >= self.envc {
            return None;
        }
        Some(self.string_at(word_at(self.bytes, self.envp_offset, index).ok()?))
    }

    /// Returns an auxiliary-vector entry; its terminal pair is not exposed as an entry.
    pub fn aux(&self, index: usize) -> Option<(u64, u64)> {
        if index >= self.auxc {
            return None;
        }
        let offset = advance_words(self.auxv_offset, index.checked_mul(2)?)?;
        Some((
            read_word(self.bytes, offset)?,
            read_word(self.bytes, offset + WORD_SIZE)?,
        ))
    }

    fn string_at(&self, pointer: u64) -> StartupString<'a> {
        let start = usize::try_from(pointer - self.address).expect("validated startup pointer");
        let tail = &self.bytes[start..];
        let nul = tail
            .iter()
            .position(|byte| *byte == 0)
            .expect("validated startup string");
        StartupString(&tail[..nul])
    }
}

fn startup_block_size(version: u64) -> Result<usize, StartupError> {
    match version {
        STARTUP_ABI_V1 => Ok(STARTUP_BLOCK_SIZE),
        STARTUP_ABI_V2 => Ok(STARTUP_BLOCK_V2_SIZE),
        _ => Err(StartupError::UnsupportedVersion),
    }
}

fn validate_v2_layout(
    bytes: &[u8],
    address: u64,
    argc: usize,
    argv_offset: usize,
    envc: usize,
    envp_offset: usize,
    auxv_offset: usize,
) -> Result<(), StartupError> {
    if !(1..=64).contains(&argc) {
        return Err(StartupError::ArgumentLimit);
    }
    if envc > 64 {
        return Err(StartupError::EnvironmentLimit);
    }
    let mut cursor = scan_auxiliary_vector_end(bytes, auxv_offset)?;
    let mut string_bytes = 0usize;
    for index in 0..argc {
        cursor = validate_canonical_v2_string(
            bytes,
            address,
            argv_offset,
            index,
            cursor,
            &mut string_bytes,
        )?;
    }
    for index in 0..envc {
        cursor = validate_canonical_v2_string(
            bytes,
            address,
            envp_offset,
            index,
            cursor,
            &mut string_bytes,
        )?;
    }
    if string_bytes > 16 * 1024 {
        return Err(StartupError::StringBytesExceeded);
    }
    for index in 0..envc {
        let pointer = word_at(bytes, envp_offset, index)?;
        let value = string_slice(bytes, address, pointer)?;
        let name = environment_name(value)?;
        for previous in 0..index {
            let previous = string_slice(bytes, address, word_at(bytes, envp_offset, previous)?)?;
            if environment_name(previous)? == name {
                return Err(StartupError::DuplicateEnvironment);
            }
        }
    }
    Ok(())
}

fn scan_auxiliary_vector_end(bytes: &[u8], offset: usize) -> Result<usize, StartupError> {
    let mut current = offset;
    loop {
        let kind = read_word(bytes, current).ok_or(StartupError::MissingAuxiliaryTerminator)?;
        let value = read_word(bytes, current + WORD_SIZE)
            .ok_or(StartupError::MissingAuxiliaryTerminator)?;
        current = current
            .checked_add(2 * WORD_SIZE)
            .ok_or(StartupError::VectorOverflow)?;
        if (kind, value) == AUXILIARY_VECTOR_TERMINATOR {
            return Ok(current);
        }
    }
}

fn validate_canonical_v2_string(
    bytes: &[u8],
    address: u64,
    vector_offset: usize,
    index: usize,
    cursor: usize,
    total: &mut usize,
) -> Result<usize, StartupError> {
    let pointer = word_at(bytes, vector_offset, index)?;
    let expected = address
        .checked_add(cursor as u64)
        .ok_or(StartupError::AddressOverflow)?;
    if pointer != expected {
        return Err(StartupError::NoncanonicalStringLayout);
    }
    let tail = bytes
        .get(cursor..)
        .ok_or(StartupError::StringPointerOutOfRange)?;
    let nul = tail
        .iter()
        .position(|byte| *byte == 0)
        .ok_or(StartupError::UnterminatedString)?;
    core::str::from_utf8(&tail[..nul]).map_err(|_| StartupError::InvalidUtf8)?;
    let consumed = nul.checked_add(1).ok_or(StartupError::VectorOverflow)?;
    *total = total.checked_add(nul).ok_or(StartupError::VectorOverflow)?;
    cursor
        .checked_add(consumed)
        .ok_or(StartupError::VectorOverflow)
}

fn string_slice(bytes: &[u8], address: u64, pointer: u64) -> Result<&[u8], StartupError> {
    let offset = usize::try_from(
        pointer
            .checked_sub(address)
            .ok_or(StartupError::StringPointerOutOfRange)?,
    )
    .map_err(|_| StartupError::StringPointerOutOfRange)?;
    let tail = bytes
        .get(offset..)
        .ok_or(StartupError::StringPointerOutOfRange)?;
    let nul = tail
        .iter()
        .position(|byte| *byte == 0)
        .ok_or(StartupError::UnterminatedString)?;
    Ok(&tail[..nul])
}

fn environment_name(value: &[u8]) -> Result<&[u8], StartupError> {
    let equals = value
        .iter()
        .position(|byte| *byte == b'=')
        .ok_or(StartupError::InvalidEnvironment)?;
    let name = &value[..equals];
    if name.is_empty()
        || name.len() > 64
        || !(name[0].is_ascii_uppercase() || name[0] == b'_')
        || !name[1..]
            .iter()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || *byte == b'_')
    {
        return Err(StartupError::InvalidEnvironment);
    }
    Ok(name)
}

fn scan_null_terminated_vector(
    bytes: &[u8],
    offset: usize,
) -> Result<(usize, usize), StartupError> {
    let mut count = 0usize;
    let mut current = offset;
    loop {
        let word = read_word(bytes, current).ok_or(StartupError::MissingVectorTerminator)?;
        if word == 0 {
            return Ok((
                count,
                current
                    .checked_add(WORD_SIZE)
                    .ok_or(StartupError::VectorOverflow)?,
            ));
        }
        count = count.checked_add(1).ok_or(StartupError::VectorOverflow)?;
        current = current
            .checked_add(WORD_SIZE)
            .ok_or(StartupError::VectorOverflow)?;
    }
}

fn scan_auxiliary_vector(bytes: &[u8], offset: usize) -> Result<usize, StartupError> {
    let mut count = 0usize;
    let mut current = offset;
    loop {
        let kind = read_word(bytes, current).ok_or(StartupError::MissingAuxiliaryTerminator)?;
        let value_offset = current
            .checked_add(WORD_SIZE)
            .ok_or(StartupError::VectorOverflow)?;
        let value =
            read_word(bytes, value_offset).ok_or(StartupError::MissingAuxiliaryTerminator)?;
        if (kind, value) == AUXILIARY_VECTOR_TERMINATOR {
            return Ok(count);
        }
        count = count.checked_add(1).ok_or(StartupError::VectorOverflow)?;
        current = value_offset
            .checked_add(WORD_SIZE)
            .ok_or(StartupError::VectorOverflow)?;
    }
}

fn validate_string(bytes: &[u8], start: u64, end: u64, pointer: u64) -> Result<(), StartupError> {
    if pointer < start || pointer >= end {
        return Err(StartupError::StringPointerOutOfRange);
    }
    let offset =
        usize::try_from(pointer - start).map_err(|_| StartupError::StringPointerOutOfRange)?;
    let tail = &bytes[offset..];
    let nul = tail
        .iter()
        .position(|byte| *byte == 0)
        .ok_or(StartupError::UnterminatedString)?;
    core::str::from_utf8(&tail[..nul])
        .map(|_| ())
        .map_err(|_| StartupError::InvalidUtf8)
}

fn word_at(bytes: &[u8], offset: usize, index: usize) -> Result<u64, StartupError> {
    let offset = advance_words(offset, index).ok_or(StartupError::VectorOverflow)?;
    read_word(bytes, offset).ok_or(StartupError::VectorOverflow)
}

fn require_word(
    bytes: &[u8],
    offset: usize,
    expected: u64,
    error: StartupError,
) -> Result<(), StartupError> {
    if read_word(bytes, offset) == Some(expected) {
        Ok(())
    } else {
        Err(error)
    }
}

fn advance_words(offset: usize, count: usize) -> Option<usize> {
    offset.checked_add(count.checked_mul(WORD_SIZE)?)
}
fn read_word(bytes: &[u8], offset: usize) -> Option<u64> {
    Some(u64::from_le_bytes(
        bytes
            .get(offset..offset.checked_add(WORD_SIZE)?)?
            .try_into()
            .ok()?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    const BASE: u64 = 0x0000_0000_0040_0000;
    fn put_word(block: &mut [u8], offset: usize, value: u64) {
        block[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }
    fn valid_block() -> [u8; STARTUP_BLOCK_SIZE] {
        let mut block = [0u8; STARTUP_BLOCK_SIZE];
        put_word(&mut block, 0, 1);
        put_word(&mut block, 8, BASE + 128);
        put_word(&mut block, 16, 0);
        put_word(&mut block, 24, 0);
        put_word(&mut block, 32, 0);
        put_word(&mut block, 40, 0);
        block[128..132].copy_from_slice(b"arg\0");
        block
    }
    fn registers() -> StartupRegisters {
        StartupRegisters {
            startup_argument0: 77,
            startup_argument1: STARTUP_ABI_V1,
        }
    }

    #[test]
    fn parses_empty_environment_and_auxv() {
        let block = valid_block();
        let parsed = StartupBlock::parse(registers(), BASE, &block).unwrap();
        assert_eq!(parsed.bootstrap_channel().raw(), 77);
        assert_eq!(parsed.bootstrap_channel().as_abi(), DwHandle(77));
        assert_eq!(parsed.arg(0).unwrap().as_bytes(), b"arg");
        assert_eq!(parsed.arg(0).unwrap().as_str(), "arg");
        assert_eq!(parsed.envc(), 0);
        assert_eq!(parsed.auxc(), 0);
    }
    #[test]
    fn parses_bounded_nonempty_vectors() {
        let mut block = valid_block();
        put_word(&mut block, 24, BASE + 160);
        put_word(&mut block, 32, 0);
        put_word(&mut block, 40, 7);
        put_word(&mut block, 48, 9);
        put_word(&mut block, 56, 0);
        put_word(&mut block, 64, 0);
        block[160..164].copy_from_slice(b"K=V\0");
        let parsed = StartupBlock::parse(registers(), BASE, &block).unwrap();
        assert_eq!(parsed.env(0).unwrap().as_bytes(), b"K=V");
        assert_eq!(parsed.aux(0), Some((7, 9)));
    }
    #[test]
    fn rejects_version_alignment_and_bounds() {
        let block = valid_block();
        assert!(matches!(
            StartupBlock::parse(
                StartupRegisters {
                    startup_argument1: 3,
                    ..registers()
                },
                BASE,
                &block
            ),
            Err(StartupError::UnsupportedVersion)
        ));
        assert!(matches!(
            StartupBlock::parse(
                StartupRegisters {
                    startup_argument0: 0,
                    ..registers()
                },
                BASE,
                &block
            ),
            Err(StartupError::InvalidBootstrapChannelHandle)
        ));
        assert!(matches!(
            StartupBlock::parse(registers(), BASE + 8, &block),
            Err(StartupError::MisalignedStack)
        ));
        assert!(matches!(
            StartupBlock::parse(registers(), BASE, &block[..4095]),
            Err(StartupError::WrongBlockSize)
        ));
        assert!(matches!(
            StartupBlock::parse(registers(), u64::MAX - 4095, &block),
            Err(StartupError::AddressOverflow)
        ));
    }
    #[test]
    fn rejects_terminators_pointers_and_count_overflow() {
        let mut block = valid_block();
        put_word(&mut block, 16, BASE + 200);
        assert!(matches!(
            StartupBlock::parse(registers(), BASE, &block),
            Err(StartupError::MissingVectorTerminator)
        ));
        let mut block = valid_block();
        put_word(&mut block, 8, BASE + STARTUP_BLOCK_SIZE as u64);
        assert!(matches!(
            StartupBlock::parse(registers(), BASE, &block),
            Err(StartupError::StringPointerOutOfRange)
        ));
        let mut block = valid_block();
        put_word(&mut block, 0, u64::MAX);
        assert!(matches!(
            StartupBlock::parse(registers(), BASE, &block),
            Err(StartupError::VectorOverflow)
        ));

        let mut block = valid_block();
        block[128] = 0xff;
        assert!(matches!(
            StartupBlock::parse(registers(), BASE, &block),
            Err(StartupError::InvalidUtf8)
        ));
    }

    #[test]
    fn parses_canonical_startup_v2_and_rejects_string_aliases() {
        let mut block = [0u8; STARTUP_BLOCK_V2_SIZE];
        // argc, argv[0], argv NULL, env[0], env NULL, aux terminator.
        let strings = 56usize;
        put_word(&mut block, 0, 1);
        put_word(&mut block, 8, BASE + strings as u64);
        put_word(&mut block, 24, BASE + strings as u64 + 10);
        block[strings..strings + 10].copy_from_slice(b"bin/hello\0");
        block[strings + 10..strings + 17].copy_from_slice(b"MODE=1\0");
        let registers = StartupRegisters {
            startup_argument0: 77,
            startup_argument1: STARTUP_ABI_V2,
        };
        let parsed = StartupBlock::parse(registers, BASE, &block).unwrap();
        assert_eq!(parsed.arg(0).unwrap().as_str(), "bin/hello");
        assert_eq!(parsed.env(0).unwrap().as_str(), "MODE=1");

        put_word(&mut block, 24, BASE + strings as u64);
        assert!(matches!(
            StartupBlock::parse(registers, BASE, &block),
            Err(StartupError::NoncanonicalStringLayout)
        ));
    }

    #[test]
    fn native_entry_exit_codes_preserve_each_startup_failure() {
        let failures = [
            StartupError::UnsupportedVersion,
            StartupError::InvalidBootstrapChannelHandle,
            StartupError::MisalignedStack,
            StartupError::WrongBlockSize,
            StartupError::AddressOverflow,
            StartupError::VectorOverflow,
            StartupError::MissingVectorTerminator,
            StartupError::MissingAuxiliaryTerminator,
            StartupError::StringPointerOutOfRange,
            StartupError::UnterminatedString,
            StartupError::InvalidUtf8,
        ];
        for (index, failure) in failures.into_iter().enumerate() {
            assert_eq!(startup_error_exit_code(failure), 0x5700_0001 + index as u32);
        }
    }

    #[repr(align(4096))]
    struct AlignedStartup([u8; STARTUP_BLOCK_SIZE]);

    #[test]
    #[allow(
        unsafe_code,
        reason = "the test owns the complete aligned startup page for the documented native callback contract"
    )]
    fn native_startup_callback_receives_the_exact_bounded_block() {
        let mut bytes = AlignedStartup(valid_block());
        let address = bytes.0.as_ptr() as u64;
        put_word(&mut bytes.0, 8, address + 128);
        // SAFETY: `bytes` is aligned, readable, immutable for the call, and contains a complete
        // startup block whose only pointer was rebased to this exact storage.
        let observed = unsafe {
            with_native_startup(registers(), address, |block| {
                assert_eq!(block.arg(0).unwrap().as_bytes(), b"arg");
                block.bootstrap_channel().raw()
            })
        };
        assert_eq!(observed, Ok(77));
    }
}
