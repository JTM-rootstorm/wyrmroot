//! Pure construction and validation of the generated Deepwyrm BootInfo ABI.
//!
//! This module deliberately has no UEFI dependency and performs no firmware calls. The firmware
//! adapter supplies normalized descriptors and post-`ExitBootServices` storage ownership; this
//! module rejects a handoff that cannot remain valid until Deepwyrm copies it.
//!
//! Construction writes the output slices before every later validation step has completed. Callers
//! must treat `BootInfoOutput` as unusable after an error; transactional construction is deferred
//! until the firmware adapter owns the final physical allocations.

use core::mem::{align_of, size_of};

use deepwyrm_abi::{
    DW_BOOT_BASE_PAGE_SIZE, DW_BOOT_ENTROPY_FLAG_CONDITIONED,
    DW_BOOT_ENTROPY_SOURCE_FIRMWARE_PLATFORM, DW_BOOT_ENTROPY_SOURCE_MIXED_FIRMWARE,
    DW_BOOT_ENTROPY_SOURCE_UEFI_RNG_PROTOCOL, DW_BOOT_ENTROPY_V1_SIZE, DW_BOOT_ENTROPY_V1_VERSION,
    DW_BOOT_FRAMEBUFFER_FLAG_LINEAR, DW_BOOT_FRAMEBUFFER_V1_SIZE, DW_BOOT_FRAMEBUFFER_V1_VERSION,
    DW_BOOT_INFO_FLAG_FRAMEBUFFER_PRESENT, DW_BOOT_INFO_V1_SIZE, DW_BOOT_INFO_V1_VERSION,
    DW_BOOT_MEMORY_KIND_ACPI_NVS, DW_BOOT_MEMORY_KIND_ACPI_RECLAIM, DW_BOOT_MEMORY_KIND_MMIO,
    DW_BOOT_MEMORY_KIND_RESERVED, DW_BOOT_MEMORY_KIND_RUNTIME_SERVICES,
    DW_BOOT_MEMORY_KIND_UNUSABLE, DW_BOOT_MEMORY_KIND_USABLE, DW_BOOT_MEMORY_RANGE_V1_SIZE,
    DW_BOOT_MEMORY_RANGE_V1_VERSION, DW_BOOT_MODULE_FLAG_READ_ONLY,
    DW_BOOT_MODULE_KIND_WYRMROOT_BOOTFS, DW_BOOT_MODULE_KIND_WYRMROOT_BOOTSTRAP,
    DW_BOOT_MODULE_V1_SIZE, DW_BOOT_MODULE_V1_VERSION, DW_BOOT_PIXEL_FORMAT_BGRX8,
    DW_BOOT_PIXEL_FORMAT_BITMASK, DW_BOOT_PIXEL_FORMAT_RGBX8, DwBootEntropyFlags, DwBootEntropyV1,
    DwBootFramebufferV1, DwBootInfoFlags, DwBootInfoV1, DwBootMemoryKind, DwBootMemoryRangeV1,
    DwBootModuleV1,
};

/// Loader-local resource cap, not a Deepwyrm ABI value.
pub const MAX_COMMAND_LINE_BYTES: u64 = 4096;
/// Loader-local bound on the firmware entropy seed retained for handoff.
pub const MAX_ENTROPY_BYTES: u64 = 4096;
/// The external ACPI RSDP base structure is at least this many bytes.
pub const ACPI_RSDP_MINIMUM_BYTES: u64 = 20;
/// ACPI RSDP alignment prescribed by the ACPI specification.
pub const ACPI_RSDP_ALIGNMENT: u64 = 16;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FirmwarePhase {
    BeforeExitBootServices,
    AfterExitBootServices,
}

/// UEFI categories normalized by the loader without importing UEFI numeric constants here.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UefiMemoryKind {
    Conventional,
    BootServices,
    Loader,
    Reserved,
    AcpiReclaim,
    AcpiNvs,
    Mmio,
    RuntimeServices,
    Unusable,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UefiMemoryDescriptor {
    pub kind: UefiMemoryKind,
    pub physical_start: u64,
    pub page_count: u64,
    pub firmware_attributes: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AllocationLifetime {
    /// The allocation remains valid until the kernel has copied the handoff data it needs.
    RetainedUntilKernelCopy,
    ReleasedBeforeHandoff,
    AllocationFailed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HandoffAllocation {
    pub physical_start: u64,
    /// Full retained allocation extent, including any page-rounding slack.
    pub byte_len: u64,
    pub lifetime: AllocationLifetime,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FirmwareEntropySource {
    UefiRngProtocol,
    FirmwarePlatform,
    MixedFirmware,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EntropyInput {
    pub storage: HandoffAllocation,
    pub byte_len: u64,
    pub source: FirmwareEntropySource,
    pub conditioned: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CommandLineInput {
    pub storage: HandoffAllocation,
    /// Exact ABI-visible command-line byte count, excluding allocation slack.
    pub byte_len: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FramebufferPixelFormat {
    Rgbx8,
    Bgrx8,
    Bitmask {
        red_mask: u32,
        green_mask: u32,
        blue_mask: u32,
        reserved_mask: u32,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FramebufferInput {
    pub physical_start: u64,
    pub byte_len: u64,
    pub width: u32,
    pub height: u32,
    pub pixels_per_scanline: u32,
    pub pixel_format: FramebufferPixelFormat,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AcpiRsdpInput {
    pub physical_start: u64,
    pub byte_len: u64,
}

/// Physical references to values that the kernel will read after firmware boot services are gone.
pub struct BootInfoInput<'a> {
    pub phase: FirmwarePhase,
    pub boot_info_storage: HandoffAllocation,
    pub memory_map_storage: HandoffAllocation,
    pub module_table_storage: HandoffAllocation,
    pub memory_map: &'a [UefiMemoryDescriptor],
    /// Already canonicalized by the modules lane; this module never creates or orders modules.
    pub modules: &'a [DwBootModuleV1],
    pub acpi_rsdp: Option<AcpiRsdpInput>,
    pub framebuffer: Option<FramebufferInput>,
    pub command_line: Option<CommandLineInput>,
    pub entropy: Option<EntropyInput>,
}

pub struct BootInfoOutput<'a> {
    pub boot_info: &'a mut DwBootInfoV1,
    pub memory_map: &'a mut [DwBootMemoryRangeV1],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BootInfoError {
    ExitBootServicesIncomplete,
    AllocationUnavailable,
    AllocationReleased,
    EmptyMemoryMap,
    OutputLengthMismatch,
    PhysicalAddressUnaligned,
    EmptyRange,
    RangeOverflow,
    MemoryMapOverlap,
    HandoffStorageNotReserved,
    HandoffStorageOverlap,
    MissingBootstrapModule,
    MissingBootfsModule,
    DuplicateModule,
    ModuleMustBeReadOnly,
    UnsupportedModuleFlags,
    CommandLineTooLarge,
    InvalidOptionalAddress,
    InvalidAcpiRsdp,
    InvalidFramebuffer,
    InvalidEntropy,
    InvalidHeader,
    InvalidReservedField,
    InvalidTableReference,
    UnknownMemoryKind,
}

pub fn build(
    input: &BootInfoInput<'_>,
    output: &mut BootInfoOutput<'_>,
) -> Result<(), BootInfoError> {
    if input.phase != FirmwarePhase::AfterExitBootServices {
        return Err(BootInfoError::ExitBootServicesIncomplete);
    }
    if input.memory_map.is_empty() {
        return Err(BootInfoError::EmptyMemoryMap);
    }
    if input.memory_map.len() != output.memory_map.len() {
        return Err(BootInfoError::OutputLengthMismatch);
    }
    let memory_map_entry_count =
        u64::try_from(input.memory_map.len()).map_err(|_| BootInfoError::RangeOverflow)?;
    let module_count =
        u64::try_from(input.modules.len()).map_err(|_| BootInfoError::RangeOverflow)?;

    validate_retained(&input.boot_info_storage, u64::from(DW_BOOT_INFO_V1_SIZE))?;
    validate_table_storage(
        &input.memory_map_storage,
        input.memory_map.len(),
        u64::from(DW_BOOT_MEMORY_RANGE_V1_SIZE),
        align_of::<DwBootMemoryRangeV1>() as u64,
    )?;
    validate_table_storage(
        &input.module_table_storage,
        input.modules.len(),
        u64::from(DW_BOOT_MODULE_V1_SIZE),
        align_of::<DwBootModuleV1>() as u64,
    )?;

    normalize_memory_map(input.memory_map, output.memory_map)?;
    validate_memory_map(output.memory_map)?;
    validate_reserved_storage(&input.boot_info_storage, output.memory_map)?;
    validate_reserved_storage(&input.memory_map_storage, output.memory_map)?;
    validate_reserved_storage(&input.module_table_storage, output.memory_map)?;
    validate_modules(input.modules)?;
    for module in input.modules {
        validate_reserved_range(
            module.physical_start,
            module_allocation_len(module.byte_len)?,
            output.memory_map,
        )?;
    }
    let command_line = build_command_line(input.command_line, output.memory_map)?;
    let entropy = build_entropy(input.entropy, output.memory_map)?;
    let (flags, framebuffer) = build_framebuffer(input.framebuffer, output.memory_map)?;
    let acpi_rsdp_physical_address = build_acpi_rsdp(input.acpi_rsdp, output.memory_map)?;
    validate_distinct_handoff_ranges(input, command_line, input.entropy)?;

    let info = DwBootInfoV1 {
        size: DW_BOOT_INFO_V1_SIZE,
        version: DW_BOOT_INFO_V1_VERSION,
        flags,
        memory_map_physical_start: input.memory_map_storage.physical_start,
        memory_map_entry_count,
        memory_map_entry_size: DW_BOOT_MEMORY_RANGE_V1_SIZE,
        reserved0: 0,
        modules_physical_start: input.module_table_storage.physical_start,
        module_count,
        module_entry_size: DW_BOOT_MODULE_V1_SIZE,
        reserved1: 0,
        acpi_rsdp_physical_address,
        framebuffer,
        command_line_physical_start: command_line.storage.physical_start,
        command_line_byte_len: command_line.byte_len,
        entropy,
        reserved: [0; 8],
    };
    validate_boot_info(&info)?;
    validate_tables(&info, output.memory_map, input.modules)?;
    *output.boot_info = info;
    Ok(())
}

/// Validates the generated BootInfo header and embedded optional descriptors.
pub fn validate_boot_info(info: &DwBootInfoV1) -> Result<(), BootInfoError> {
    if info.size != DW_BOOT_INFO_V1_SIZE || info.version != DW_BOOT_INFO_V1_VERSION {
        return Err(BootInfoError::InvalidHeader);
    }
    if info.reserved0 != 0 || info.reserved1 != 0 || info.reserved.iter().any(|value| *value != 0) {
        return Err(BootInfoError::InvalidReservedField);
    }
    if info.flags.0 & !DW_BOOT_INFO_FLAG_FRAMEBUFFER_PRESENT.0 != 0 {
        return Err(BootInfoError::InvalidHeader);
    }
    if info.acpi_rsdp_physical_address != 0
        && !info
            .acpi_rsdp_physical_address
            .is_multiple_of(ACPI_RSDP_ALIGNMENT)
    {
        return Err(BootInfoError::InvalidAcpiRsdp);
    }
    validate_table_reference(
        info.memory_map_physical_start,
        info.memory_map_entry_count,
        info.memory_map_entry_size,
        DW_BOOT_MEMORY_RANGE_V1_SIZE,
        align_of::<DwBootMemoryRangeV1>() as u64,
    )?;
    validate_table_reference(
        info.modules_physical_start,
        info.module_count,
        info.module_entry_size,
        DW_BOOT_MODULE_V1_SIZE,
        align_of::<DwBootModuleV1>() as u64,
    )?;
    if info.command_line_byte_len > MAX_COMMAND_LINE_BYTES {
        return Err(BootInfoError::CommandLineTooLarge);
    }
    validate_byte_reference(
        info.command_line_physical_start,
        info.command_line_byte_len,
        MAX_COMMAND_LINE_BYTES,
    )?;

    let framebuffer_present = info.flags.0 & DW_BOOT_INFO_FLAG_FRAMEBUFFER_PRESENT.0 != 0;
    if framebuffer_present {
        validate_framebuffer(&info.framebuffer)?;
    } else if info.framebuffer != DwBootFramebufferV1::default() {
        return Err(BootInfoError::InvalidFramebuffer);
    }

    if info.entropy != DwBootEntropyV1::default() {
        validate_entropy(&info.entropy)?;
    }
    Ok(())
}

/// Validates the generated tables that a `DwBootInfoV1` references.
pub fn validate_tables(
    info: &DwBootInfoV1,
    memory_map: &[DwBootMemoryRangeV1],
    modules: &[DwBootModuleV1],
) -> Result<(), BootInfoError> {
    if info.memory_map_entry_count
        != u64::try_from(memory_map.len()).map_err(|_| BootInfoError::RangeOverflow)?
        || info.module_count
            != u64::try_from(modules.len()).map_err(|_| BootInfoError::RangeOverflow)?
    {
        return Err(BootInfoError::InvalidTableReference);
    }
    validate_memory_map(memory_map)?;
    if info.acpi_rsdp_physical_address != 0
        && !range_has_kind(
            info.acpi_rsdp_physical_address,
            ACPI_RSDP_MINIMUM_BYTES,
            memory_map,
            |kind| {
                kind == DW_BOOT_MEMORY_KIND_ACPI_RECLAIM
                    || kind == DW_BOOT_MEMORY_KIND_ACPI_NVS
                    || kind == DW_BOOT_MEMORY_KIND_RESERVED
            },
        )?
    {
        return Err(BootInfoError::InvalidAcpiRsdp);
    }
    validate_modules(modules)
}

fn normalize_memory_map(
    input: &[UefiMemoryDescriptor],
    output: &mut [DwBootMemoryRangeV1],
) -> Result<(), BootInfoError> {
    for (descriptor, entry) in input.iter().zip(output.iter_mut()) {
        validate_page_range(descriptor.physical_start, descriptor.page_count)?;
        *entry = DwBootMemoryRangeV1 {
            size: DW_BOOT_MEMORY_RANGE_V1_SIZE,
            version: DW_BOOT_MEMORY_RANGE_V1_VERSION,
            kind: normalize_memory_kind(descriptor.kind),
            reserved0: 0,
            physical_start: descriptor.physical_start,
            page_count: descriptor.page_count,
            firmware_attributes: descriptor.firmware_attributes,
            reserved: [0; 3],
        };
    }
    Ok(())
}

fn normalize_memory_kind(kind: UefiMemoryKind) -> DwBootMemoryKind {
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

fn build_command_line(
    command_line: Option<CommandLineInput>,
    memory_map: &[DwBootMemoryRangeV1],
) -> Result<CommandLineInput, BootInfoError> {
    let Some(command_line) = command_line else {
        return Ok(CommandLineInput {
            storage: HandoffAllocation {
                physical_start: 0,
                byte_len: 0,
                lifetime: AllocationLifetime::RetainedUntilKernelCopy,
            },
            byte_len: 0,
        });
    };
    validate_retained(&command_line.storage, command_line.byte_len)?;
    if command_line.byte_len > MAX_COMMAND_LINE_BYTES {
        return Err(BootInfoError::CommandLineTooLarge);
    }
    if command_line.byte_len == 0 {
        return Err(BootInfoError::InvalidOptionalAddress);
    }
    validate_reserved_storage(&command_line.storage, memory_map)?;
    Ok(command_line)
}

fn build_entropy(
    entropy: Option<EntropyInput>,
    memory_map: &[DwBootMemoryRangeV1],
) -> Result<DwBootEntropyV1, BootInfoError> {
    let Some(entropy) = entropy else {
        return Ok(DwBootEntropyV1::default());
    };
    if entropy.byte_len == 0
        || entropy.byte_len > MAX_ENTROPY_BYTES
        || entropy.byte_len > entropy.storage.byte_len
    {
        return Err(BootInfoError::InvalidEntropy);
    }
    validate_retained(&entropy.storage, entropy.byte_len)?;
    validate_reserved_storage(&entropy.storage, memory_map)?;
    let source = match entropy.source {
        FirmwareEntropySource::UefiRngProtocol => DW_BOOT_ENTROPY_SOURCE_UEFI_RNG_PROTOCOL,
        FirmwareEntropySource::FirmwarePlatform => DW_BOOT_ENTROPY_SOURCE_FIRMWARE_PLATFORM,
        FirmwareEntropySource::MixedFirmware => DW_BOOT_ENTROPY_SOURCE_MIXED_FIRMWARE,
    };
    let flags = if entropy.conditioned {
        DW_BOOT_ENTROPY_FLAG_CONDITIONED
    } else {
        DwBootEntropyFlags(0)
    };
    Ok(DwBootEntropyV1 {
        size: DW_BOOT_ENTROPY_V1_SIZE,
        version: DW_BOOT_ENTROPY_V1_VERSION,
        source,
        flags,
        physical_start: entropy.storage.physical_start,
        byte_len: entropy.byte_len,
        reserved: [0; 4],
    })
}

fn build_acpi_rsdp(
    rsdp: Option<AcpiRsdpInput>,
    memory_map: &[DwBootMemoryRangeV1],
) -> Result<u64, BootInfoError> {
    let Some(rsdp) = rsdp else {
        return Ok(0);
    };
    if rsdp.physical_start == 0
        || !rsdp.physical_start.is_multiple_of(ACPI_RSDP_ALIGNMENT)
        || rsdp.byte_len < ACPI_RSDP_MINIMUM_BYTES
        || rsdp.physical_start.checked_add(rsdp.byte_len).is_none()
        || !range_has_kind(rsdp.physical_start, rsdp.byte_len, memory_map, |kind| {
            kind == DW_BOOT_MEMORY_KIND_ACPI_RECLAIM
                || kind == DW_BOOT_MEMORY_KIND_ACPI_NVS
                || kind == DW_BOOT_MEMORY_KIND_RESERVED
        })?
    {
        return Err(BootInfoError::InvalidAcpiRsdp);
    }
    Ok(rsdp.physical_start)
}

fn validate_distinct_handoff_ranges(
    input: &BootInfoInput<'_>,
    command_line: CommandLineInput,
    entropy: Option<EntropyInput>,
) -> Result<(), BootInfoError> {
    let fixed = [
        input.boot_info_storage,
        input.memory_map_storage,
        input.module_table_storage,
    ];
    for (index, left) in fixed.iter().enumerate() {
        for right in fixed.iter().skip(index + 1) {
            if ranges_overlap(
                left.physical_start,
                left.byte_len,
                right.physical_start,
                right.byte_len,
            )? {
                return Err(BootInfoError::HandoffStorageOverlap);
            }
        }
        for module in input.modules {
            if ranges_overlap(
                left.physical_start,
                left.byte_len,
                module.physical_start,
                module_allocation_len(module.byte_len)?,
            )? {
                return Err(BootInfoError::HandoffStorageOverlap);
            }
        }
    }
    if command_line.byte_len != 0 {
        for left in fixed {
            if ranges_overlap(
                left.physical_start,
                left.byte_len,
                command_line.storage.physical_start,
                command_line.storage.byte_len,
            )? {
                return Err(BootInfoError::HandoffStorageOverlap);
            }
        }
        for module in input.modules {
            if ranges_overlap(
                command_line.storage.physical_start,
                command_line.storage.byte_len,
                module.physical_start,
                module_allocation_len(module.byte_len)?,
            )? {
                return Err(BootInfoError::HandoffStorageOverlap);
            }
        }
    }
    if let Some(entropy) = entropy {
        for left in fixed {
            if ranges_overlap(
                left.physical_start,
                left.byte_len,
                entropy.storage.physical_start,
                entropy.storage.byte_len,
            )? {
                return Err(BootInfoError::HandoffStorageOverlap);
            }
        }
        for module in input.modules {
            if ranges_overlap(
                entropy.storage.physical_start,
                entropy.storage.byte_len,
                module.physical_start,
                module_allocation_len(module.byte_len)?,
            )? {
                return Err(BootInfoError::HandoffStorageOverlap);
            }
        }
        if command_line.byte_len != 0
            && ranges_overlap(
                command_line.storage.physical_start,
                command_line.storage.byte_len,
                entropy.storage.physical_start,
                entropy.storage.byte_len,
            )?
        {
            return Err(BootInfoError::HandoffStorageOverlap);
        }
    }
    Ok(())
}

fn build_framebuffer(
    framebuffer: Option<FramebufferInput>,
    memory_map: &[DwBootMemoryRangeV1],
) -> Result<(DwBootInfoFlags, DwBootFramebufferV1), BootInfoError> {
    let Some(framebuffer) = framebuffer else {
        return Ok((DwBootInfoFlags(0), DwBootFramebufferV1::default()));
    };
    let descriptor = framebuffer_descriptor(framebuffer)?;
    if !range_is_framebuffer_backed(descriptor.physical_start, descriptor.byte_len, memory_map)? {
        return Err(BootInfoError::HandoffStorageNotReserved);
    }
    Ok((DW_BOOT_INFO_FLAG_FRAMEBUFFER_PRESENT, descriptor))
}

fn framebuffer_descriptor(
    framebuffer: FramebufferInput,
) -> Result<DwBootFramebufferV1, BootInfoError> {
    if framebuffer.width == 0
        || framebuffer.height == 0
        || framebuffer.pixels_per_scanline < framebuffer.width
    {
        return Err(BootInfoError::InvalidFramebuffer);
    }
    let bytes_per_line = u64::from(framebuffer.pixels_per_scanline)
        .checked_mul(4)
        .ok_or(BootInfoError::InvalidFramebuffer)?;
    let required_len = bytes_per_line
        .checked_mul(u64::from(framebuffer.height))
        .ok_or(BootInfoError::InvalidFramebuffer)?;
    if framebuffer.byte_len < required_len
        || framebuffer
            .physical_start
            .checked_add(framebuffer.byte_len)
            .is_none()
    {
        return Err(BootInfoError::InvalidFramebuffer);
    }
    let (pixel_format, red_mask, green_mask, blue_mask, reserved_mask) =
        match framebuffer.pixel_format {
            FramebufferPixelFormat::Rgbx8 => (DW_BOOT_PIXEL_FORMAT_RGBX8, 0, 0, 0, 0),
            FramebufferPixelFormat::Bgrx8 => (DW_BOOT_PIXEL_FORMAT_BGRX8, 0, 0, 0, 0),
            FramebufferPixelFormat::Bitmask {
                red_mask,
                green_mask,
                blue_mask,
                reserved_mask,
            } => {
                if red_mask == 0
                    || green_mask == 0
                    || blue_mask == 0
                    || masks_overlap(red_mask, green_mask, blue_mask, reserved_mask)
                {
                    return Err(BootInfoError::InvalidFramebuffer);
                }
                (
                    DW_BOOT_PIXEL_FORMAT_BITMASK,
                    red_mask,
                    green_mask,
                    blue_mask,
                    reserved_mask,
                )
            }
        };
    Ok(DwBootFramebufferV1 {
        size: DW_BOOT_FRAMEBUFFER_V1_SIZE,
        version: DW_BOOT_FRAMEBUFFER_V1_VERSION,
        flags: DW_BOOT_FRAMEBUFFER_FLAG_LINEAR,
        pixel_format,
        physical_start: framebuffer.physical_start,
        byte_len: framebuffer.byte_len,
        width: framebuffer.width,
        height: framebuffer.height,
        pixels_per_scanline: framebuffer.pixels_per_scanline,
        reserved0: 0,
        red_mask,
        green_mask,
        blue_mask,
        reserved_mask,
        reserved: [0; 4],
    })
}

fn validate_memory_map(memory_map: &[DwBootMemoryRangeV1]) -> Result<(), BootInfoError> {
    let mut previous_end = 0;
    for (index, entry) in memory_map.iter().enumerate() {
        if entry.size != DW_BOOT_MEMORY_RANGE_V1_SIZE
            || entry.version != DW_BOOT_MEMORY_RANGE_V1_VERSION
        {
            return Err(BootInfoError::InvalidHeader);
        }
        if entry.reserved0 != 0 || entry.reserved.iter().any(|value| *value != 0) {
            return Err(BootInfoError::InvalidReservedField);
        }
        if !is_known_memory_kind(entry.kind) {
            return Err(BootInfoError::UnknownMemoryKind);
        }
        validate_page_range(entry.physical_start, entry.page_count)?;
        let end = page_range_end(entry.physical_start, entry.page_count)?;
        if index > 0 && entry.physical_start < previous_end {
            return Err(BootInfoError::MemoryMapOverlap);
        }
        previous_end = end;
    }
    Ok(())
}

fn validate_modules(modules: &[DwBootModuleV1]) -> Result<(), BootInfoError> {
    let mut bootstrap_seen = false;
    let mut bootfs_seen = false;
    for (index, module) in modules.iter().enumerate() {
        if module.size != DW_BOOT_MODULE_V1_SIZE || module.version != DW_BOOT_MODULE_V1_VERSION {
            return Err(BootInfoError::InvalidHeader);
        }
        if module.reserved.iter().any(|value| *value != 0) {
            return Err(BootInfoError::InvalidReservedField);
        }
        validate_module_range(module.physical_start, module.byte_len)?;
        if module.flags.0 & !DW_BOOT_MODULE_FLAG_READ_ONLY.0 != 0 {
            return Err(BootInfoError::UnsupportedModuleFlags);
        }
        if module.kind == DW_BOOT_MODULE_KIND_WYRMROOT_BOOTSTRAP {
            if bootstrap_seen {
                return Err(BootInfoError::DuplicateModule);
            }
            bootstrap_seen = true;
        } else if module.kind == DW_BOOT_MODULE_KIND_WYRMROOT_BOOTFS {
            if bootfs_seen {
                return Err(BootInfoError::DuplicateModule);
            }
            if module.flags.0 & DW_BOOT_MODULE_FLAG_READ_ONLY.0 == 0 {
                return Err(BootInfoError::ModuleMustBeReadOnly);
            }
            bootfs_seen = true;
        } else {
            return Err(BootInfoError::InvalidHeader);
        }
        for other in modules.iter().skip(index + 1) {
            if ranges_overlap(
                module.physical_start,
                module_allocation_len(module.byte_len)?,
                other.physical_start,
                module_allocation_len(other.byte_len)?,
            )? {
                return Err(BootInfoError::HandoffStorageOverlap);
            }
        }
    }
    if !bootstrap_seen {
        return Err(BootInfoError::MissingBootstrapModule);
    }
    if !bootfs_seen {
        return Err(BootInfoError::MissingBootfsModule);
    }
    Ok(())
}

fn is_known_memory_kind(kind: DwBootMemoryKind) -> bool {
    kind == DW_BOOT_MEMORY_KIND_USABLE
        || kind == DW_BOOT_MEMORY_KIND_RESERVED
        || kind == DW_BOOT_MEMORY_KIND_ACPI_RECLAIM
        || kind == DW_BOOT_MEMORY_KIND_ACPI_NVS
        || kind == DW_BOOT_MEMORY_KIND_MMIO
        || kind == DW_BOOT_MEMORY_KIND_RUNTIME_SERVICES
        || kind == DW_BOOT_MEMORY_KIND_UNUSABLE
}

fn validate_framebuffer(framebuffer: &DwBootFramebufferV1) -> Result<(), BootInfoError> {
    if framebuffer.size != DW_BOOT_FRAMEBUFFER_V1_SIZE
        || framebuffer.version != DW_BOOT_FRAMEBUFFER_V1_VERSION
        || framebuffer.flags != DW_BOOT_FRAMEBUFFER_FLAG_LINEAR
        || framebuffer.reserved0 != 0
        || framebuffer.reserved.iter().any(|value| *value != 0)
    {
        return Err(BootInfoError::InvalidFramebuffer);
    }
    let input = match framebuffer.pixel_format {
        format if format == DW_BOOT_PIXEL_FORMAT_RGBX8 => FramebufferPixelFormat::Rgbx8,
        format if format == DW_BOOT_PIXEL_FORMAT_BGRX8 => FramebufferPixelFormat::Bgrx8,
        format if format == DW_BOOT_PIXEL_FORMAT_BITMASK => FramebufferPixelFormat::Bitmask {
            red_mask: framebuffer.red_mask,
            green_mask: framebuffer.green_mask,
            blue_mask: framebuffer.blue_mask,
            reserved_mask: framebuffer.reserved_mask,
        },
        _ => return Err(BootInfoError::InvalidFramebuffer),
    };
    if !matches!(input, FramebufferPixelFormat::Bitmask { .. })
        && (framebuffer.red_mask != 0
            || framebuffer.green_mask != 0
            || framebuffer.blue_mask != 0
            || framebuffer.reserved_mask != 0)
    {
        return Err(BootInfoError::InvalidFramebuffer);
    }
    framebuffer_descriptor(FramebufferInput {
        physical_start: framebuffer.physical_start,
        byte_len: framebuffer.byte_len,
        width: framebuffer.width,
        height: framebuffer.height,
        pixels_per_scanline: framebuffer.pixels_per_scanline,
        pixel_format: input,
    })
    .map(|_| ())
}

fn validate_entropy(entropy: &DwBootEntropyV1) -> Result<(), BootInfoError> {
    if entropy.size != DW_BOOT_ENTROPY_V1_SIZE
        || entropy.version != DW_BOOT_ENTROPY_V1_VERSION
        || entropy.reserved.iter().any(|value| *value != 0)
        || entropy.byte_len == 0
        || entropy.byte_len > MAX_ENTROPY_BYTES
        || entropy.physical_start == 0
        || !entropy
            .physical_start
            .is_multiple_of(u64::from(DW_BOOT_BASE_PAGE_SIZE))
        || entropy
            .physical_start
            .checked_add(entropy.byte_len)
            .is_none()
        || entropy.flags.0 & !DW_BOOT_ENTROPY_FLAG_CONDITIONED.0 != 0
    {
        return Err(BootInfoError::InvalidEntropy);
    }
    if entropy.source != DW_BOOT_ENTROPY_SOURCE_UEFI_RNG_PROTOCOL
        && entropy.source != DW_BOOT_ENTROPY_SOURCE_FIRMWARE_PLATFORM
        && entropy.source != DW_BOOT_ENTROPY_SOURCE_MIXED_FIRMWARE
    {
        return Err(BootInfoError::InvalidEntropy);
    }
    Ok(())
}

fn validate_retained(
    allocation: &HandoffAllocation,
    minimum_len: u64,
) -> Result<(), BootInfoError> {
    match allocation.lifetime {
        AllocationLifetime::AllocationFailed => return Err(BootInfoError::AllocationUnavailable),
        AllocationLifetime::ReleasedBeforeHandoff => return Err(BootInfoError::AllocationReleased),
        AllocationLifetime::RetainedUntilKernelCopy => {}
    }
    if allocation.physical_start == 0 || allocation.byte_len < minimum_len {
        return Err(BootInfoError::EmptyRange);
    }
    if allocation
        .physical_start
        .checked_add(allocation.byte_len)
        .is_none()
    {
        return Err(BootInfoError::RangeOverflow);
    }
    Ok(())
}

fn validate_table_storage(
    allocation: &HandoffAllocation,
    entry_count: usize,
    entry_size: u64,
    alignment: u64,
) -> Result<(), BootInfoError> {
    let required = u64::try_from(entry_count)
        .map_err(|_| BootInfoError::RangeOverflow)?
        .checked_mul(entry_size)
        .ok_or(BootInfoError::RangeOverflow)?;
    validate_retained(allocation, required)?;
    if !allocation.physical_start.is_multiple_of(alignment) {
        return Err(BootInfoError::PhysicalAddressUnaligned);
    }
    Ok(())
}

fn validate_table_reference(
    physical_start: u64,
    count: u64,
    entry_size: u32,
    expected_size: u32,
    alignment: u64,
) -> Result<(), BootInfoError> {
    if count == 0
        || entry_size != expected_size
        || physical_start == 0
        || !physical_start.is_multiple_of(alignment)
    {
        return Err(BootInfoError::InvalidTableReference);
    }
    let byte_len = count
        .checked_mul(u64::from(entry_size))
        .ok_or(BootInfoError::RangeOverflow)?;
    physical_start
        .checked_add(byte_len)
        .ok_or(BootInfoError::RangeOverflow)?;
    Ok(())
}

fn validate_byte_reference(
    physical_start: u64,
    byte_len: u64,
    maximum_len: u64,
) -> Result<(), BootInfoError> {
    if byte_len > maximum_len
        || (byte_len == 0 && physical_start != 0)
        || (byte_len != 0 && physical_start == 0)
    {
        return Err(BootInfoError::InvalidOptionalAddress);
    }
    if byte_len != 0 && physical_start.checked_add(byte_len).is_none() {
        return Err(BootInfoError::RangeOverflow);
    }
    Ok(())
}

fn validate_page_range(physical_start: u64, page_count: u64) -> Result<(), BootInfoError> {
    if page_count == 0 {
        return Err(BootInfoError::EmptyRange);
    }
    if !physical_start.is_multiple_of(u64::from(DW_BOOT_BASE_PAGE_SIZE)) {
        return Err(BootInfoError::PhysicalAddressUnaligned);
    }
    page_range_end(physical_start, page_count).map(|_| ())
}

fn page_range_end(physical_start: u64, page_count: u64) -> Result<u64, BootInfoError> {
    let byte_len = page_count
        .checked_mul(u64::from(DW_BOOT_BASE_PAGE_SIZE))
        .ok_or(BootInfoError::RangeOverflow)?;
    physical_start
        .checked_add(byte_len)
        .ok_or(BootInfoError::RangeOverflow)
}

fn validate_module_range(physical_start: u64, byte_len: u64) -> Result<(), BootInfoError> {
    if byte_len == 0 {
        return Err(BootInfoError::EmptyRange);
    }
    if physical_start == 0 || !physical_start.is_multiple_of(u64::from(DW_BOOT_BASE_PAGE_SIZE)) {
        return Err(BootInfoError::PhysicalAddressUnaligned);
    }
    physical_start
        .checked_add(byte_len)
        .ok_or(BootInfoError::RangeOverflow)?;
    Ok(())
}

fn module_allocation_len(byte_len: u64) -> Result<u64, BootInfoError> {
    byte_len
        .checked_add(u64::from(DW_BOOT_BASE_PAGE_SIZE) - 1)
        .ok_or(BootInfoError::RangeOverflow)
        .map(|rounded| {
            rounded / u64::from(DW_BOOT_BASE_PAGE_SIZE) * u64::from(DW_BOOT_BASE_PAGE_SIZE)
        })
}

fn validate_reserved_storage(
    allocation: &HandoffAllocation,
    memory_map: &[DwBootMemoryRangeV1],
) -> Result<(), BootInfoError> {
    if range_has_kind(
        allocation.physical_start,
        allocation.byte_len,
        memory_map,
        |kind| kind == DW_BOOT_MEMORY_KIND_RESERVED,
    )? {
        Ok(())
    } else {
        Err(BootInfoError::HandoffStorageNotReserved)
    }
}

fn validate_reserved_range(
    physical_start: u64,
    byte_len: u64,
    memory_map: &[DwBootMemoryRangeV1],
) -> Result<(), BootInfoError> {
    if range_has_kind(physical_start, byte_len, memory_map, |kind| {
        kind == DW_BOOT_MEMORY_KIND_RESERVED
    })? {
        Ok(())
    } else {
        Err(BootInfoError::HandoffStorageNotReserved)
    }
}

fn range_is_framebuffer_backed(
    physical_start: u64,
    byte_len: u64,
    memory_map: &[DwBootMemoryRangeV1],
) -> Result<bool, BootInfoError> {
    range_has_kind(physical_start, byte_len, memory_map, |kind| {
        kind == DW_BOOT_MEMORY_KIND_RESERVED || kind == DW_BOOT_MEMORY_KIND_MMIO
    })
}

fn range_has_kind(
    physical_start: u64,
    byte_len: u64,
    memory_map: &[DwBootMemoryRangeV1],
    accepts: impl Fn(DwBootMemoryKind) -> bool,
) -> Result<bool, BootInfoError> {
    let end = physical_start
        .checked_add(byte_len)
        .ok_or(BootInfoError::RangeOverflow)?;
    for entry in memory_map {
        let entry_end = page_range_end(entry.physical_start, entry.page_count)?;
        if accepts(entry.kind) && physical_start >= entry.physical_start && end <= entry_end {
            return Ok(true);
        }
    }
    Ok(false)
}

fn ranges_overlap(
    left_start: u64,
    left_len: u64,
    right_start: u64,
    right_len: u64,
) -> Result<bool, BootInfoError> {
    let left_end = left_start
        .checked_add(left_len)
        .ok_or(BootInfoError::RangeOverflow)?;
    let right_end = right_start
        .checked_add(right_len)
        .ok_or(BootInfoError::RangeOverflow)?;
    Ok(left_start < right_end && right_start < left_end)
}

fn masks_overlap(red: u32, green: u32, blue: u32, reserved: u32) -> bool {
    (red & green) != 0
        || (red & blue) != 0
        || (red & reserved) != 0
        || (green & blue) != 0
        || (green & reserved) != 0
        || (blue & reserved) != 0
}

const _: () = assert!(size_of::<DwBootInfoV1>() as u32 == DW_BOOT_INFO_V1_SIZE);
