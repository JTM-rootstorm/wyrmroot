//! Loader file intake, artifact retention, entropy, ACPI and framebuffer discovery.

use super::*;

pub(crate) fn read_loader_files() -> Result<LoadedFiles, FirmwarePreparationError> {
    let mut filesystem: ScopedProtocol<_> = boot::get_image_file_system(boot::image_handle())
        .map_err(|_| FirmwarePreparationError::FileSystem)?;
    let mut root = filesystem
        .open_volume()
        .map_err(|_| FirmwarePreparationError::FileSystem)?;

    let kernel_path = firmware_path(KERNEL_PATH)?;
    let bootstrap_path = firmware_path(BOOTSTRAP_PATH)?;
    let bootfs_path = firmware_path(BOOTFS_PATH)?;
    let boot_device_table_path = firmware_path(BOOT_DEVICE_TABLE_PATH)?;
    let config_path = firmware_path(CONFIG_PATH)?;

    let kernel = read_bounded_file(&mut root, &kernel_path, MAX_KERNEL_ARTIFACT_BYTES)?;
    let bootstrap = read_bounded_file(&mut root, &bootstrap_path, MAX_BOOTSTRAP_ARTIFACT_BYTES)?;
    let bootfs = read_bounded_file(&mut root, &bootfs_path, MAX_BOOTFS_ARTIFACT_BYTES)?;
    let boot_device_table = read_optional_bounded_file(
        &mut root,
        &boot_device_table_path,
        super::super::MAX_BOOT_DEVICE_TABLE_ARTIFACT_BYTES,
    )?;
    total_artifact_bytes([
        kernel.len(),
        bootstrap.len(),
        bootfs.len(),
        boot_device_table.as_ref().map_or(0, Vec::len),
    ])
    .map_err(FirmwarePreparationError::Artifact)?;
    let config = read_optional_bounded_file(&mut root, &config_path, MAX_CONFIG_BYTES)?;

    Ok(LoadedFiles {
        kernel,
        bootstrap,
        bootfs,
        boot_device_table,
        config,
    })
}

pub(crate) fn firmware_path(path: &str) -> Result<UefiPathBuf, FirmwarePreparationError> {
    let encoded = CString16::try_from(path).map_err(|_| FirmwarePreparationError::FileSystem)?;
    Ok(UefiPathBuf::from(encoded))
}

pub(crate) fn read_bounded_file(
    root: &mut Directory,
    path: &UefiPath,
    cap: usize,
) -> Result<Vec<u8>, FirmwarePreparationError> {
    let file = root
        .open(path.to_cstr16(), FileMode::Read, FileAttribute::empty())
        .map_err(|_| FirmwarePreparationError::FileSystem)?;
    read_opened_bounded_file(file, cap)
}

pub(crate) fn read_optional_bounded_file(
    root: &mut Directory,
    path: &UefiPath,
    cap: usize,
) -> Result<Option<Vec<u8>>, FirmwarePreparationError> {
    let file = match root.open(path.to_cstr16(), FileMode::Read, FileAttribute::empty()) {
        Ok(file) => file,
        Err(error) if error.status() == Status::NOT_FOUND => return Ok(None),
        Err(_) => return Err(FirmwarePreparationError::FileSystem),
    };
    read_opened_bounded_file(file, cap).map(Some)
}

pub(crate) fn read_opened_bounded_file(
    file: uefi::proto::media::file::FileHandle,
    cap: usize,
) -> Result<Vec<u8>, FirmwarePreparationError> {
    let mut file = file
        .into_regular_file()
        .ok_or(FirmwarePreparationError::FileSystem)?;
    let info = file
        .get_boxed_info::<FileInfo>()
        .map_err(|_| FirmwarePreparationError::FileSystem)?;
    let byte_len =
        bounded_artifact_len(info.file_size(), cap).map_err(FirmwarePreparationError::Artifact)?;

    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(byte_len)
        .map_err(|_| FirmwarePreparationError::Allocation)?;
    // `try_reserve_exact` has already reserved `byte_len`, so this resize
    // cannot request another allocation. The zero initialization prevents
    // an unread tail from ever becoming observable on a short read.
    bytes.resize(byte_len, 0);
    let read_len = file
        .read(&mut bytes)
        .map_err(|_| FirmwarePreparationError::FileSystem)?;
    if read_len != byte_len {
        return Err(FirmwarePreparationError::ShortRead);
    }
    Ok(bytes)
}

pub(crate) fn retain_artifacts(
    kernel: &[u8],
    bootstrap: &[u8],
    bootfs: &[u8],
    boot_device_table: Option<&[u8]>,
    acpi_rsdp: Option<AcpiRsdp>,
    framebuffer: Option<FramebufferMetadata>,
    entropy: CollectedEntropy,
) -> Result<PreparedPreExit, FirmwarePreparationError> {
    let kernel = match retain_payload(kernel) {
        Ok(value) => value,
        Err(error) => {
            release_acpi(acpi_rsdp);
            return Err(error);
        }
    };
    let bootstrap = match retain_payload(bootstrap) {
        Ok(value) => value,
        Err(error) => {
            // SAFETY: no reference to the retained allocation escaped.
            unsafe { kernel.release() };
            release_acpi(acpi_rsdp);
            return Err(error);
        }
    };
    let bootfs = match retain_payload(bootfs) {
        Ok(value) => value,
        Err(error) => {
            // SAFETY: no reference to either retained allocation escaped.
            unsafe { bootstrap.release() };
            // SAFETY: no reference to either retained allocation escaped.
            unsafe { kernel.release() };
            release_acpi(acpi_rsdp);
            return Err(error);
        }
    };
    let boot_device_table = match boot_device_table.map(retain_payload).transpose() {
        Ok(value) => value,
        Err(error) => {
            // SAFETY: no reference to the retained allocations escaped.
            unsafe { bootfs.release() };
            // SAFETY: no reference to the retained allocations escaped.
            unsafe { bootstrap.release() };
            // SAFETY: no reference to the retained allocations escaped.
            unsafe { kernel.release() };
            release_acpi(acpi_rsdp);
            return Err(error);
        }
    };
    let entropy = match retain_entropy(entropy) {
        Ok(value) => value,
        Err(error) => {
            if let Some(boot_device_table) = boot_device_table {
                // SAFETY: no reference to the retained allocation escaped.
                unsafe { boot_device_table.release() };
            }
            // SAFETY: no reference to the retained allocations escaped.
            unsafe { bootfs.release() };
            // SAFETY: no reference to the retained allocations escaped.
            unsafe { bootstrap.release() };
            // SAFETY: no reference to the retained allocations escaped.
            unsafe { kernel.release() };
            release_acpi(acpi_rsdp);
            return Err(error);
        }
    };

    Ok(PreparedPreExit {
        kernel: Some(kernel),
        bootstrap,
        bootfs,
        boot_device_table,
        acpi_rsdp,
        framebuffer,
        entropy,
    })
}

pub(crate) fn release_acpi(acpi_rsdp: Option<AcpiRsdp>) {
    if let Some(acpi) = acpi_rsdp {
        // SAFETY: this cleanup path owns the copy and runs before ExitBootServices.
        unsafe { acpi.storage.release() };
    }
}

pub(crate) fn retain_payload(payload: &[u8]) -> Result<RetainedPages, FirmwarePreparationError> {
    let page_count =
        pages_for_payload(payload.len()).map_err(FirmwarePreparationError::Artifact)?;
    let mut retained = RetainedPages::allocate_zeroed_pages(page_count)?;
    // SAFETY: retained storage has exactly the checked full allocation
    // extent. The pure helper clears all slack before copying the payload.
    let allocation = unsafe {
        core::slice::from_raw_parts_mut(retained.ptr.as_ptr(), retained.allocation_byte_len)
    };
    super::super::initialize_payload_allocation(allocation, payload)
        .map_err(FirmwarePreparationError::Artifact)?;
    retained.payload_byte_len = payload.len();
    Ok(retained)
}

pub(crate) enum CollectedEntropy {
    Available([u8; 32]),
    Unavailable,
    Failed,
}

pub(crate) fn collect_entropy() -> CollectedEntropy {
    let Ok(handle) = boot::get_handle_for_protocol::<Rng>() else {
        return CollectedEntropy::Unavailable;
    };
    let Ok(mut rng) = boot::open_protocol_exclusive::<Rng>(handle) else {
        return CollectedEntropy::Unavailable;
    };
    let mut bytes = [0_u8; 32];
    match rng.get_rng(None, &mut bytes) {
        Ok(()) => CollectedEntropy::Available(bytes),
        Err(_) => CollectedEntropy::Failed,
    }
}

pub(crate) fn retain_entropy(
    entropy: CollectedEntropy,
) -> Result<FirmwareEntropy, FirmwarePreparationError> {
    match entropy {
        CollectedEntropy::Available(bytes) => retain_payload(&bytes).map(|storage| {
            FirmwareEntropy::Available {
                storage,
                source: FirmwareEntropySource::UefiRngProtocol,
                // The UEFI RNG protocol does not itself attest that the
                // bytes have passed Deepwyrm's conditioning policy.
                conditioned: false,
            }
        }),
        CollectedEntropy::Unavailable => Ok(FirmwareEntropy::Unavailable),
        CollectedEntropy::Failed => Ok(FirmwareEntropy::Failed),
    }
}

/// Reads the architectural MAXPHYADDR fact from CPUID. The returned value
/// is deliberately not a Deepwyrm layout constant: pass it to
/// `UefiPageTable::new`, which enforces the supported encoder range before
/// any physical address can be encoded.
#[cfg(all(target_arch = "x86_64", target_os = "uefi"))]
#[allow(dead_code)] // Called by the pending generated-policy table builder.
pub fn query_maxphyaddr() -> Result<u8, FirmwarePreparationError> {
    let maximum_extended_leaf = __cpuid(0x8000_0000).eax;
    if maximum_extended_leaf < 0x8000_0008 {
        return Err(FirmwarePreparationError::CpuMaxPhysicalAddressUnavailable);
    }
    let physical_bits = __cpuid(0x8000_0008).eax as u8;
    if physical_bits == 0 {
        return Err(FirmwarePreparationError::CpuMaxPhysicalAddressUnavailable);
    }
    Ok(physical_bits)
}

pub(crate) fn find_and_retain_acpi_rsdp() -> Result<Option<AcpiRsdp>, FirmwarePreparationError> {
    let selected = system::with_config_table(|entries| {
        super::super::select_rsdp_candidate(entries.iter().filter_map(|entry| {
            if entry.guid == ConfigTableEntry::ACPI2_GUID {
                Some(super::super::AcpiRsdpConfigCandidate {
                    kind: super::super::AcpiRsdpConfigKind::Acpi2,
                    physical_start: entry.address as u64,
                })
            } else if entry.guid == ConfigTableEntry::ACPI_GUID {
                Some(super::super::AcpiRsdpConfigCandidate {
                    kind: super::super::AcpiRsdpConfigKind::Acpi1,
                    physical_start: entry.address as u64,
                })
            } else {
                None
            }
        }))
    })
    .map_err(FirmwarePreparationError::Acpi)?;
    let Some(selected) = selected else {
        return Ok(None);
    };
    let address = usize::try_from(selected.physical_start)
        .map_err(|_| FirmwarePreparationError::Acpi(PreparationError::InvalidAcpiRsdpAddress))?;
    validate_acpi_rsdp_address(address).map_err(FirmwarePreparationError::Acpi)?;

    // SAFETY: UEFI owns configuration-table memory until handoff. The ACPI
    // configuration-table entry promises an RSDP at this address; only the
    // fixed v1 prefix is read to determine revision and extended byte length.
    let prefix = unsafe { core::slice::from_raw_parts(address as *const u8, ACPI_RSDP_V1_BYTES) };
    let byte_len = if prefix[15] < 2 {
        ACPI_RSDP_V1_BYTES
    } else {
        // SAFETY: this is the v2 length field, immediately following the v1 prefix.
        let header =
            unsafe { core::slice::from_raw_parts(address as *const u8, ACPI_RSDP_V2_MIN_BYTES) };
        usize::try_from(u32::from_le_bytes(
            header[20..24].try_into().expect("fixed slice length"),
        ))
        .map_err(|_| FirmwarePreparationError::Acpi(PreparationError::InvalidAcpiRsdpLength))?
    };
    if byte_len > MAX_ACPI_RSDP_BYTES {
        return Err(FirmwarePreparationError::Acpi(
            PreparationError::InvalidAcpiRsdpLength,
        ));
    }
    // SAFETY: the size is bounded above and was sourced from the validated
    // RSDP header while firmware configuration tables are still available.
    let bytes = unsafe { core::slice::from_raw_parts(address as *const u8, byte_len) };
    let AcpiRsdpLayout { revision, byte_len } =
        validate_acpi_rsdp(bytes).map_err(FirmwarePreparationError::Acpi)?;
    let storage = retain_payload(&bytes[..byte_len])?;
    Ok(Some(AcpiRsdp {
        storage,
        revision,
        byte_len,
    }))
}

pub(crate) fn find_framebuffer() -> Option<FramebufferMetadata> {
    let handle = boot::get_handle_for_protocol::<GraphicsOutput>().ok()?;
    let mut gop = boot::open_protocol_exclusive::<GraphicsOutput>(handle).ok()?;
    let info = gop.current_mode_info();
    let pixel_format = match info.pixel_format() {
        PixelFormat::Rgb => FramebufferPixelFormat::Rgb,
        PixelFormat::Bgr => FramebufferPixelFormat::Bgr,
        PixelFormat::Bitmask => {
            let masks = info.pixel_bitmask()?;
            FramebufferPixelFormat::Bitmask {
                red_mask: masks.red,
                green_mask: masks.green,
                blue_mask: masks.blue,
                reserved_mask: masks.reserved,
            }
        }
        PixelFormat::BltOnly => return None,
    };
    let mut framebuffer = gop.frame_buffer();
    let (width, height) = info.resolution();
    Some(FramebufferMetadata {
        physical_base: framebuffer.as_mut_ptr() as u64,
        byte_len: framebuffer.size() as u64,
        width: u32::try_from(width).ok()?,
        height: u32::try_from(height).ok()?,
        pixels_per_scan_line: u32::try_from(info.stride()).ok()?,
        pixel_format,
    })
}
