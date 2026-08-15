//! UEFI 0.39 firmware adapter for the WYR0 loader boundary.
//!
//! The host-testable normalization helpers in this file deliberately contain no
//! UEFI calls. Firmware work is feature-gated and keeps protocol guards and
//! allocator-backed values inside pre-exit scopes.

#[cfg(feature = "firmware")]
use wyrmroot_efi_loader::config::MAX_CONFIG_BYTES;
use wyrmroot_efi_loader::config::{ConfigError, LoaderConfig};

/// Optional, bounded loader configuration location.
///
/// Artifact locations remain fixed; this file can only select the currently
/// supported default profile.
pub const CONFIG_PATH: &str = "/EFI/Wyrmroot/loader.conf";

/// UEFI page size used solely for firmware page-allocation accounting.
pub const UEFI_PAGE_BYTES: usize = 4096;

/// Loader-local admission limit for the kernel ELF.
///
/// The phase plan does not yet prescribe artifact limits. This deliberately
/// conservative limit is a loader policy, not a kernel ABI constant.
pub const MAX_KERNEL_ARTIFACT_BYTES: usize = 32 * 1024 * 1024;

/// Loader-local admission limit for the primordial bootstrap ELF.
pub const MAX_BOOTSTRAP_ARTIFACT_BYTES: usize = 8 * 1024 * 1024;

/// Loader-local admission limit for the read-only bootfs image.
pub const MAX_BOOTFS_ARTIFACT_BYTES: usize = 32 * 1024 * 1024;

/// Maximum combined required-artifact input held before the handoff builder
/// consumes it. It is the exact sum of the per-artifact caps, preventing an
/// accidental future cap increase from silently admitting an unbounded total.
pub const MAX_TOTAL_ARTIFACT_BYTES: usize =
    MAX_KERNEL_ARTIFACT_BYTES + MAX_BOOTSTRAP_ARTIFACT_BYTES + MAX_BOOTFS_ARTIFACT_BYTES;

/// ACPI RSDP v1 is exactly this many bytes.
pub const ACPI_RSDP_V1_BYTES: usize = 20;
/// ACPI RSDP revision 2 and later require at least this many bytes.
pub const ACPI_RSDP_V2_MIN_BYTES: usize = 36;
/// A configuration-table RSDP must have this alignment.
pub const ACPI_RSDP_ALIGNMENT: usize = 16;
/// Loader-local upper bound for an extended RSDP length field.
pub const MAX_ACPI_RSDP_BYTES: usize = UEFI_PAGE_BYTES;

/// Fail-closed errors that can be normalized without firmware access.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PreparationError {
    Config(ConfigError),
    PageCountOverflow,
    EmptyArtifact,
    ArtifactTooLarge,
    ArtifactLengthNotRepresentable,
    TotalArtifactLimitExceeded,
    InvalidAcpiRsdpAlignment,
    InvalidAcpiRsdpSignature,
    InvalidAcpiRsdpLength,
    InvalidAcpiRsdpChecksum,
}

/// Parsed facts needed to retain a validated RSDP without inventing an ACPI
/// table ABI for later handoff code.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AcpiRsdpLayout {
    pub revision: u8,
    pub byte_len: usize,
}

/// Validates the firmware-supplied RSDP address before any raw dereference.
pub fn validate_acpi_rsdp_address(address: usize) -> Result<(), PreparationError> {
    if address == 0 || !address.is_multiple_of(ACPI_RSDP_ALIGNMENT) {
        return Err(PreparationError::InvalidAcpiRsdpAlignment);
    }
    Ok(())
}

/// Parses an absent optional configuration as the canonical default.
pub fn normalize_optional_config(input: Option<&[u8]>) -> Result<LoaderConfig, PreparationError> {
    match input {
        Some(bytes) => LoaderConfig::parse(bytes).map_err(PreparationError::Config),
        None => Ok(LoaderConfig::DEFAULT),
    }
}

/// Admits a non-empty file length before allocating a payload buffer.
pub fn bounded_artifact_len(byte_len: u64, cap: usize) -> Result<usize, PreparationError> {
    let byte_len =
        usize::try_from(byte_len).map_err(|_| PreparationError::ArtifactLengthNotRepresentable)?;
    if byte_len == 0 {
        return Err(PreparationError::EmptyArtifact);
    }
    if byte_len > cap {
        return Err(PreparationError::ArtifactTooLarge);
    }
    Ok(byte_len)
}

/// Checks the aggregate input budget with overflow protection.
pub fn total_artifact_bytes(lengths: [usize; 3]) -> Result<usize, PreparationError> {
    let total = lengths.into_iter().try_fold(0_usize, |total, length| {
        total
            .checked_add(length)
            .ok_or(PreparationError::TotalArtifactLimitExceeded)
    })?;
    if total > MAX_TOTAL_ARTIFACT_BYTES {
        return Err(PreparationError::TotalArtifactLimitExceeded);
    }
    Ok(total)
}

/// Computes the exact number of UEFI pages needed for a non-empty payload.
pub fn pages_for_payload(byte_len: usize) -> Result<usize, PreparationError> {
    if byte_len == 0 {
        return Err(PreparationError::EmptyArtifact);
    }
    byte_len
        .checked_add(UEFI_PAGE_BYTES - 1)
        .map(|rounded| rounded / UEFI_PAGE_BYTES)
        .ok_or(PreparationError::PageCountOverflow)
}

/// Validates an ACPI RSDP byte range before it becomes a handoff dependency.
pub fn validate_acpi_rsdp(bytes: &[u8]) -> Result<AcpiRsdpLayout, PreparationError> {
    if bytes.len() < ACPI_RSDP_V1_BYTES || bytes[..8] != *b"RSD PTR " {
        return Err(PreparationError::InvalidAcpiRsdpSignature);
    }
    if checksum(bytes, ACPI_RSDP_V1_BYTES) != 0 {
        return Err(PreparationError::InvalidAcpiRsdpChecksum);
    }

    let revision = bytes[15];
    if revision < 2 {
        return Ok(AcpiRsdpLayout {
            revision,
            byte_len: ACPI_RSDP_V1_BYTES,
        });
    }
    if bytes.len() < 24 {
        return Err(PreparationError::InvalidAcpiRsdpLength);
    }
    let byte_len = u32::from_le_bytes(bytes[20..24].try_into().expect("fixed slice length"));
    let byte_len =
        usize::try_from(byte_len).map_err(|_| PreparationError::InvalidAcpiRsdpLength)?;
    if !(ACPI_RSDP_V2_MIN_BYTES..=MAX_ACPI_RSDP_BYTES).contains(&byte_len) || bytes.len() < byte_len
    {
        return Err(PreparationError::InvalidAcpiRsdpLength);
    }
    if checksum(bytes, byte_len) != 0 {
        return Err(PreparationError::InvalidAcpiRsdpChecksum);
    }
    Ok(AcpiRsdpLayout { revision, byte_len })
}

fn checksum(bytes: &[u8], byte_len: usize) -> u8 {
    bytes[..byte_len]
        .iter()
        .fold(0_u8, |sum, byte| sum.wrapping_add(*byte))
}

#[cfg(feature = "firmware")]
mod firmware {
    extern crate alloc;

    use alloc::vec::Vec;
    use core::ptr::{self, NonNull};

    use uefi::boot::{
        self, AllocateType, MemoryType, MemoryType as UefiMemoryType, ScopedProtocol,
    };
    use uefi::proto::console::gop::{GraphicsOutput, PixelFormat};
    use uefi::proto::media::file::{Directory, File, FileAttribute, FileInfo, FileMode};
    use uefi::proto::rng::Rng;
    use uefi::table::cfg::ConfigTableEntry;
    use uefi::{CString16, Status, system};
    use wyrmroot_efi_loader::artifacts::{
        ArtifactInputs, BOOTFS_PATH, BOOTSTRAP_PATH, KERNEL_PATH,
    };

    use super::{
        ACPI_RSDP_V1_BYTES, ACPI_RSDP_V2_MIN_BYTES, AcpiRsdpLayout, CONFIG_PATH,
        MAX_ACPI_RSDP_BYTES, MAX_BOOTFS_ARTIFACT_BYTES, MAX_BOOTSTRAP_ARTIFACT_BYTES,
        MAX_CONFIG_BYTES, MAX_KERNEL_ARTIFACT_BYTES, PreparationError, bounded_artifact_len,
        pages_for_payload, total_artifact_bytes, validate_acpi_rsdp, validate_acpi_rsdp_address,
    };

    /// Firmware-specific failure before boot services have exited.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub enum FirmwarePreparationError {
        FileSystem,
        Artifact(PreparationError),
        PageAllocation,
        Config(PreparationError),
        Allocation,
        ShortRead,
        Acpi(PreparationError),
    }

    /// Explicit firmware-entropy outcome; neither absence nor failure receives
    /// a synthetic replacement value. Successful bytes are retained in pages.
    #[derive(Debug)]
    pub enum FirmwareEntropy {
        Available(RetainedPages),
        Unavailable,
        Failed,
    }

    /// GOP pixel layout copied from firmware. RGB and BGR formats have their
    /// implied UEFI 8-bit layouts; bitmask mode carries all four raw masks.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub enum FramebufferPixelFormat {
        Rgb,
        Bgr,
        Bitmask {
            red_mask: u32,
            green_mask: u32,
            blue_mask: u32,
            reserved_mask: u32,
        },
    }

    /// Copied optional GOP metadata. No framebuffer access is attempted here.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub struct FramebufferMetadata {
        pub physical_base: u64,
        pub byte_len: u64,
        pub width: u32,
        pub height: u32,
        pub pixels_per_scan_line: u32,
        pub pixel_format: FramebufferPixelFormat,
    }

    /// A validated and copied ACPI RSDP. The retained range, rather than the
    /// firmware configuration-table pointer, is what later mapping owns.
    #[allow(dead_code)] // Consumed by the pending canonical BootInfo adapter.
    #[derive(Debug)]
    pub struct AcpiRsdp {
        pub storage: RetainedPages,
        pub revision: u8,
        pub byte_len: usize,
    }

    /// Page-backed storage retained through the handoff boundary.
    #[allow(dead_code)] // Physical/length facts are consumed by transition mapping.
    #[derive(Debug)]
    pub struct RetainedPages {
        ptr: NonNull<u8>,
        page_count: usize,
        byte_len: usize,
    }

    #[allow(dead_code)] // Transition/BootInfo consumes these retained-range facts.
    impl RetainedPages {
        pub fn physical_start(&self) -> u64 {
            self.ptr.as_ptr() as u64
        }

        pub const fn byte_len(&self) -> usize {
            self.byte_len
        }

        pub const fn page_count(&self) -> usize {
            self.page_count
        }

        unsafe fn release(self) {
            // SAFETY: this helper is called only before ExitBootServices, with
            // the exact pointer/count returned by `allocate_pages`, and no
            // references into the allocation escape its caller on that path.
            unsafe { boot::free_pages(self.ptr, self.page_count) }
                .expect("retained pre-exit pages must be releasable");
        }
    }

    /// Pre-exit loader state containing only copied metadata and retained pages.
    #[derive(Debug)]
    pub struct PreparedPreExit {
        pub kernel: RetainedPages,
        pub bootstrap: RetainedPages,
        pub bootfs: RetainedPages,
        pub acpi_rsdp: Option<AcpiRsdp>,
        #[allow(dead_code)] // Canonical BootInfo consumes GOP metadata after integration.
        pub framebuffer: Option<FramebufferMetadata>,
        pub entropy: FirmwareEntropy,
    }

    impl PreparedPreExit {
        /// Frees retained pages while boot services are still live. The current
        /// entry uses this fail-closed path until transition and BootInfo inputs
        /// are integrated into the same pre-exit allocation transaction.
        pub fn release_before_exit(self) {
            // SAFETY: this consumes every allocation before ExitBootServices;
            // no reference into these pages escapes the current fail-closed path.
            unsafe { self.kernel.release() };
            // SAFETY: same ownership argument as for `kernel`.
            unsafe { self.bootstrap.release() };
            // SAFETY: same ownership argument as for `kernel`.
            unsafe { self.bootfs.release() };
            if let Some(acpi) = self.acpi_rsdp {
                // SAFETY: the retained copy is still pre-exit and uniquely owned.
                unsafe { acpi.storage.release() };
            }
            if let FirmwareEntropy::Available(entropy) = self.entropy {
                // SAFETY: the retained entropy copy is still pre-exit and uniquely owned.
                unsafe { entropy.release() };
            }
        }
    }

    /// State surviving the UEFI boot-services transition.
    #[allow(dead_code)] // The handoff owner creates this after all pre-exit allocations exist.
    #[derive(Debug)]
    pub struct PreparedPostExit {
        pub pre_exit: PreparedPreExit,
        pub memory_map: uefi::mem::memory_map::MemoryMapOwned,
    }

    struct LoadedFiles {
        kernel: Vec<u8>,
        bootstrap: Vec<u8>,
        bootfs: Vec<u8>,
        config: Option<Vec<u8>>,
    }

    /// Reads all required inputs, preserves their page-backed copies, and
    /// gathers optional firmware metadata while boot services remain active.
    pub fn prepare_pre_exit() -> Result<PreparedPreExit, FirmwarePreparationError> {
        let files = read_loader_files()?;
        let validated = ArtifactInputs {
            kernel: Some(&files.kernel),
            bootstrap: Some(&files.bootstrap),
            bootfs: Some(&files.bootfs),
        }
        .validate()
        .map_err(|_| FirmwarePreparationError::Artifact(PreparationError::EmptyArtifact))?;

        super::normalize_optional_config(files.config.as_deref())
            .map_err(FirmwarePreparationError::Config)?;

        // The copied RSDP and page-backed artifacts remain valid after the
        // configuration-table and protocol guards below are dropped.
        let acpi_rsdp = find_and_retain_acpi_rsdp()?;
        let framebuffer = find_framebuffer();
        let entropy = collect_entropy();

        retain_artifacts(
            validated.kernel,
            validated.bootstrap,
            validated.bootfs,
            acpi_rsdp,
            framebuffer,
            entropy,
        )
    }

    /// Uses uefi-rs's spec-compliant final-map / ExitBootServices retry wrapper.
    /// The entry deliberately does not call this yet: transition stack, page
    /// table, kernel segments, and canonical BootInfo must be allocated before
    /// the final map is captured.
    #[allow(dead_code)] // The entry must not invoke this before transition/BootInfo integration.
    pub fn exit_boot_services_after_handoff_preparation(
        pre_exit: PreparedPreExit,
    ) -> PreparedPostExit {
        // All protocol guards, files, and pool-backed input buffers have been
        // dropped. `pre_exit` has only copied scalars and retained page storage.
        uefi::println!("wyrmroot-loader: final UEFI memory map / ExitBootServices");
        // SAFETY: the uefi-rs wrapper owns the final map/key/retry sequence.
        // Callers must not retain UEFI protocol or pool-backed values.
        let memory_map = unsafe { boot::exit_boot_services(Some(MemoryType::LOADER_DATA)) };
        PreparedPostExit {
            pre_exit,
            memory_map,
        }
    }

    fn read_loader_files() -> Result<LoadedFiles, FirmwarePreparationError> {
        let mut filesystem: ScopedProtocol<_> =
            boot::get_image_file_system(boot::image_handle())
                .map_err(|_| FirmwarePreparationError::FileSystem)?;
        let mut root = filesystem
            .open_volume()
            .map_err(|_| FirmwarePreparationError::FileSystem)?;

        let kernel_path =
            CString16::try_from(KERNEL_PATH).map_err(|_| FirmwarePreparationError::FileSystem)?;
        let bootstrap_path = CString16::try_from(BOOTSTRAP_PATH)
            .map_err(|_| FirmwarePreparationError::FileSystem)?;
        let bootfs_path =
            CString16::try_from(BOOTFS_PATH).map_err(|_| FirmwarePreparationError::FileSystem)?;
        let config_path =
            CString16::try_from(CONFIG_PATH).map_err(|_| FirmwarePreparationError::FileSystem)?;

        let kernel = read_bounded_file(&mut root, &kernel_path, MAX_KERNEL_ARTIFACT_BYTES)?;
        let bootstrap =
            read_bounded_file(&mut root, &bootstrap_path, MAX_BOOTSTRAP_ARTIFACT_BYTES)?;
        let bootfs = read_bounded_file(&mut root, &bootfs_path, MAX_BOOTFS_ARTIFACT_BYTES)?;
        total_artifact_bytes([kernel.len(), bootstrap.len(), bootfs.len()])
            .map_err(FirmwarePreparationError::Artifact)?;
        let config = read_optional_bounded_file(&mut root, &config_path, MAX_CONFIG_BYTES)?;

        Ok(LoadedFiles {
            kernel,
            bootstrap,
            bootfs,
            config,
        })
    }

    fn read_bounded_file(
        root: &mut Directory,
        path: &CString16,
        cap: usize,
    ) -> Result<Vec<u8>, FirmwarePreparationError> {
        let file = root
            .open(path, FileMode::Read, FileAttribute::empty())
            .map_err(|_| FirmwarePreparationError::FileSystem)?;
        read_opened_bounded_file(file, cap)
    }

    fn read_optional_bounded_file(
        root: &mut Directory,
        path: &CString16,
        cap: usize,
    ) -> Result<Option<Vec<u8>>, FirmwarePreparationError> {
        let file = match root.open(path, FileMode::Read, FileAttribute::empty()) {
            Ok(file) => file,
            Err(error) if error.status() == Status::NOT_FOUND => return Ok(None),
            Err(_) => return Err(FirmwarePreparationError::FileSystem),
        };
        read_opened_bounded_file(file, cap).map(Some)
    }

    fn read_opened_bounded_file(
        file: uefi::proto::media::file::FileHandle,
        cap: usize,
    ) -> Result<Vec<u8>, FirmwarePreparationError> {
        let mut file = file
            .into_regular_file()
            .ok_or(FirmwarePreparationError::FileSystem)?;
        let info = file
            .get_boxed_info::<FileInfo>()
            .map_err(|_| FirmwarePreparationError::FileSystem)?;
        let byte_len = bounded_artifact_len(info.file_size(), cap)
            .map_err(FirmwarePreparationError::Artifact)?;

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

    fn retain_artifacts(
        kernel: &[u8],
        bootstrap: &[u8],
        bootfs: &[u8],
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
        let entropy = match retain_entropy(entropy) {
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

        Ok(PreparedPreExit {
            kernel,
            bootstrap,
            bootfs,
            acpi_rsdp,
            framebuffer,
            entropy,
        })
    }

    fn release_acpi(acpi_rsdp: Option<AcpiRsdp>) {
        if let Some(acpi) = acpi_rsdp {
            // SAFETY: this cleanup path owns the copy and runs before ExitBootServices.
            unsafe { acpi.storage.release() };
        }
    }

    fn retain_payload(payload: &[u8]) -> Result<RetainedPages, FirmwarePreparationError> {
        let page_count =
            pages_for_payload(payload.len()).map_err(FirmwarePreparationError::Artifact)?;
        let ptr = boot::allocate_pages(
            AllocateType::AnyPages,
            UefiMemoryType::LOADER_DATA,
            page_count,
        )
        .map_err(|_| FirmwarePreparationError::PageAllocation)?;

        // SAFETY: `allocate_pages` returned `page_count * 4096` writable bytes,
        // which is at least `payload.len()` by `pages_for_payload`; the source
        // slice is valid and the allocation cannot overlap it.
        unsafe { ptr::copy_nonoverlapping(payload.as_ptr(), ptr.as_ptr(), payload.len()) };

        Ok(RetainedPages {
            ptr,
            page_count,
            byte_len: payload.len(),
        })
    }

    enum CollectedEntropy {
        Available([u8; 32]),
        Unavailable,
        Failed,
    }

    fn collect_entropy() -> CollectedEntropy {
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

    fn retain_entropy(
        entropy: CollectedEntropy,
    ) -> Result<FirmwareEntropy, FirmwarePreparationError> {
        match entropy {
            CollectedEntropy::Available(bytes) => {
                retain_payload(&bytes).map(FirmwareEntropy::Available)
            }
            CollectedEntropy::Unavailable => Ok(FirmwareEntropy::Unavailable),
            CollectedEntropy::Failed => Ok(FirmwareEntropy::Failed),
        }
    }

    fn find_and_retain_acpi_rsdp() -> Result<Option<AcpiRsdp>, FirmwarePreparationError> {
        let address = system::with_config_table(|entries| {
            entries
                .iter()
                .find(|entry| entry.guid == ConfigTableEntry::ACPI2_GUID)
                .or_else(|| {
                    entries
                        .iter()
                        .find(|entry| entry.guid == ConfigTableEntry::ACPI_GUID)
                })
                .map(|entry| entry.address as usize)
        });
        let Some(address) = address else {
            return Ok(None);
        };
        validate_acpi_rsdp_address(address).map_err(FirmwarePreparationError::Acpi)?;

        // SAFETY: UEFI owns configuration-table memory until handoff. The ACPI
        // entry promises an RSDP at this aligned address; only the fixed v1
        // prefix is read to determine the revision and extended byte length.
        let prefix =
            unsafe { core::slice::from_raw_parts(address as *const u8, ACPI_RSDP_V1_BYTES) };
        let byte_len = if prefix[15] < 2 {
            ACPI_RSDP_V1_BYTES
        } else {
            // SAFETY: this is the v2 length field, immediately following the v1 prefix.
            let header = unsafe {
                core::slice::from_raw_parts(address as *const u8, ACPI_RSDP_V2_MIN_BYTES)
            };
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

    fn find_framebuffer() -> Option<FramebufferMetadata> {
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
}

#[cfg(feature = "firmware")]
pub use firmware::prepare_pre_exit;
