//! Pending resources and the prepared and exited handoff.

use super::*;

#[cfg(all(target_arch = "x86_64", target_os = "uefi"))]
pub(crate) struct PendingResources {
    pub(crate) prepared: Option<PreparedPreExit>,
    pub(crate) kernel_pages: Option<RetainedPages>,
    pub(crate) boot_info: Option<RetainedPages>,
    pub(crate) memory_map: Option<RetainedPages>,
    pub(crate) modules: Option<RetainedPages>,
    pub(crate) paging_handoff: Option<RetainedPages>,
    pub(crate) transition_stack: Option<RetainedPages>,
    pub(crate) page_tables: Option<RetainedPages>,
}

#[cfg(all(target_arch = "x86_64", target_os = "uefi"))]
impl PendingResources {
    pub(crate) fn new(prepared: PreparedPreExit) -> Self {
        Self {
            prepared: Some(prepared),
            kernel_pages: None,
            boot_info: None,
            memory_map: None,
            modules: None,
            paging_handoff: None,
            transition_stack: None,
            page_tables: None,
        }
    }

    pub(crate) fn prepare(
        mut self,
        policy: GeneratedHandoffPolicy,
    ) -> Result<PreparedHandoff, FirmwarePreparationError> {
        let kernel_image_byte_len = u64::try_from(
            self.prepared
                .as_ref()
                .ok_or(FirmwarePreparationError::KernelSourceReleased)?
                .kernel_elf_bytes()?
                .len(),
        )
        .map_err(|_| FirmwarePreparationError::InvalidPreExitAllocation)?;
        let elf_policy = KernelElfPolicy {
            virtual_addresses: AddressRange::new(
                policy.elf_window_start,
                policy.elf_window_end_exclusive,
            ),
            link_base: policy.link_base,
            mapping_granule: policy.base_page_size,
        };
        let capacity = kernel_elf::kernel_load_segment_capacity(
            self.prepared
                .as_ref()
                .ok_or(FirmwarePreparationError::KernelSourceReleased)?
                .kernel_elf_bytes()?,
            elf_policy,
        )
        .map_err(|_| FirmwarePreparationError::InvalidPreExitAllocation)?;
        let mut load_segments = fallible_segments(capacity)?;
        let plan = kernel_elf::plan_kernel_elf(
            self.prepared
                .as_ref()
                .ok_or(FirmwarePreparationError::KernelSourceReleased)?
                .kernel_elf_bytes()?,
            elf_policy,
            &mut load_segments,
        )
        .map_err(|_| FirmwarePreparationError::InvalidPreExitAllocation)?;
        let kernel_entry = plan.entry_point;
        let kernel_bytes = plan.segments.iter().try_fold(0_usize, |total, segment| {
            let length = usize::try_from(segment.mapping_byte_len)
                .map_err(|_| FirmwarePreparationError::InvalidPreExitAllocation)?;
            total
                .checked_add(length)
                .ok_or(FirmwarePreparationError::InvalidPreExitAllocation)
        })?;
        self.kernel_pages = Some(RetainedPages::allocate_zeroed_pages(
            pages_for_payload(kernel_bytes).map_err(FirmwarePreparationError::Artifact)?,
        )?);
        let kernel_base = self
            .kernel_pages
            .as_ref()
            .ok_or(FirmwarePreparationError::InvalidPreExitAllocation)?
            .physical_start();
        let mut kernel_segments = fallible_kernel_segment_pages(capacity)?;
        let mut next_offset = 0_u64;
        for segment in plan.segments {
            kernel_segments.push(KernelSegmentPages {
                segment: *segment,
                pages: RetainedPhysicalRange {
                    physical_start: kernel_base
                        .checked_add(next_offset)
                        .ok_or(FirmwarePreparationError::InvalidPreExitAllocation)?,
                    byte_len: segment.mapping_byte_len,
                    lifetime: AllocationLifetime::RetainedUntilKernelPageTableReplacement,
                },
            });
            next_offset = next_offset
                .checked_add(segment.mapping_byte_len)
                .ok_or(FirmwarePreparationError::InvalidPreExitAllocation)?;
        }

        let map_cap = usize::try_from(policy.max_normalized_memory_map_entries)
            .map_err(|_| FirmwarePreparationError::InvalidGeneratedPolicy)?;
        let module_cap = usize::try_from(policy.max_module_entries)
            .map_err(|_| FirmwarePreparationError::InvalidGeneratedPolicy)?;
        let module_count = 3 + usize::from(
            self.prepared
                .as_ref()
                .ok_or(FirmwarePreparationError::KernelSourceReleased)?
                .boot_device_table
                .is_some(),
        );
        super::super::bounded_intake_count(module_count, policy.max_module_entries)
            .map_err(FirmwarePreparationError::Artifact)?;
        self.boot_info = Some(allocate_typed_table::<DwBootInfoV1>(1)?);
        self.memory_map = Some(allocate_typed_table::<DwBootMemoryRangeV1>(map_cap)?);
        self.modules = Some(allocate_typed_table::<DwBootModuleV1>(module_cap)?);
        self.paging_handoff = Some(RetainedPages::allocate_zeroed_pages(
            pages_for_payload(DW_BOOT_X86_64_PAGING_HANDOFF_MAX_BYTE_LEN as usize)
                .map_err(FirmwarePreparationError::Artifact)?,
        )?);
        let stack_pages = usize::try_from(policy.transition_stack_size / policy.base_page_size)
            .map_err(|_| FirmwarePreparationError::InvalidPreExitAllocation)?;
        self.transition_stack = Some(RetainedPages::allocate_zeroed_pages(stack_pages)?);

        let original = self
            .prepared
            .as_ref()
            .ok_or(FirmwarePreparationError::KernelSourceReleased)?;
        let bootstrap_range = original.bootstrap.retained_physical_range()?;
        let bootfs_range = original.bootfs.retained_physical_range()?;
        let paging_handoff_range = self
            .paging_handoff
            .as_ref()
            .ok_or(FirmwarePreparationError::InvalidPreExitAllocation)?
            .retained_physical_range()?;
        let boot_device_table_range = original
            .boot_device_table
            .as_ref()
            .map(RetainedPages::retained_physical_range)
            .transpose()?
            .unwrap_or(bootstrap_range);
        let module_ranges = [
            bootstrap_range,
            bootfs_range,
            paging_handoff_range,
            boot_device_table_range,
        ];
        let validated_rsdp = original
            .acpi_rsdp
            .as_ref()
            .map(|rsdp| {
                Ok(ValidatedRsdpMappingInput {
                    retained_allocation: rsdp.storage.retained_physical_range()?,
                    record_physical_start: rsdp.storage.physical_start(),
                    record_byte_len: u64::try_from(rsdp.byte_len)
                        .map_err(|_| FirmwarePreparationError::InvalidPreExitAllocation)?,
                })
            })
            .transpose()?;
        let entropy_range = match &original.entropy {
            FirmwareEntropy::Available { storage, .. } => Some(storage.retained_physical_range()?),
            FirmwareEntropy::Unavailable | FirmwareEntropy::Failed => None,
        };
        let framebuffer_pixels = original.framebuffer.map(|framebuffer| PhysicalRange {
            physical_start: framebuffer.physical_base,
            byte_len: framebuffer.byte_len,
        });
        let (stub_start, stub_len, handoff_stub_entry) = discover_linked_handoff_stub()?;
        let handoff_stub = RetainedPhysicalRange {
            physical_start: stub_start,
            byte_len: stub_len,
            lifetime: AllocationLifetime::RetainedUntilKernelPageTableReplacement,
        };
        let mapping_capacity = capacity
            .checked_add(10)
            .and_then(|value| value.checked_add(module_count - 3))
            .ok_or(FirmwarePreparationError::InvalidPreExitAllocation)?;
        let mut mapping_output = fallible_mappings(mapping_capacity)?;
        let mut materialization_output = fallible_materializations(capacity)?;
        let transition_policy = transition_policy(policy);

        let page_count = {
            let identity = identity_inputs(
                &self,
                &module_ranges[..module_count],
                validated_rsdp,
                entropy_range,
                framebuffer_pixels,
                handoff_stub,
                handoff_stub_entry,
            )?;
            let input = TransitionPreflightInput {
                policy: transition_policy,
                kernel_entry,
                kernel_image_byte_len,
                kernel_segments: &kernel_segments,
                identity,
            };
            let preflight = transition::preflight_transition(
                &input,
                &mut mapping_output,
                &mut materialization_output,
            )
            .map_err(|_| FirmwarePreparationError::InvalidPreExitAllocation)?;
            usize::try_from(preflight.page_table_page_count())
                .map_err(|_| FirmwarePreparationError::InvalidPreExitAllocation)?
        };
        self.page_tables = Some(RetainedPages::allocate_zeroed_pages(page_count)?);

        let (materializations, paging_handoff_byte_len) = {
            let identity = identity_inputs(
                &self,
                &module_ranges[..module_count],
                validated_rsdp,
                entropy_range,
                framebuffer_pixels,
                handoff_stub,
                handoff_stub_entry,
            )?;
            let input = TransitionPreflightInput {
                policy: transition_policy,
                kernel_entry,
                kernel_image_byte_len,
                kernel_segments: &kernel_segments,
                identity,
            };
            let preflight = transition::preflight_transition(
                &input,
                &mut mapping_output,
                &mut materialization_output,
            )
            .map_err(|_| FirmwarePreparationError::InvalidPreExitAllocation)?;
            let page_table_range = self
                .page_tables
                .as_ref()
                .ok_or(FirmwarePreparationError::InvalidPreExitAllocation)?
                .retained_physical_range()?;
            let finalized = transition::finalize_transition(preflight, page_table_range)
                .map_err(|_| FirmwarePreparationError::InvalidPreExitAllocation)?;
            let frame_bytes = finalized
                .used_page_table_page_count()
                .checked_mul(u64::from(DW_BOOT_X86_64_PAGING_HANDOFF_TABLE_FRAME_STRIDE))
                .ok_or(FirmwarePreparationError::InvalidPreExitAllocation)?;
            let carrier_byte_len = u64::from(DW_BOOT_X86_64_PAGING_HANDOFF_TABLE_FRAMES_OFFSET)
                .checked_add(frame_bytes)
                .and_then(|value| usize::try_from(value).ok())
                .ok_or(FirmwarePreparationError::InvalidPreExitAllocation)?;
            (
                copy_materializations(finalized.pre_exit().kernel_materializations)?,
                carrier_byte_len,
            )
        };

        {
            let prepared = self
                .prepared
                .as_mut()
                .ok_or(FirmwarePreparationError::KernelSourceReleased)?;
            let kernel_pages = self
                .kernel_pages
                .as_mut()
                .ok_or(FirmwarePreparationError::InvalidPreExitAllocation)?;
            let base = kernel_pages.physical_start();
            prepared.materialize_kernel_and_release(|image| {
                for materialization in &materializations {
                    let start = usize::try_from(materialization.file_offset)
                        .map_err(|_| FirmwarePreparationError::CopyRangeInvalid)?;
                    let len = usize::try_from(materialization.file_size)
                        .map_err(|_| FirmwarePreparationError::CopyRangeInvalid)?;
                    let end = start
                        .checked_add(len)
                        .ok_or(FirmwarePreparationError::CopyRangeInvalid)?;
                    let destination = materialization
                        .copy_destination
                        .checked_sub(base)
                        .and_then(|offset| usize::try_from(offset).ok())
                        .ok_or(FirmwarePreparationError::CopyRangeInvalid)?;
                    kernel_pages.copy_zeroed_from(
                        destination,
                        image
                            .get(start..end)
                            .ok_or(FirmwarePreparationError::CopyRangeInvalid)?,
                    )?;
                }
                Ok(())
            })?;
        }
        let materialized_inputs = materialized_inputs(
            self.prepared
                .take()
                .ok_or(FirmwarePreparationError::KernelSourceReleased)?,
        )?;

        Ok(PreparedHandoff {
            inputs: Some(materialized_inputs),
            kernel_pages: self.kernel_pages.take(),
            boot_info: self.boot_info.take(),
            memory_map: self.memory_map.take(),
            modules: self.modules.take(),
            paging_handoff: self.paging_handoff.take(),
            transition_stack: self.transition_stack.take(),
            page_tables: self.page_tables.take(),
            kernel_segments,
            mapping_output,
            materialization_output,
            module_ranges,
            module_count,
            validated_rsdp,
            entropy_range,
            framebuffer_pixels,
            handoff_stub,
            handoff_stub_entry,
            kernel_entry,
            kernel_image_byte_len,
            paging_handoff_byte_len,
        })
    }
}

#[cfg(all(target_arch = "x86_64", target_os = "uefi"))]
impl Drop for PendingResources {
    fn drop(&mut self) {
        release_pages(&mut self.page_tables);
        release_pages(&mut self.transition_stack);
        release_pages(&mut self.modules);
        release_pages(&mut self.paging_handoff);
        release_pages(&mut self.memory_map);
        release_pages(&mut self.boot_info);
        release_pages(&mut self.kernel_pages);
        if let Some(prepared) = self.prepared.take() {
            prepared.release_before_exit();
        }
    }
}

#[cfg(all(target_arch = "x86_64", target_os = "uefi"))]
pub(crate) struct PreparedHandoff {
    pub(crate) inputs: Option<MaterializedInputs>,
    pub(crate) kernel_pages: Option<RetainedPages>,
    pub(crate) boot_info: Option<RetainedPages>,
    pub(crate) memory_map: Option<RetainedPages>,
    pub(crate) modules: Option<RetainedPages>,
    pub(crate) paging_handoff: Option<RetainedPages>,
    pub(crate) transition_stack: Option<RetainedPages>,
    pub(crate) page_tables: Option<RetainedPages>,
    pub(crate) kernel_segments: Vec<KernelSegmentPages>,
    pub(crate) mapping_output: Vec<TransitionMapping>,
    pub(crate) materialization_output: Vec<KernelMaterialization>,
    pub(crate) module_ranges: [RetainedPhysicalRange; 4],
    pub(crate) module_count: usize,
    pub(crate) validated_rsdp: Option<ValidatedRsdpMappingInput>,
    pub(crate) entropy_range: Option<RetainedPhysicalRange>,
    pub(crate) framebuffer_pixels: Option<PhysicalRange>,
    pub(crate) handoff_stub: RetainedPhysicalRange,
    pub(crate) handoff_stub_entry: u64,
    pub(crate) kernel_entry: u64,
    pub(crate) kernel_image_byte_len: u64,
    pub(crate) paging_handoff_byte_len: usize,
}

#[cfg(all(target_arch = "x86_64", target_os = "uefi"))]
impl PreparedHandoff {
    pub(crate) fn exit_boot_services(mut self) -> ExitedHandoff {
        let inputs = self.inputs.take().expect("prepared handoff inputs");
        let kernel_pages = self.kernel_pages.take().expect("prepared kernel pages");
        let boot_info = self.boot_info.take().expect("prepared BootInfo pages");
        let memory_map_pages = self.memory_map.take().expect("prepared memory-map pages");
        let modules = self.modules.take().expect("prepared module pages");
        let paging_handoff = self
            .paging_handoff
            .take()
            .expect("prepared paging-handoff carrier pages");
        let transition_stack = self.transition_stack.take().expect("prepared stack pages");
        let page_tables = self.page_tables.take().expect("prepared page-table pages");
        let kernel_segments = core::mem::take(&mut self.kernel_segments);
        let mapping_output = core::mem::take(&mut self.mapping_output);
        let materialization_output = core::mem::take(&mut self.materialization_output);
        uefi::println!("wyrmroot-loader: final UEFI memory map / ExitBootServices");
        // SAFETY: no firmware protocol guard or pool-backed input remains;
        // this wrapper owns final map capture and its one retry.
        let mut memory_map = unsafe { boot::exit_boot_services(Some(MemoryType::LOADER_DATA)) };
        memory_map.sort();
        ExitedHandoff {
            inputs: inputs.into_post_exit(),
            kernel_pages: kernel_pages.into_post_exit(),
            boot_info: boot_info.into_post_exit(),
            memory_map_pages: memory_map_pages.into_post_exit(),
            modules: modules.into_post_exit(),
            paging_handoff: paging_handoff.into_post_exit(),
            transition_stack: transition_stack.into_post_exit(),
            page_tables: page_tables.into_post_exit(),
            memory_map,
            kernel_segments,
            mapping_output,
            materialization_output,
            module_ranges: self.module_ranges,
            module_count: self.module_count,
            validated_rsdp: self.validated_rsdp,
            entropy_range: self.entropy_range,
            framebuffer_pixels: self.framebuffer_pixels,
            handoff_stub: self.handoff_stub,
            handoff_stub_entry: self.handoff_stub_entry,
            kernel_entry: self.kernel_entry,
            kernel_image_byte_len: self.kernel_image_byte_len,
            paging_handoff_byte_len: self.paging_handoff_byte_len,
        }
    }
}

#[cfg(all(target_arch = "x86_64", target_os = "uefi"))]
impl Drop for PreparedHandoff {
    fn drop(&mut self) {
        release_pages(&mut self.page_tables);
        release_pages(&mut self.transition_stack);
        release_pages(&mut self.modules);
        release_pages(&mut self.paging_handoff);
        release_pages(&mut self.memory_map);
        release_pages(&mut self.boot_info);
        release_pages(&mut self.kernel_pages);
        if let Some(inputs) = self.inputs.take() {
            inputs.release_before_exit();
        }
    }
}

#[cfg(all(target_arch = "x86_64", target_os = "uefi"))]
pub(crate) struct ExitedHandoff {
    pub(crate) inputs: PostExitInputs,
    pub(crate) kernel_pages: PostExitPages,
    pub(crate) boot_info: PostExitPages,
    pub(crate) memory_map_pages: PostExitPages,
    pub(crate) modules: PostExitPages,
    pub(crate) paging_handoff: PostExitPages,
    pub(crate) transition_stack: PostExitPages,
    pub(crate) page_tables: PostExitPages,
    pub(crate) memory_map: uefi::mem::memory_map::MemoryMapOwned,
    pub(crate) kernel_segments: Vec<KernelSegmentPages>,
    pub(crate) mapping_output: Vec<TransitionMapping>,
    pub(crate) materialization_output: Vec<KernelMaterialization>,
    pub(crate) module_ranges: [RetainedPhysicalRange; 4],
    pub(crate) module_count: usize,
    pub(crate) validated_rsdp: Option<ValidatedRsdpMappingInput>,
    pub(crate) entropy_range: Option<RetainedPhysicalRange>,
    pub(crate) framebuffer_pixels: Option<PhysicalRange>,
    pub(crate) handoff_stub: RetainedPhysicalRange,
    pub(crate) handoff_stub_entry: u64,
    pub(crate) kernel_entry: u64,
    pub(crate) kernel_image_byte_len: u64,
    pub(crate) paging_handoff_byte_len: usize,
}

#[cfg(all(target_arch = "x86_64", target_os = "uefi"))]
impl ExitedHandoff {
    pub(crate) fn complete(self, policy: GeneratedHandoffPolicy) -> ! {
        let ExitedHandoff {
            inputs,
            kernel_pages,
            mut boot_info,
            mut memory_map_pages,
            mut modules,
            mut paging_handoff,
            transition_stack,
            mut page_tables,
            memory_map,
            kernel_segments,
            mut mapping_output,
            mut materialization_output,
            module_ranges,
            module_count,
            validated_rsdp,
            entropy_range,
            framebuffer_pixels,
            handoff_stub,
            handoff_stub_entry,
            kernel_entry,
            kernel_image_byte_len,
            paging_handoff_byte_len,
        } = self;

        let kernel_allocation = match kernel_pages.retained_physical_range() {
            Ok(value) => value,
            Err(_) => post_exit_halt(),
        };
        let kernel_segment_bytes = match kernel_segments.iter().try_fold(0_u64, |total, segment| {
            total.checked_add(segment.pages.byte_len)
        }) {
            Some(value) => value,
            None => post_exit_halt(),
        };
        if kernel_segments
            .first()
            .map(|segment| segment.pages.physical_start)
            != Some(kernel_allocation.physical_start)
            || kernel_segment_bytes != kernel_allocation.byte_len
        {
            post_exit_halt();
        }

        let map_cap = match usize::try_from(policy.max_normalized_memory_map_entries) {
            Ok(value) => value,
            Err(_) => post_exit_halt(),
        };
        let module_cap = match usize::try_from(policy.max_module_entries) {
            Ok(value) => value,
            Err(_) => post_exit_halt(),
        };
        let bootstrap_module = ModuleInput {
            kind: DW_BOOT_MODULE_KIND_WYRMROOT_BOOTSTRAP,
            physical_start: inputs.bootstrap.physical_start(),
            byte_len: match u64::try_from(inputs.bootstrap.payload_byte_len) {
                Ok(value) => value,
                Err(_) => post_exit_halt(),
            },
        };
        let bootfs_module = ModuleInput {
            kind: DW_BOOT_MODULE_KIND_WYRMROOT_BOOTFS,
            physical_start: inputs.bootfs.physical_start(),
            byte_len: match u64::try_from(inputs.bootfs.payload_byte_len) {
                Ok(value) => value,
                Err(_) => post_exit_halt(),
            },
        };
        let paging_handoff_module = ModuleInput {
            kind: DW_BOOT_MODULE_KIND_DEEPWYRM_X86_64_PAGING_HANDOFF_V1,
            physical_start: paging_handoff.physical_start(),
            byte_len: match u64::try_from(paging_handoff_byte_len) {
                Ok(value) => value,
                Err(_) => post_exit_halt(),
            },
        };
        let mut module_records = [DwBootModuleV1::default(); 4];
        let planned_module_count = match inputs.boot_device_table.as_ref() {
            Some(boot_device_table) => match modules::plan_modules_with_boot_device_table(
                bootstrap_module,
                bootfs_module,
                paging_handoff_module,
                ModuleInput {
                    kind: DW_BOOT_MODULE_KIND_DEEPWYRM_BOOT_DEVICE_TABLE_V1,
                    physical_start: boot_device_table.physical_start(),
                    byte_len: match u64::try_from(boot_device_table.payload_byte_len) {
                        Ok(value) => value,
                        Err(_) => post_exit_halt(),
                    },
                },
            ) {
                Ok(value) => {
                    module_records.copy_from_slice(&value);
                    4
                }
                Err(_) => post_exit_halt(),
            },
            None => {
                match modules::plan_modules(bootstrap_module, bootfs_module, paging_handoff_module)
                {
                    Ok(value) => {
                        module_records[..3].copy_from_slice(&value.to_abi_modules());
                        3
                    }
                    Err(_) => post_exit_halt(),
                }
            }
        };
        if planned_module_count != module_count {
            post_exit_halt();
        }
        let module_records = &module_records[..planned_module_count];
        if super::super::bounded_intake_count(module_records.len(), policy.max_module_entries)
            .is_err()
        {
            post_exit_halt();
        }

        let boot_info_storage = match boot_info.boot_info_allocation() {
            Ok(value) => value,
            Err(_) => post_exit_halt(),
        };
        let memory_map_storage = match memory_map_pages.boot_info_allocation() {
            Ok(value) => value,
            Err(_) => post_exit_halt(),
        };
        let module_table_storage = match modules.boot_info_allocation() {
            Ok(value) => value,
            Err(_) => post_exit_halt(),
        };
        let acpi_rsdp = match inputs.acpi_rsdp.as_ref() {
            Some(rsdp) => Some(AcpiRsdpInput {
                storage: match rsdp.storage.boot_info_allocation() {
                    Ok(value) => value,
                    Err(_) => post_exit_halt(),
                },
                byte_len: match u64::try_from(rsdp.byte_len) {
                    Ok(value) => value,
                    Err(_) => post_exit_halt(),
                },
            }),
            None => None,
        };
        let framebuffer = inputs
            .framebuffer
            .map(|framebuffer| BootInfoFramebufferInput {
                physical_start: framebuffer.physical_base,
                byte_len: framebuffer.byte_len,
                width: framebuffer.width,
                height: framebuffer.height,
                pixels_per_scanline: framebuffer.pixels_per_scan_line,
                pixel_format: match framebuffer.pixel_format {
                    FramebufferPixelFormat::Rgb => BootInfoPixelFormat::Rgbx8,
                    FramebufferPixelFormat::Bgr => BootInfoPixelFormat::Bgrx8,
                    FramebufferPixelFormat::Bitmask {
                        red_mask,
                        green_mask,
                        blue_mask,
                        reserved_mask,
                    } => BootInfoPixelFormat::Bitmask {
                        red_mask,
                        green_mask,
                        blue_mask,
                        reserved_mask,
                    },
                },
            });
        let entropy = match &inputs.entropy {
            PostExitEntropy::Available {
                storage,
                source,
                conditioned,
            } => Some(EntropyInput {
                storage: match storage.boot_info_allocation() {
                    Ok(value) => value,
                    Err(_) => post_exit_halt(),
                },
                byte_len: match u64::try_from(storage.payload_byte_len) {
                    Ok(value) => value,
                    Err(_) => post_exit_halt(),
                },
                source: match source {
                    FirmwareEntropySource::UefiRngProtocol => {
                        BootInfoEntropySource::UefiRngProtocol
                    }
                },
                conditioned: *conditioned,
            }),
            PostExitEntropy::Unavailable | PostExitEntropy::Failed => None,
        };

        let memory_records =
            match unsafe { memory_map_pages.typed_slice_mut::<DwBootMemoryRangeV1>(map_cap) } {
                Ok(value) => value,
                Err(_) => post_exit_halt(),
            };
        let (normalized, final_map_accepted) =
            match super::super::accept_final_memory_map(memory_map::normalize_and_coalesce(
                memory_map
                    .entries()
                    .copied()
                    .map(firmware_memory_descriptor),
                memory_records,
            )) {
                Ok(value) => value,
                Err(error) => super::super::dispatch_post_exit_failure(error, |_| post_exit_halt()),
            };
        let module_output =
            match unsafe { modules.typed_slice_mut::<DwBootModuleV1>(module_records.len()) } {
                Ok(value) => value,
                Err(_) => post_exit_halt(),
            };
        let boot_info_output = match unsafe { boot_info.typed_slice_mut::<DwBootInfoV1>(1) } {
            Ok(value) => &mut value[0],
            Err(_) => post_exit_halt(),
        };
        let boot_input = BootInfoInput {
            phase: FirmwarePhase::AfterExitBootServices,
            boot_info_storage,
            memory_map_storage,
            module_table_storage,
            memory_map: normalized,
            modules: &module_records,
            acpi_rsdp,
            framebuffer,
            command_line: None,
            entropy,
        };
        let mut boot_output = BootInfoOutput {
            boot_info: boot_info_output,
            modules: module_output,
        };
        let (_, boot_info_accepted) =
            match super::super::accept_boot_info(boot_info::build_with_limits(
                &boot_input,
                &mut boot_output,
                BootInfoLimits {
                    max_memory_map_entries: map_cap,
                    max_module_entries: module_cap,
                },
            )) {
                Ok(value) => value,
                Err(error) => super::super::dispatch_post_exit_failure(error, |_| post_exit_halt()),
            };

        let transition_policy = transition_policy(policy);
        let identity = IdentityMapInputs {
            boot_info: match boot_info.retained_physical_range() {
                Ok(value) => value,
                Err(_) => post_exit_halt(),
            },
            memory_map_table: match memory_map_pages.retained_physical_range() {
                Ok(value) => value,
                Err(_) => post_exit_halt(),
            },
            module_table: match modules.retained_physical_range() {
                Ok(value) => value,
                Err(_) => post_exit_halt(),
            },
            module_data: &module_ranges[..planned_module_count],
            command_line: None,
            entropy: entropy_range,
            validated_rsdp,
            handoff_stub,
            handoff_stub_entry,
            transition_stack: match transition_stack.retained_physical_range() {
                Ok(value) => value,
                Err(_) => post_exit_halt(),
            },
            framebuffer_pixels,
        };
        let transition_input = TransitionPreflightInput {
            policy: transition_policy,
            kernel_entry,
            kernel_image_byte_len,
            kernel_segments: &kernel_segments,
            identity,
        };
        let preflight = match transition::preflight_transition(
            &transition_input,
            &mut mapping_output,
            &mut materialization_output,
        ) {
            Ok(value) => value,
            Err(_) => post_exit_halt(),
        };
        let page_table_storage = match page_tables.retained_physical_range() {
            Ok(value) => value,
            Err(_) => post_exit_halt(),
        };
        let plan = match transition::finalize_transition(preflight, page_table_storage) {
            Ok(value) => value,
            Err(_) => post_exit_halt(),
        };
        let entropy_coherence = match (entropy, entropy_range) {
            (Some(value), Some(range)) => Some((value.storage, range)),
            (None, None) => None,
            _ => post_exit_halt(),
        };
        let rsdp_coherence = match (acpi_rsdp, validated_rsdp) {
            (Some(value), Some(mapping)) => Some((value.storage, mapping)),
            (None, None) => None,
            _ => post_exit_halt(),
        };
        let retained_addresses = match super::super::validate_retained_address_coherence(
            plan.mappings(),
            super::super::RetainedAddressFacts {
                boot_info: boot_info_storage,
                memory_map: memory_map_storage,
                module_table: module_table_storage,
                module_records: &module_records,
                module_allocations: &module_ranges[..planned_module_count],
                entropy: entropy_coherence,
                rsdp: rsdp_coherence,
            },
        ) {
            Ok(value) => value,
            Err(_) => post_exit_halt(),
        };
        let physical_address_bits = match query_maxphyaddr() {
            Ok(value) => value,
            Err(_) => post_exit_halt(),
        };
        let table_pages = match unsafe {
            page_tables.typed_slice_mut::<crate::uefi_page_table::PageTablePage>(
                page_tables.allocation_byte_len / super::super::UEFI_PAGE_BYTES,
            )
        } {
            Ok(value) => value,
            Err(_) => post_exit_halt(),
        };
        let mut table = match crate::uefi_page_table::UefiPageTable::new(
            page_table_storage.physical_start,
            physical_address_bits,
            table_pages,
        ) {
            Ok(value) => value,
            Err(_) => post_exit_halt(),
        };
        let post_exit = match transition::confirm_exit_boot_services(true) {
            Some(value) => value,
            None => post_exit_halt(),
        };
        let page_table_result = (|| {
            transition::populate_page_table(&plan, post_exit, &mut table).map_err(|_| ())?;
            let attestation = table.attest(&plan).map_err(|_| ())?;
            let encoded_len = paging_handoff
                .write_paging_handoff_carrier(&attestation)
                .map_err(|_| ())?;
            if encoded_len != paging_handoff_byte_len {
                return Err(());
            }
            Ok(attestation)
        })();
        let (page_table_attestation, page_table_accepted) =
            match super::super::accept_page_table(page_table_result) {
                Ok(value) => value,
                Err(error) => super::super::dispatch_post_exit_failure(error, |_| post_exit_halt()),
            };
        let serial_result = (|| {
            // SAFETY: EBS completed and this loader exclusively owns COM1
            // for the final bounded marker path.
            let mut serial = unsafe { crate::handoff_x86_64::Com1Writer::initialize(100_000) }
                .map_err(|_| ())?;
            crate::handoff_x86_64::write_final_handoff_marker(&mut serial, 100_000)
                .map_err(|_| ())?;
            Ok::<(), ()>(())
        })();
        let (_, serial_accepted) = match super::super::accept_serial_diagnostic(serial_result) {
            Ok(value) => value,
            Err(error) => super::super::dispatch_post_exit_failure(error, |_| post_exit_halt()),
        };
        // SAFETY: EBS completed, this is the BSP in x86_64 supervisor
        // mode, and the helper validates NX/WP/paging/segment state.
        let entry_state =
            match unsafe { crate::handoff_x86_64::enable_and_verify_entry_state(true) } {
                Ok(value) => value,
                Err(_) => post_exit_halt(),
            };
        let (transfer, transfer_accepted) = match super::super::accept_transfer(
            crate::handoff_x86_64::prepare_x86_64_transfer(page_table_attestation, entry_state),
        ) {
            Ok(value) => value,
            Err(error) => super::super::dispatch_post_exit_failure(error, |_| post_exit_halt()),
        };
        let jump_authorization = super::super::authorize_jump(
            final_map_accepted,
            boot_info_accepted,
            page_table_accepted,
            serial_accepted,
            transfer_accepted,
            retained_addresses,
        );
        // SAFETY: `transfer` binds the finalized transition mappings,
        // table root, BootInfo pointer, stack, linked stub, and verified
        // machine state. This path is deliberately nonreturning.
        unsafe { jump_to_kernel_authorized(jump_authorization, transfer) }
    }
}

#[cfg(all(target_arch = "x86_64", target_os = "uefi"))]
pub(crate) struct MaterializedInputs {
    pub(crate) bootstrap: RetainedPages,
    pub(crate) bootfs: RetainedPages,
    pub(crate) boot_device_table: Option<RetainedPages>,
    pub(crate) acpi_rsdp: Option<AcpiRsdp>,
    pub(crate) framebuffer: Option<FramebufferMetadata>,
    pub(crate) entropy: FirmwareEntropy,
}

#[cfg(all(target_arch = "x86_64", target_os = "uefi"))]
impl MaterializedInputs {
    pub(crate) fn release_before_exit(self) {
        // SAFETY: this type exists only while boot services remain live,
        // and consumes every uniquely owned retained allocation.
        unsafe { self.bootstrap.release() };
        // SAFETY: same unique pre-EBS ownership as `bootstrap`.
        unsafe { self.bootfs.release() };
        if let Some(boot_device_table) = self.boot_device_table {
            // SAFETY: same unique pre-EBS ownership as `bootfs`.
            unsafe { boot_device_table.release() };
        }
        if let Some(rsdp) = self.acpi_rsdp {
            // SAFETY: the retained RSDP copy is still pre-EBS and unique.
            unsafe { rsdp.storage.release() };
        }
        if let FirmwareEntropy::Available { storage, .. } = self.entropy {
            // SAFETY: the retained entropy copy is still pre-EBS and unique.
            unsafe { storage.release() };
        }
    }

    pub(crate) fn into_post_exit(self) -> PostExitInputs {
        let acpi_rsdp = self.acpi_rsdp.map(|rsdp| {
            let _validated_revision = rsdp.revision;
            PostExitAcpiRsdp {
                storage: rsdp.storage.into_post_exit(),
                byte_len: rsdp.byte_len,
            }
        });
        let entropy = match self.entropy {
            FirmwareEntropy::Available {
                storage,
                source,
                conditioned,
            } => PostExitEntropy::Available {
                storage: storage.into_post_exit(),
                source,
                conditioned,
            },
            FirmwareEntropy::Unavailable => PostExitEntropy::Unavailable,
            FirmwareEntropy::Failed => PostExitEntropy::Failed,
        };
        PostExitInputs {
            bootstrap: self.bootstrap.into_post_exit(),
            bootfs: self.bootfs.into_post_exit(),
            boot_device_table: self.boot_device_table.map(RetainedPages::into_post_exit),
            acpi_rsdp,
            framebuffer: self.framebuffer,
            entropy,
        }
    }
}
