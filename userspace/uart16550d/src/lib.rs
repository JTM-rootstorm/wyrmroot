//! WYR1-D production UART driver staging policy.
//!
//! D3A ends after exact DeviceResource intake and silent UART quiescence. It
//! intentionally contains no Interrupt stage, activation, wait/ack loop, or
//! raw-stream event loop; those belong to D3B and D3D.

#![no_std]
#![forbid(unsafe_code)]

#[cfg(test)]
use wyrmroot_devmgr as _;
#[cfg(feature = "native-uart16550d")]
use {wyrmroot_loader as _, wyrmroot_runtime as _};

use deepwyrm_syscall::{
    DW_DEVICE_RESOURCE_INFO_V1_SIZE, DW_DEVICE_RESOURCE_INFO_V1_VERSION,
    DW_DEVICE_RESOURCE_KIND_X86_PIO_WITH_PLATFORM_INTERRUPT, DW_OBJECT_TYPE_CHANNEL,
    DW_OBJECT_TYPE_DEVICE_RESOURCE, DW_RIGHT_INSPECT, DW_RIGHT_READ, DW_RIGHT_WAIT, DW_RIGHT_WRITE,
    DwDeviceResourceInfoV1, DwHandle, DwObjectType, DwRights,
};
use wyrmroot_device_proto::control_v1_1::{ControlIdentityV1_1, ControlMessageV1_1};
use wyrmroot_uart16550_core::{ByteRegisterIo, CoreError, CoreState, Uart16550};

pub const COM2_RESOURCE_ID: u64 = 1;
pub const COM2_PIO_BASE: u16 = 0x2f8;
pub const COM2_PIO_LENGTH: u16 = 8;
pub const COM2_INTERRUPT_SOURCE: u32 = 3;
pub const DEVICE_RESOURCE_RIGHTS: DwRights =
    DwRights(DW_RIGHT_READ.0 | DW_RIGHT_WRITE.0 | DW_RIGHT_INSPECT.0);
pub const RAW_STREAM_RIGHTS: DwRights =
    DwRights(DW_RIGHT_READ.0 | DW_RIGHT_WRITE.0 | DW_RIGHT_WAIT.0 | DW_RIGHT_INSPECT.0);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReceivedDeviceResource {
    pub handle: DwHandle,
    pub object_type: DwObjectType,
    pub rights: DwRights,
    pub reserved0: u32,
    pub reserved: [u64; 2],
    pub info: DwDeviceResourceInfoV1,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StageError {
    WrongMessage,
    WrongCorrelation,
    WrongHandle,
    WrongResource,
    Uart(CoreError),
    RegisterIo,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReceivedStreamEndpoint {
    pub handle: DwHandle,
    pub object_type: DwObjectType,
    pub rights: DwRights,
    pub reserved0: u32,
    pub reserved: [u64; 2],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StreamAttachError {
    Busy,
    WrongMessage,
    WrongCorrelation,
    WrongHandle,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StreamAttachment {
    driver: ControlIdentityV1_1,
    active: Option<(u64, u64, u64, ReceivedStreamEndpoint)>,
}

impl StreamAttachment {
    pub const fn new(driver: ControlIdentityV1_1) -> Self {
        Self {
            driver,
            active: None,
        }
    }

    pub const fn active_endpoint(&self) -> Option<ReceivedStreamEndpoint> {
        match self.active {
            Some((_, _, _, endpoint)) => Some(endpoint),
            None => None,
        }
    }

    /// Accepts only the exact current ATTACH_STREAM and one moved Channel.
    /// D3C does not read or write WRST bytes; D3D owns that event loop.
    pub fn attach(
        &mut self,
        message: ControlMessageV1_1,
        endpoint: ReceivedStreamEndpoint,
    ) -> Result<ControlMessageV1_1, StreamAttachError> {
        if self.active.is_some() {
            return Err(StreamAttachError::Busy);
        }
        let ControlMessageV1_1::AttachStream {
            identity,
            stream_generation,
            publication_generation,
        } = message
        else {
            return Err(StreamAttachError::WrongMessage);
        };
        if identity.role_id != self.driver.role_id
            || identity.bundle_generation != self.driver.bundle_generation
            || identity.attempt_generation != self.driver.attempt_generation
            || identity.endpoint != self.driver.endpoint
            || identity.transaction_id == 0
            || stream_generation == 0
            || publication_generation == 0
        {
            return Err(StreamAttachError::WrongCorrelation);
        }
        if endpoint.handle.0 == 0
            || endpoint.object_type != DW_OBJECT_TYPE_CHANNEL
            || endpoint.rights != RAW_STREAM_RIGHTS
            || endpoint.reserved0 != 0
            || endpoint.reserved != [0; 2]
        {
            return Err(StreamAttachError::WrongHandle);
        }
        self.active = Some((
            identity.transaction_id,
            stream_generation,
            publication_generation,
            endpoint,
        ));
        Ok(ControlMessageV1_1::StreamReady {
            identity,
            stream_generation,
            publication_generation,
        })
    }

    pub fn detach(&mut self) -> Option<(ControlMessageV1_1, ReceivedStreamEndpoint)> {
        let (transaction_id, stream_generation, publication_generation, endpoint) =
            self.active.take()?;
        Some((
            ControlMessageV1_1::StreamDetached {
                identity: ControlIdentityV1_1 {
                    transaction_id,
                    ..self.driver
                },
                stream_generation,
                publication_generation,
            },
            endpoint,
        ))
    }
}

impl From<CoreError> for StageError {
    fn from(error: CoreError) -> Self {
        Self::Uart(error)
    }
}

#[derive(Debug)]
pub struct DeviceStage<I> {
    identity: ControlIdentityV1_1,
    stage_generation: u64,
    resource: ReceivedDeviceResource,
    uart: Uart16550<I>,
}

impl<I: ByteRegisterIo> DeviceStage<I> {
    /// Validates the complete WRDC correlation, exact reduced capability, and
    /// a fresh DeviceResource info record before any register access occurs.
    pub fn validate(
        startup: ControlIdentityV1_1,
        message: ControlMessageV1_1,
        resource: ReceivedDeviceResource,
        io: I,
    ) -> Result<Self, StageError> {
        let ControlMessageV1_1::DeviceStage {
            identity,
            stage_generation,
            resource_id,
            pio_base,
            pio_length,
            source,
        } = message
        else {
            return Err(StageError::WrongMessage);
        };
        if identity.role_id != startup.role_id
            || identity.bundle_generation != startup.bundle_generation
            || identity.attempt_generation != startup.attempt_generation
            || identity.endpoint != startup.endpoint
            || identity.transaction_id == 0
            || stage_generation == 0
        {
            return Err(StageError::WrongCorrelation);
        }
        if resource.handle.0 == 0
            || resource.object_type != DW_OBJECT_TYPE_DEVICE_RESOURCE
            || resource.rights != DEVICE_RESOURCE_RIGHTS
            || resource.reserved0 != 0
            || resource.reserved != [0; 2]
        {
            return Err(StageError::WrongHandle);
        }
        let info = resource.info;
        if resource_id != COM2_RESOURCE_ID
            || pio_base != COM2_PIO_BASE
            || pio_length != COM2_PIO_LENGTH
            || source != COM2_INTERRUPT_SOURCE
            || info.size != DW_DEVICE_RESOURCE_INFO_V1_SIZE
            || info.version != DW_DEVICE_RESOURCE_INFO_V1_VERSION
            || info.kind != DW_DEVICE_RESOURCE_KIND_X86_PIO_WITH_PLATFORM_INTERRUPT
            || info.flags != 0
            || info.resource_id != resource_id
            || info.lease_generation != identity.bundle_generation.0
            || info.pio_base != pio_base
            || info.pio_length != pio_length
            || info.interrupt_source != source
            || info.reserved != 0
        {
            return Err(StageError::WrongResource);
        }
        Ok(Self {
            identity,
            stage_generation,
            resource,
            uart: Uart16550::new(io),
        })
    }

    pub const fn resource(&self) -> ReceivedDeviceResource {
        self.resource
    }

    pub fn uart(&self) -> &Uart16550<I> {
        &self.uart
    }

    /// Performs the D2 silent initialization and only then creates the exact
    /// DEVICE_QUIESCED response. IER remains zero at this D3A boundary.
    pub fn initialize_quiesced(&mut self) -> Result<ControlMessageV1_1, StageError> {
        self.uart.initialize_quiesced()?;
        if self.uart.state() != CoreState::Quiesced {
            return Err(StageError::RegisterIo);
        }
        Ok(ControlMessageV1_1::DeviceQuiesced {
            identity: self.identity,
            stage_generation: self.stage_generation,
        })
    }

    pub fn into_parts(self) -> (ReceivedDeviceResource, Uart16550<I>) {
        (self.resource, self.uart)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use deepwyrm_syscall::{DwObjectType, DwRights};
    use wyrmroot_device_proto::control::ControlEndpoint;
    use wyrmroot_device_proto::coordinator::{
        AttemptGeneration, BundleGeneration, EndpointGeneration, EndpointId,
    };
    use wyrmroot_device_proto::manifest::RoleId;

    #[derive(Debug)]
    struct FakeIo {
        writes: [(u8, u8); 16],
        write_len: usize,
    }

    impl FakeIo {
        const fn new() -> Self {
            Self {
                writes: [(0, 0); 16],
                write_len: 0,
            }
        }
    }

    impl ByteRegisterIo for FakeIo {
        fn read(&mut self, offset: u8) -> u8 {
            if offset == 2 { 1 } else { 0 }
        }

        fn write(&mut self, offset: u8, value: u8) {
            self.writes[self.write_len] = (offset, value);
            self.write_len += 1;
        }
    }

    fn identity(transaction: u64) -> ControlIdentityV1_1 {
        ControlIdentityV1_1 {
            role_id: RoleId(1),
            bundle_generation: BundleGeneration(2),
            attempt_generation: AttemptGeneration(3),
            endpoint: ControlEndpoint {
                id: EndpointId(4),
                generation: EndpointGeneration(5),
            },
            transaction_id: transaction,
        }
    }

    fn message() -> ControlMessageV1_1 {
        ControlMessageV1_1::DeviceStage {
            identity: identity(6),
            stage_generation: 7,
            resource_id: COM2_RESOURCE_ID,
            pio_base: COM2_PIO_BASE,
            pio_length: COM2_PIO_LENGTH,
            source: COM2_INTERRUPT_SOURCE,
        }
    }

    fn resource() -> ReceivedDeviceResource {
        ReceivedDeviceResource {
            handle: DwHandle(9),
            object_type: DW_OBJECT_TYPE_DEVICE_RESOURCE,
            rights: DEVICE_RESOURCE_RIGHTS,
            reserved0: 0,
            reserved: [0; 2],
            info: DwDeviceResourceInfoV1 {
                size: DW_DEVICE_RESOURCE_INFO_V1_SIZE,
                version: DW_DEVICE_RESOURCE_INFO_V1_VERSION,
                kind: DW_DEVICE_RESOURCE_KIND_X86_PIO_WITH_PLATFORM_INTERRUPT,
                flags: 0,
                resource_id: COM2_RESOURCE_ID,
                lease_generation: 2,
                pio_base: COM2_PIO_BASE,
                pio_length: COM2_PIO_LENGTH,
                interrupt_source: COM2_INTERRUPT_SOURCE,
                reserved: 0,
            },
        }
    }

    #[test]
    fn exact_stage_reaches_quiesced_gate_with_ier_zero_first() {
        let mut stage =
            DeviceStage::validate(identity(99), message(), resource(), FakeIo::new()).unwrap();
        assert_eq!(stage.uart().state(), CoreState::Reset);
        assert_eq!(
            stage.initialize_quiesced().unwrap(),
            ControlMessageV1_1::DeviceQuiesced {
                identity: identity(6),
                stage_generation: 7
            }
        );
        let (_, uart) = stage.into_parts();
        let io = uart.into_io();
        assert_eq!(io.writes[0], (1, 0));
        assert_eq!(io.writes[io.write_len - 1], (4, 0x0b));
        assert!(!io.writes[..io.write_len].contains(&(1, 0x05)));
    }

    #[test]
    fn rights_resource_and_generation_mismatches_precede_io() {
        let mut bad_rights = resource();
        bad_rights.rights = DwRights(DW_RIGHT_READ.0 | DW_RIGHT_INSPECT.0);
        assert!(matches!(
            DeviceStage::validate(identity(99), message(), bad_rights, FakeIo::new()),
            Err(StageError::WrongHandle)
        ));

        let mut bad_info = resource();
        bad_info.info.lease_generation = 3;
        assert!(matches!(
            DeviceStage::validate(identity(99), message(), bad_info, FakeIo::new()),
            Err(StageError::WrongResource)
        ));

        let mut wrong_type = resource();
        wrong_type.object_type = DwObjectType(0);
        assert!(matches!(
            DeviceStage::validate(identity(99), message(), wrong_type, FakeIo::new()),
            Err(StageError::WrongHandle)
        ));

        let mut reserved_metadata = resource();
        reserved_metadata.reserved[1] = 1;
        assert!(matches!(
            DeviceStage::validate(identity(99), message(), reserved_metadata, FakeIo::new()),
            Err(StageError::WrongHandle)
        ));
    }

    #[test]
    fn one_stream_endpoint_attaches_ready_detaches_and_reconnects() {
        let mut streams = StreamAttachment::new(identity(6));
        let endpoint = ReceivedStreamEndpoint {
            handle: DwHandle(10),
            object_type: DW_OBJECT_TYPE_CHANNEL,
            rights: RAW_STREAM_RIGHTS,
            reserved0: 0,
            reserved: [0; 2],
        };
        let attach = ControlMessageV1_1::AttachStream {
            identity: identity(11),
            stream_generation: 12,
            publication_generation: 13,
        };
        assert_eq!(
            streams.attach(attach, endpoint).unwrap(),
            ControlMessageV1_1::StreamReady {
                identity: identity(11),
                stream_generation: 12,
                publication_generation: 13,
            }
        );
        assert_eq!(
            streams.attach(attach, endpoint),
            Err(StreamAttachError::Busy)
        );
        let (detached, released) = streams.detach().unwrap();
        assert_eq!(released, endpoint);
        assert_eq!(
            detached,
            ControlMessageV1_1::StreamDetached {
                identity: identity(11),
                stream_generation: 12,
                publication_generation: 13,
            }
        );
        let fresh = ControlMessageV1_1::AttachStream {
            identity: identity(14),
            stream_generation: 15,
            publication_generation: 13,
        };
        assert!(streams.attach(fresh, endpoint).is_ok());

        let mut malformed_endpoint = endpoint;
        malformed_endpoint.reserved0 = 1;
        streams.detach().unwrap();
        assert_eq!(
            streams.attach(fresh, malformed_endpoint),
            Err(StreamAttachError::WrongHandle)
        );
    }
}
