//! WYR1-D production UART driver staging policy.
//!
//! The production lifecycle is deliberately split into exact DeviceResource
//! and Interrupt stages.  UART causes remain disabled until the latter has
//! been freshly validated, and stream failures remain isolated from hardware
//! custody.

#![no_std]
#![forbid(unsafe_code)]

#[cfg(feature = "dw1e3-selector31")]
use wyrmroot_dw1e3_com2_test as _;

#[cfg(test)]
extern crate std;

#[cfg(test)]
use wyrmroot_devmgr as _;
#[cfg(feature = "native-uart16550d")]
use {wyrmroot_loader as _, wyrmroot_runtime as _};

use deepwyrm_syscall::{
    DW_DEVICE_RESOURCE_INFO_V1_SIZE, DW_DEVICE_RESOURCE_INFO_V1_VERSION,
    DW_DEVICE_RESOURCE_KIND_X86_PIO_WITH_PLATFORM_INTERRUPT, DW_INTERRUPT_INFO_V1_SIZE,
    DW_INTERRUPT_INFO_V1_VERSION, DW_INTERRUPT_STATE_ARMED, DW_OBJECT_TYPE_CHANNEL,
    DW_OBJECT_TYPE_DEVICE_RESOURCE, DW_OBJECT_TYPE_INTERRUPT, DW_RIGHT_INSPECT, DW_RIGHT_MODIFY,
    DW_RIGHT_READ, DW_RIGHT_WAIT, DW_RIGHT_WRITE, DW_SIGNAL_PEER_CLOSED, DW_SIGNAL_READABLE,
    DwDeviceResourceInfoV1, DwHandle, DwInterruptInfoV1, DwObjectType, DwRights, DwSignals,
};
use wyrmroot_device_proto::control_v1_1::{ControlIdentityV1_1, ControlMessageV1_1};
use wyrmroot_stream_proto::{MAX_PAYLOAD_BYTES, MAX_RECORD_BYTES, decode_data, encode_data};
use wyrmroot_uart16550_core::{
    ByteRegisterIo, CoreError, CoreState, InterruptWork, RING_CAPACITY, Uart16550,
};

pub const COM2_RESOURCE_ID: u64 = 1;
pub const COM2_PIO_BASE: u16 = 0x2f8;
pub const COM2_PIO_LENGTH: u16 = 8;
pub const COM2_INTERRUPT_SOURCE: u32 = 3;
pub const DEVICE_RESOURCE_RIGHTS: DwRights =
    DwRights(DW_RIGHT_READ.0 | DW_RIGHT_WRITE.0 | DW_RIGHT_INSPECT.0);
pub const RAW_STREAM_RIGHTS: DwRights =
    DwRights(DW_RIGHT_READ.0 | DW_RIGHT_WRITE.0 | DW_RIGHT_WAIT.0 | DW_RIGHT_INSPECT.0);
pub const INTERRUPT_RIGHTS: DwRights =
    DwRights(DW_RIGHT_WAIT.0 | DW_RIGHT_MODIFY.0 | DW_RIGHT_INSPECT.0);

/// Both startup handoff waits are fail-closed: once the control peer has
/// closed, queued readability cannot authorize further hardware activation.
pub const fn startup_control_is_readable(index: u32, signals: DwSignals) -> bool {
    index == 0 && signals.0 & DW_SIGNAL_PEER_CLOSED.0 == 0 && signals.0 & DW_SIGNAL_READABLE.0 != 0
}

/// Tracks a closed stream whose final queued DATA cannot yet be received
/// without violating the 1024-byte TX admission gate.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PeerCloseDrain {
    pending: bool,
}

impl PeerCloseDrain {
    pub const fn new() -> Self {
        Self { pending: false }
    }

    pub fn observe(&mut self) {
        self.pending = true;
    }

    pub fn clear(&mut self) {
        self.pending = false;
    }

    pub const fn is_pending(self) -> bool {
        self.pending
    }

    /// Omits the stream wait item while a sticky PEER_CLOSED signal would
    /// hot-loop but TX capacity cannot admit the next maximum DATA record.
    pub const fn include_stream_wait(self, receive_capacity: bool) -> bool {
        !self.pending || receive_capacity
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StreamSendResult {
    Sent,
    WouldBlock,
    PeerClosed,
    Failed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StreamSendAction {
    Continue,
    Detached(ControlMessageV1_1, ReceivedStreamEndpoint),
}

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
pub struct ReceivedInterrupt {
    pub handle: DwHandle,
    pub object_type: DwObjectType,
    pub rights: DwRights,
    pub reserved0: u32,
    pub reserved: [u64; 2],
    pub info: DwInterruptInfoV1,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DriverError {
    Stage(StageError),
    NotActive,
    RegisterIo,
    Interrupt(CoreError),
    InterruptAck,
    StreamProtocol,
    StreamHandles,
    StreamCapacity,
}

#[derive(Debug, Eq, PartialEq)]
pub struct DrainedInterrupt {
    handle: DwHandle,
    work: InterruptWork,
}

impl DrainedInterrupt {
    pub const fn work(&self) -> InterruptWork {
        self.work
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct DriverCounters {
    pub interrupt_wakes: u32,
    pub interrupt_acks: u32,
    pub interrupt_failures: u32,
    pub ack_failures: u32,
    pub pio_failures: u32,
    pub malformed_streams: u32,
    pub stream_detaches: u32,
    pub rx_records: u32,
    pub tx_records: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CloseStep {
    DisableInterrupts,
    ClearStreamState,
    CloseStream(DwHandle),
    CloseInterrupt(DwHandle),
    CloseDeviceResource(DwHandle),
    CloseControl(DwHandle),
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

    pub const fn active_generations(&self) -> Option<(u64, u64)> {
        match self.active {
            Some((_, stream_generation, publication_generation, _)) => {
                Some((stream_generation, publication_generation))
            }
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
    startup_identity: ControlIdentityV1_1,
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
            || identity.transaction_id == startup.transaction_id
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
            startup_identity: startup,
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

    /// Joins the exact post-DEVICE_QUIESCED state to one freshly queried
    /// Interrupt.  No UART interrupt enable write occurs in this method.
    pub fn validate_interrupt(
        self,
        message: ControlMessageV1_1,
        interrupt: ReceivedInterrupt,
    ) -> Result<ProductionDriver<I>, StageError> {
        if self.uart.state() != CoreState::Quiesced {
            return Err(StageError::RegisterIo);
        }
        let ControlMessageV1_1::InterruptStage {
            identity,
            stage_generation,
            parent_resource_id,
            source,
        } = message
        else {
            return Err(StageError::WrongMessage);
        };
        if identity.role_id != self.identity.role_id
            || identity.bundle_generation != self.identity.bundle_generation
            || identity.attempt_generation != self.identity.attempt_generation
            || identity.endpoint != self.identity.endpoint
            || identity.transaction_id == 0
            || identity.transaction_id == self.identity.transaction_id
            || identity.transaction_id == self.startup_identity.transaction_id
            || stage_generation != self.stage_generation
        {
            return Err(StageError::WrongCorrelation);
        }
        let ready_transaction_id = identity
            .transaction_id
            .checked_add(1)
            .ok_or(StageError::WrongCorrelation)?;
        let ready_identity = ControlIdentityV1_1 {
            transaction_id: ready_transaction_id,
            ..identity
        };
        if interrupt.handle.0 == 0
            || interrupt.object_type != DW_OBJECT_TYPE_INTERRUPT
            || interrupt.rights != INTERRUPT_RIGHTS
            || interrupt.reserved0 != 0
            || interrupt.reserved != [0; 2]
        {
            return Err(StageError::WrongHandle);
        }
        let info = interrupt.info;
        if parent_resource_id != self.resource.info.resource_id
            || source != self.resource.info.interrupt_source
            || info.size != DW_INTERRUPT_INFO_V1_SIZE
            || info.version != DW_INTERRUPT_INFO_V1_VERSION
            || info.source != source
            || info.state != DW_INTERRUPT_STATE_ARMED
            || info.object_generation == 0
            || info.binding_generation == 0
            || info.parent_resource_id != parent_resource_id
            || info.parent_lease_generation != self.resource.info.lease_generation
            || info.flags.0 != 0
            || info.reserved0 != 0
            || info.reserved != 0
        {
            return Err(StageError::WrongResource);
        }
        Ok(ProductionDriver {
            ready_identity,
            resource: self.resource,
            interrupt,
            uart: self.uart,
            stream: StreamAttachment::new(ready_identity),
            pending_rx: [0; MAX_PAYLOAD_BYTES],
            pending_rx_len: 0,
            counters: DriverCounters::default(),
            active: false,
        })
    }
}

/// Exact bounded work classes in descending service priority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReadyWork {
    ControlRetire,
    ControlReadable,
    Interrupt,
    StreamPeerClosed,
    StreamReadable,
    StreamWritable,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ReadySet {
    pub control_retire: bool,
    pub control_readable: bool,
    pub interrupt: bool,
    pub stream_peer_closed: bool,
    pub stream_readable: bool,
    pub stream_writable: bool,
}

impl ReadySet {
    /// Selects one bounded quantum. Control retirement and control traffic are
    /// always considered before hardware and client stream work.
    pub const fn highest_priority(self) -> Option<ReadyWork> {
        if self.control_retire {
            Some(ReadyWork::ControlRetire)
        } else if self.control_readable {
            Some(ReadyWork::ControlReadable)
        } else if self.interrupt {
            Some(ReadyWork::Interrupt)
        } else if self.stream_readable {
            Some(ReadyWork::StreamReadable)
        } else if self.stream_peer_closed {
            Some(ReadyWork::StreamPeerClosed)
        } else if self.stream_writable {
            Some(ReadyWork::StreamWritable)
        } else {
            None
        }
    }
}

/// The joined D3B/D3D state after exact Interrupt intake but before
/// production READY.  Handle closure remains an explicit caller operation so
/// native code and host models can prove the same order.
#[derive(Debug)]
pub struct ProductionDriver<I> {
    ready_identity: ControlIdentityV1_1,
    resource: ReceivedDeviceResource,
    interrupt: ReceivedInterrupt,
    uart: Uart16550<I>,
    stream: StreamAttachment,
    pending_rx: [u8; MAX_PAYLOAD_BYTES],
    pending_rx_len: usize,
    counters: DriverCounters,
    active: bool,
}

impl<I: ByteRegisterIo> ProductionDriver<I> {
    pub const fn identity(&self) -> ControlIdentityV1_1 {
        self.ready_identity
    }

    pub const fn resource(&self) -> ReceivedDeviceResource {
        self.resource
    }

    pub const fn interrupt(&self) -> ReceivedInterrupt {
        self.interrupt
    }

    pub fn uart(&self) -> &Uart16550<I> {
        &self.uart
    }

    pub fn uart_mut(&mut self) -> &mut Uart16550<I> {
        &mut self.uart
    }

    pub const fn counters(&self) -> DriverCounters {
        self.counters
    }

    pub const fn stream_endpoint(&self) -> Option<ReceivedStreamEndpoint> {
        self.stream.active_endpoint()
    }

    pub const fn stream_generations(&self) -> Option<(u64, u64)> {
        self.stream.active_generations()
    }

    pub fn tx_free(&self) -> usize {
        RING_CAPACITY - self.uart.tx_len()
    }

    pub fn rx_len(&self) -> usize {
        self.uart.rx_len()
    }

    pub fn copy_rx_from(&self, offset: usize, output: &mut [u8]) -> usize {
        self.uart.copy_rx_from(offset, output)
    }

    pub fn wants_stream_readable(&self) -> bool {
        self.stream.active_endpoint().is_some() && self.tx_free() >= MAX_PAYLOAD_BYTES
    }

    pub fn wants_stream_writable(&self) -> bool {
        self.stream.active_endpoint().is_some()
            && (self.pending_rx_len != 0 || self.uart.rx_len() != 0)
    }

    /// This is the only operation which enables RDI/RLSI. The caller checks
    /// its sticky native PIO adapter immediately afterwards, before sending
    /// the returned production READY.
    pub fn activate(&mut self) -> Result<ControlMessageV1_1, DriverError> {
        if self.active || self.uart.state() != CoreState::Quiesced {
            return Err(DriverError::NotActive);
        }
        self.uart.activate_interrupts();
        if self.uart.state() != CoreState::Active {
            return Err(DriverError::NotActive);
        }
        self.active = true;
        Ok(ControlMessageV1_1::Ready {
            identity: self.ready_identity,
        })
    }

    /// Drains all currently indicated UART causes and returns a single-use ack
    /// token. No acknowledgement is possible until the native adapter has
    /// checked its sticky PIO health.
    pub fn drain_interrupt(&mut self) -> Result<DrainedInterrupt, DriverError> {
        if !self.active {
            return Err(DriverError::NotActive);
        }
        self.counters.interrupt_wakes = self.counters.interrupt_wakes.saturating_add(1);
        let work = match self.uart.handle_interrupt() {
            Ok(work) => work,
            Err(error) => {
                self.counters.interrupt_failures =
                    self.counters.interrupt_failures.saturating_add(1);
                return Err(DriverError::Interrupt(error));
            }
        };
        Ok(DrainedInterrupt {
            handle: self.interrupt.handle,
            work,
        })
    }

    /// Acknowledges exactly one successfully drained pending epoch. A sticky
    /// PIO failure is checked first and suppresses the ack.
    pub fn acknowledge_interrupt(
        &mut self,
        drained: DrainedInterrupt,
        pio_healthy: bool,
        mut acknowledge: impl FnMut(DwHandle) -> Result<(), ()>,
    ) -> Result<InterruptWork, DriverError> {
        if !pio_healthy {
            self.counters.pio_failures = self.counters.pio_failures.saturating_add(1);
            return Err(DriverError::RegisterIo);
        }
        if acknowledge(drained.handle).is_err() {
            self.counters.ack_failures = self.counters.ack_failures.saturating_add(1);
            return Err(DriverError::InterruptAck);
        }
        self.counters.interrupt_acks = self.counters.interrupt_acks.saturating_add(1);
        Ok(drained.work)
    }

    pub fn attach_stream(
        &mut self,
        message: ControlMessageV1_1,
        endpoint: ReceivedStreamEndpoint,
    ) -> Result<ControlMessageV1_1, StreamAttachError> {
        self.stream.attach(message, endpoint)
    }

    pub fn detach_stream(&mut self) -> Option<(ControlMessageV1_1, ReceivedStreamEndpoint)> {
        self.pending_rx_len = 0;
        let detached = self.stream.detach();
        if detached.is_some() {
            self.counters.stream_detaches = self.counters.stream_detaches.saturating_add(1);
        }
        detached
    }

    /// Selector-private stage-1 retirement: IER is zero and only the raw
    /// stream endpoint is detached. The caller deliberately retains the
    /// Interrupt/resource/control handles for controller-authorized stage 2.
    pub fn begin_selector_retire(
        &mut self,
    ) -> Option<(ControlMessageV1_1, ReceivedStreamEndpoint)> {
        self.uart.disable_interrupts();
        self.detach_stream()
    }

    /// Accepts one complete handle-free WRST record only while the maximum
    /// legal payload can fit. Malformed input is classified for stream-only
    /// isolation by the caller.
    pub fn accept_stream_record(
        &mut self,
        wire: &[u8],
        received_handles: usize,
    ) -> Result<usize, DriverError> {
        if received_handles != 0 {
            self.counters.malformed_streams = self.counters.malformed_streams.saturating_add(1);
            return Err(DriverError::StreamHandles);
        }
        if self.stream.active_endpoint().is_none() || self.tx_free() < MAX_PAYLOAD_BYTES {
            return Err(DriverError::StreamCapacity);
        }
        let payload = match decode_data(wire) {
            Ok(data) => data.payload(),
            Err(_) => {
                self.counters.malformed_streams = self.counters.malformed_streams.saturating_add(1);
                return Err(DriverError::StreamProtocol);
            }
        };
        let accepted = self.uart.enqueue_tx(payload);
        if accepted != payload.len() {
            return Err(DriverError::StreamCapacity);
        }
        self.counters.rx_records = self.counters.rx_records.saturating_add(1);
        Ok(accepted)
    }

    /// Builds at most one WRST DATA record by copying without removing the
    /// UART ring prefix. A WOULD_BLOCK result therefore loses no bytes.
    pub fn prepare_stream_send(
        &mut self,
        output: &mut [u8; MAX_RECORD_BYTES],
    ) -> Result<Option<usize>, DriverError> {
        if self.stream.active_endpoint().is_none() {
            return Ok(None);
        }
        if self.pending_rx_len == 0 {
            self.pending_rx_len = self.uart.copy_rx(&mut self.pending_rx);
        }
        if self.pending_rx_len == 0 {
            return Ok(None);
        }
        encode_data(&self.pending_rx[..self.pending_rx_len], output)
            .map(Some)
            .map_err(|_| DriverError::StreamProtocol)
    }

    /// Commits a prepared record only after the Channel send succeeds.
    pub fn commit_stream_send(&mut self) {
        if self.pending_rx_len != 0 {
            debug_assert_eq!(
                self.uart.discard_rx(self.pending_rx_len),
                self.pending_rx_len
            );
            self.pending_rx_len = 0;
            self.counters.tx_records = self.counters.tx_records.saturating_add(1);
        }
    }

    pub const fn pending_stream_bytes(&self) -> usize {
        self.pending_rx_len
    }

    /// Applies the state transition for one attempted WRST send. A peer-close
    /// result preserves both the endpoint and prepared UART RX prefix so the
    /// receive side can drain final queued DATA before detaching.
    pub fn resolve_stream_send(
        &mut self,
        drain: &mut PeerCloseDrain,
        result: StreamSendResult,
    ) -> StreamSendAction {
        match result {
            StreamSendResult::Sent => {
                self.commit_stream_send();
                StreamSendAction::Continue
            }
            StreamSendResult::WouldBlock => StreamSendAction::Continue,
            StreamSendResult::PeerClosed => {
                drain.observe();
                StreamSendAction::Continue
            }
            StreamSendResult::Failed => {
                drain.clear();
                match self.detach_stream() {
                    Some((message, endpoint)) => StreamSendAction::Detached(message, endpoint),
                    None => StreamSendAction::Continue,
                }
            }
        }
    }

    /// Produces the exact graceful-close order. The caller performs the first
    /// IER=0 step best-effort while the resource remains usable and does not
    /// wait for TX FIFO drain.
    pub fn close_steps(&self, control: DwHandle, output: &mut [Option<CloseStep>; 6]) -> usize {
        output.fill(None);
        let mut count = 0;
        for step in [
            Some(CloseStep::DisableInterrupts),
            Some(CloseStep::ClearStreamState),
            self.stream
                .active_endpoint()
                .map(|endpoint| CloseStep::CloseStream(endpoint.handle)),
            Some(CloseStep::CloseInterrupt(self.interrupt.handle)),
            Some(CloseStep::CloseDeviceResource(self.resource.handle)),
            Some(CloseStep::CloseControl(control)),
        ]
        .into_iter()
        .flatten()
        {
            output[count] = Some(step);
            count += 1;
        }
        count
    }

    pub fn into_uart(self) -> Uart16550<I> {
        self.uart
    }

    #[cfg(test)]
    fn test_counters_mut(&mut self) -> &mut DriverCounters {
        &mut self.counters
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use deepwyrm_syscall::{DwObjectType, DwRights};
    use std::{cell::RefCell, collections::VecDeque, rc::Rc, vec::Vec};
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

    #[derive(Debug)]
    struct ScriptedIo {
        reads: [VecDeque<u8>; 8],
        writes: Vec<(u8, u8)>,
        trace: Rc<RefCell<Vec<&'static str>>>,
    }

    impl ScriptedIo {
        fn new(trace: Rc<RefCell<Vec<&'static str>>>) -> Self {
            Self {
                reads: core::array::from_fn(|_| VecDeque::new()),
                writes: Vec::new(),
                trace,
            }
        }

        fn push_reads(&mut self, offset: u8, values: impl IntoIterator<Item = u8>) {
            self.reads[usize::from(offset)].extend(values);
        }
    }

    impl ByteRegisterIo for ScriptedIo {
        fn read(&mut self, offset: u8) -> u8 {
            self.trace.borrow_mut().push("read");
            self.reads[usize::from(offset)]
                .pop_front()
                .unwrap_or(if offset == 2 { 1 } else { 0 })
        }

        fn write(&mut self, offset: u8, value: u8) {
            self.trace.borrow_mut().push("write");
            self.writes.push((offset, value));
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

    fn interrupt(transaction: u64) -> (ControlMessageV1_1, ReceivedInterrupt) {
        let info = DwInterruptInfoV1 {
            size: DW_INTERRUPT_INFO_V1_SIZE,
            version: DW_INTERRUPT_INFO_V1_VERSION,
            source: COM2_INTERRUPT_SOURCE,
            state: DW_INTERRUPT_STATE_ARMED,
            object_generation: 10,
            binding_generation: 11,
            parent_resource_id: COM2_RESOURCE_ID,
            parent_lease_generation: 2,
            ..DwInterruptInfoV1::default()
        };
        (
            ControlMessageV1_1::InterruptStage {
                identity: identity(transaction),
                stage_generation: 7,
                parent_resource_id: COM2_RESOURCE_ID,
                source: COM2_INTERRUPT_SOURCE,
            },
            ReceivedInterrupt {
                handle: DwHandle(12),
                object_type: DW_OBJECT_TYPE_INTERRUPT,
                rights: INTERRUPT_RIGHTS,
                reserved0: 0,
                reserved: [0; 2],
                info,
            },
        )
    }

    fn production<I: ByteRegisterIo>(io: I) -> ProductionDriver<I> {
        let mut stage = DeviceStage::validate(identity(99), message(), resource(), io).unwrap();
        stage.initialize_quiesced().unwrap();
        let (interrupt_message, interrupt) = interrupt(8);
        stage
            .validate_interrupt(interrupt_message, interrupt)
            .unwrap()
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

    #[test]
    fn interrupt_stage_is_exact_fresh_and_activation_is_last() {
        let mut stage =
            DeviceStage::validate(identity(99), message(), resource(), FakeIo::new()).unwrap();
        stage.initialize_quiesced().unwrap();
        let (interrupt_message, interrupt) = interrupt(8);
        let mut driver = stage
            .validate_interrupt(interrupt_message, interrupt)
            .unwrap();
        assert_eq!(driver.uart().state(), CoreState::Quiesced);
        assert_eq!(
            driver.activate().unwrap(),
            ControlMessageV1_1::Ready {
                identity: identity(9)
            }
        );
        assert_eq!(driver.uart().state(), CoreState::Active);

        let mut stale = interrupt_message;
        if let ControlMessageV1_1::InterruptStage {
            ref mut identity, ..
        } = stale
        {
            identity.transaction_id = 6;
        }
        let mut stage =
            DeviceStage::validate(identity(99), message(), resource(), FakeIo::new()).unwrap();
        stage.initialize_quiesced().unwrap();
        assert!(matches!(
            stage.validate_interrupt(stale, interrupt),
            Err(StageError::WrongCorrelation)
        ));

        let mut wrong = interrupt;
        wrong.info.binding_generation = 0;
        let mut stage =
            DeviceStage::validate(identity(99), message(), resource(), FakeIo::new()).unwrap();
        stage.initialize_quiesced().unwrap();
        assert!(matches!(
            stage.validate_interrupt(interrupt_message, wrong),
            Err(StageError::WrongResource)
        ));
    }

    #[test]
    fn irq_drain_precedes_one_ack_and_ack_failure_is_fatal() {
        let trace = Rc::new(RefCell::new(Vec::new()));
        let mut io = ScriptedIo::new(trace.clone());
        // Quiesced stale drain consumes IIR=NO_INT. Active wake sees THRI,
        // then NO_INT after filling one queued byte.
        io.push_reads(2, [1, 2, 1]);
        let mut driver = production(io);
        driver.activate().unwrap();
        assert_eq!(driver.uart_mut().enqueue_tx(b"x"), 1);
        trace.borrow_mut().clear();
        let drained = driver.drain_interrupt().unwrap();
        assert_ne!(trace.borrow().last(), Some(&"ack"));
        let work = driver
            .acknowledge_interrupt(drained, true, |handle| {
                assert_eq!(handle, DwHandle(12));
                trace.borrow_mut().push("ack");
                Ok(())
            })
            .unwrap();
        assert_eq!(work.transmitted, 1);
        let trace = trace.borrow();
        assert_eq!(trace.last(), Some(&"ack"));
        assert_eq!(trace.iter().filter(|entry| **entry == "ack").count(), 1);
        drop(trace);

        let drained = driver.drain_interrupt().unwrap();
        assert_eq!(
            driver.acknowledge_interrupt(drained, true, |_| Err(())),
            Err(DriverError::InterruptAck)
        );
        assert_eq!(driver.counters().ack_failures, 1);
    }

    #[test]
    fn unknown_interrupt_fails_without_ack() {
        let trace = Rc::new(RefCell::new(Vec::new()));
        let mut io = ScriptedIo::new(trace);
        io.push_reads(2, [1, 0x0a]);
        let mut driver = production(io);
        driver.activate().unwrap();
        assert!(matches!(
            driver.drain_interrupt(),
            Err(DriverError::Interrupt(CoreError::UnknownInterruptCause(
                0x0a
            )))
        ));
        assert!(matches!(driver.uart().state(), CoreState::Failed(_)));
    }

    #[test]
    fn stream_backpressure_malformed_isolation_and_reconnect_preserve_driver() {
        let mut driver = production(FakeIo::new());
        driver.activate().unwrap();
        let endpoint = ReceivedStreamEndpoint {
            handle: DwHandle(20),
            object_type: DW_OBJECT_TYPE_CHANNEL,
            rights: RAW_STREAM_RIGHTS,
            reserved0: 0,
            reserved: [0; 2],
        };
        let attach = ControlMessageV1_1::AttachStream {
            identity: identity(21),
            stream_generation: 22,
            publication_generation: 23,
        };
        driver.attach_stream(attach, endpoint).unwrap();
        assert_eq!(
            driver.accept_stream_record(b"bad", 0),
            Err(DriverError::StreamProtocol)
        );
        let (_, released) = driver.detach_stream().unwrap();
        assert_eq!(released.handle, DwHandle(20));
        let fresh = ControlMessageV1_1::AttachStream {
            identity: identity(24),
            stream_generation: 25,
            publication_generation: 23,
        };
        assert!(driver.attach_stream(fresh, endpoint).is_ok());
        assert_eq!(driver.uart().state(), CoreState::Active);

        let payload = [0x5a; MAX_PAYLOAD_BYTES];
        let mut wire = [0; MAX_RECORD_BYTES];
        let size = encode_data(&payload, &mut wire).unwrap();
        for _ in 0..4 {
            assert_eq!(driver.accept_stream_record(&wire[..size], 0), Ok(1024));
        }
        assert!(!driver.wants_stream_readable());
        assert_eq!(
            driver.accept_stream_record(&wire[..size], 0),
            Err(DriverError::StreamCapacity)
        );
    }

    #[test]
    fn control_priority_close_order_and_counters_are_bounded() {
        assert_eq!(
            ReadySet {
                control_retire: true,
                interrupt: true,
                stream_readable: true,
                ..ReadySet::default()
            }
            .highest_priority(),
            Some(ReadyWork::ControlRetire)
        );
        assert_eq!(
            ReadySet {
                interrupt: true,
                stream_peer_closed: true,
                ..ReadySet::default()
            }
            .highest_priority(),
            Some(ReadyWork::Interrupt)
        );

        let mut driver = production(FakeIo::new());
        driver.activate().unwrap();
        driver
            .attach_stream(
                ControlMessageV1_1::AttachStream {
                    identity: identity(21),
                    stream_generation: 22,
                    publication_generation: 23,
                },
                ReceivedStreamEndpoint {
                    handle: DwHandle(20),
                    object_type: DW_OBJECT_TYPE_CHANNEL,
                    rights: RAW_STREAM_RIGHTS,
                    reserved0: 0,
                    reserved: [0; 2],
                },
            )
            .unwrap();
        let mut steps = [None; 6];
        assert_eq!(driver.close_steps(DwHandle(30), &mut steps), 6);
        assert_eq!(
            steps,
            [
                Some(CloseStep::DisableInterrupts),
                Some(CloseStep::ClearStreamState),
                Some(CloseStep::CloseStream(DwHandle(20))),
                Some(CloseStep::CloseInterrupt(DwHandle(12))),
                Some(CloseStep::CloseDeviceResource(DwHandle(9))),
                Some(CloseStep::CloseControl(DwHandle(30))),
            ]
        );

        driver.test_counters_mut().interrupt_wakes = u32::MAX;
        let drained = driver.drain_interrupt().unwrap();
        driver
            .acknowledge_interrupt(drained, true, |_| Ok(()))
            .unwrap();
        assert_eq!(driver.counters().interrupt_wakes, u32::MAX);
    }

    #[test]
    fn startup_peer_close_wins_and_stream_readable_drains_before_detach() {
        let both = DwSignals(DW_SIGNAL_READABLE.0 | DW_SIGNAL_PEER_CLOSED.0);
        assert!(!startup_control_is_readable(0, both));
        assert!(!startup_control_is_readable(1, DW_SIGNAL_READABLE));
        assert!(startup_control_is_readable(0, DW_SIGNAL_READABLE));

        assert_eq!(
            ReadySet {
                stream_peer_closed: true,
                stream_readable: true,
                ..ReadySet::default()
            }
            .highest_priority(),
            Some(ReadyWork::StreamReadable)
        );

        let mut driver = production(FakeIo::new());
        driver.activate().unwrap();
        let endpoint = ReceivedStreamEndpoint {
            handle: DwHandle(20),
            object_type: DW_OBJECT_TYPE_CHANNEL,
            rights: RAW_STREAM_RIGHTS,
            reserved0: 0,
            reserved: [0; 2],
        };
        driver
            .attach_stream(
                ControlMessageV1_1::AttachStream {
                    identity: identity(21),
                    stream_generation: 22,
                    publication_generation: 23,
                },
                endpoint,
            )
            .unwrap();
        let payload = b"final queued WRST data";
        let mut wire = [0; MAX_RECORD_BYTES];
        let size = encode_data(payload, &mut wire).unwrap();
        assert_eq!(
            driver.accept_stream_record(&wire[..size], 0),
            Ok(payload.len())
        );
        let (_, detached) = driver.detach_stream().unwrap();
        assert_eq!(detached, endpoint);
        assert_eq!(driver.uart().tx_len(), payload.len());
    }

    #[test]
    fn peer_close_drain_pauses_at_capacity_then_accepts_the_fifth_record() {
        let trace = Rc::new(RefCell::new(Vec::new()));
        let mut io = ScriptedIo::new(trace);
        let interrupt_reads = core::iter::once(1).chain((0..64).flat_map(|_| [2, 1]));
        io.push_reads(2, interrupt_reads);
        let mut driver = production(io);
        driver.activate().unwrap();
        let endpoint = ReceivedStreamEndpoint {
            handle: DwHandle(20),
            object_type: DW_OBJECT_TYPE_CHANNEL,
            rights: RAW_STREAM_RIGHTS,
            reserved0: 0,
            reserved: [0; 2],
        };
        driver
            .attach_stream(
                ControlMessageV1_1::AttachStream {
                    identity: identity(21),
                    stream_generation: 22,
                    publication_generation: 23,
                },
                endpoint,
            )
            .unwrap();

        let payload = [0x5a; MAX_PAYLOAD_BYTES];
        let mut wire = [0; MAX_RECORD_BYTES];
        let size = encode_data(&payload, &mut wire).unwrap();
        let mut queued = VecDeque::from([wire; 5]);
        let mut drain = PeerCloseDrain::new();
        drain.observe();
        while drain.is_pending() && driver.wants_stream_readable() && !queued.is_empty() {
            assert_eq!(
                driver.accept_stream_record(&queued.front().unwrap()[..size], 0),
                Ok(payload.len())
            );
            queued.pop_front();
        }
        assert_eq!(queued.len(), 1);
        assert_eq!(driver.uart().tx_len(), RING_CAPACITY);
        assert!(!drain.include_stream_wait(driver.wants_stream_readable()));
        assert_eq!(driver.stream_endpoint(), Some(endpoint));

        let mut transmitted = 0;
        for _ in 0..64 {
            let drained = driver.drain_interrupt().unwrap();
            transmitted += driver
                .acknowledge_interrupt(drained, true, |_| Ok(()))
                .unwrap()
                .transmitted;
        }
        assert!(driver.wants_stream_readable());
        assert!(drain.include_stream_wait(driver.wants_stream_readable()));
        assert_eq!(
            driver.accept_stream_record(&queued.front().unwrap()[..size], 0),
            Ok(payload.len())
        );
        queued.pop_front();
        assert!(queued.is_empty());

        drain.clear();
        let (_, detached) = driver.detach_stream().unwrap();
        assert_eq!(detached, endpoint);
        assert_eq!(transmitted, 1024);
        assert_eq!(driver.uart().tx_len(), RING_CAPACITY);
        assert_eq!(
            usize::from(transmitted) + driver.uart().tx_len(),
            5 * MAX_PAYLOAD_BYTES
        );
    }

    #[test]
    fn send_peer_close_preserves_final_inbound_data_until_empty_queue_proof() {
        fn driver_with_pending_rx() -> (ProductionDriver<ScriptedIo>, ReceivedStreamEndpoint) {
            let trace = Rc::new(RefCell::new(Vec::new()));
            let mut io = ScriptedIo::new(trace);
            io.push_reads(2, [1, 4, 1]);
            io.push_reads(5, [0, 1, 0]);
            io.push_reads(0, [0x41]);
            let mut driver = production(io);
            driver.activate().unwrap();
            let endpoint = ReceivedStreamEndpoint {
                handle: DwHandle(20),
                object_type: DW_OBJECT_TYPE_CHANNEL,
                rights: RAW_STREAM_RIGHTS,
                reserved0: 0,
                reserved: [0; 2],
            };
            driver
                .attach_stream(
                    ControlMessageV1_1::AttachStream {
                        identity: identity(21),
                        stream_generation: 22,
                        publication_generation: 23,
                    },
                    endpoint,
                )
                .unwrap();
            let drained = driver.drain_interrupt().unwrap();
            assert_eq!(drained.work().received, 1);
            driver
                .acknowledge_interrupt(drained, true, |_| Ok(()))
                .unwrap();
            let mut wire = [0; MAX_RECORD_BYTES];
            assert!(driver.prepare_stream_send(&mut wire).unwrap().is_some());
            (driver, endpoint)
        }

        let (mut driver, endpoint) = driver_with_pending_rx();
        let mut drain = PeerCloseDrain::new();
        assert_eq!(driver.pending_stream_bytes(), 1);
        assert_eq!(driver.rx_len(), 1);
        assert!(driver.wants_stream_writable());
        assert_eq!(driver.counters().tx_records, 0);

        assert_eq!(
            driver.resolve_stream_send(&mut drain, StreamSendResult::PeerClosed),
            StreamSendAction::Continue
        );
        assert_eq!(driver.stream_endpoint(), Some(endpoint));
        assert!(drain.is_pending());
        assert_eq!(driver.pending_stream_bytes(), 1);
        assert_eq!(driver.rx_len(), 1);
        assert_eq!(driver.counters().tx_records, 0);
        assert!(!(!drain.is_pending() && driver.wants_stream_writable()));
        assert!(drain.include_stream_wait(driver.wants_stream_readable()));

        let payload = b"final queued WRST data";
        let mut wire = [0; MAX_RECORD_BYTES];
        let size = encode_data(payload, &mut wire).unwrap();
        assert_eq!(
            driver.accept_stream_record(&wire[..size], 0),
            Ok(payload.len())
        );
        assert_eq!(driver.stream_endpoint(), Some(endpoint));
        assert_eq!(driver.uart().tx_len(), payload.len());

        let (_, detached) = driver.detach_stream().unwrap();
        drain.clear();
        assert_eq!(detached, endpoint);
        assert_eq!(driver.stream_endpoint(), None);
        assert_eq!(driver.uart().tx_len(), payload.len());
        assert_eq!(driver.pending_stream_bytes(), 0);
        assert_eq!(driver.rx_len(), 1);
        assert_eq!(driver.counters().tx_records, 0);
        assert_eq!(driver.counters().rx_records, 1);

        let (mut failed, endpoint) = driver_with_pending_rx();
        let mut failed_drain = PeerCloseDrain::new();
        failed_drain.observe();
        let StreamSendAction::Detached(_, detached) =
            failed.resolve_stream_send(&mut failed_drain, StreamSendResult::Failed)
        else {
            panic!("non-peer send failure must detach");
        };
        assert_eq!(detached, endpoint);
        assert!(!failed_drain.is_pending());
        assert_eq!(failed.stream_endpoint(), None);
        assert_eq!(failed.pending_stream_bytes(), 0);
        assert_eq!(failed.rx_len(), 1);
        assert_eq!(failed.counters().tx_records, 0);

        let (mut blocked, endpoint) = driver_with_pending_rx();
        let mut blocked_drain = PeerCloseDrain::new();
        assert_eq!(
            blocked.resolve_stream_send(&mut blocked_drain, StreamSendResult::WouldBlock),
            StreamSendAction::Continue
        );
        assert_eq!(blocked.stream_endpoint(), Some(endpoint));
        assert_eq!(blocked.pending_stream_bytes(), 1);
        assert_eq!(blocked.rx_len(), 1);

        assert_eq!(
            blocked.resolve_stream_send(&mut blocked_drain, StreamSendResult::Sent),
            StreamSendAction::Continue
        );
        assert_eq!(blocked.pending_stream_bytes(), 0);
        assert_eq!(blocked.rx_len(), 0);
        assert_eq!(blocked.counters().tx_records, 1);
    }
}
