//! Bounded, allocation-free policy for the WYR1-D q35 16550 UART.
//!
//! This crate has no port-I/O implementation.  A D3 `DeviceResource` adapter
//! supplies [`ByteRegisterIo`]; host tests use a fake implementation.

#![no_std]
#![forbid(unsafe_code)]

#[cfg(test)]
extern crate std;

/// q35's fixed COM2 PIO base.  The core itself never uses this address.
pub const COM2_PIO_BASE: u16 = 0x2f8;
/// Fixed receive and transmit software-ring capacity.
pub const RING_CAPACITY: usize = 4096;
/// q35's 16550A transmit FIFO capacity used by one THRI service.
pub const TX_FIFO_CAPACITY: usize = 16;
/// Maximum IIR causes handled for one interrupt wake or stale drain.
pub const DRAIN_LIMIT: usize = 256;

const RBR_THR_DLL: u8 = 0;
const IER_DLM: u8 = 1;
const IIR_FCR: u8 = 2;
const LCR: u8 = 3;
const MCR: u8 = 4;
const LSR: u8 = 5;
const MSR: u8 = 6;

const LCR_8N1: u8 = 0x03;
const LCR_DLAB: u8 = 0x80;
const FCR_ENABLE_AND_CLEAR: u8 = 0x07;
const MCR_OUT2_RTS_DTR: u8 = 0x0b;
const IER_RDI_RLSI: u8 = 0x05;
const IER_THRI: u8 = 0x02;

const IIR_NO_INTERRUPT: u8 = 0x01;
const IIR_CAUSE_MASK: u8 = 0x0e;
const IIR_MSI: u8 = 0x00;
const IIR_THRI: u8 = 0x02;
const IIR_RDI: u8 = 0x04;
const IIR_RLSI: u8 = 0x06;
const IIR_RX_TIMEOUT: u8 = 0x0c;

const LSR_DR: u8 = 0x01;
const LSR_OE: u8 = 0x02;
const LSR_PE: u8 = 0x04;
const LSR_FE: u8 = 0x08;
const LSR_BI: u8 = 0x10;

/// Injectable, byte-oriented UART register access.
pub trait ByteRegisterIo {
    /// Reads one byte from the register at `offset`.
    fn read(&mut self, offset: u8) -> u8;
    /// Writes one byte to the register at `offset`.
    fn write(&mut self, offset: u8, value: u8);
}

/// State visible to the D3 adapter for staged handoff and failure reporting.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CoreState {
    /// No resource has been configured.
    Reset,
    /// Stale state was cleared; IER remains exactly zero.
    Quiesced,
    /// RDI/RLSI are enabled; THRI follows the transmit-ring state.
    Active,
    /// A bounded drain or IIR decode failed; IER was disabled.
    Failed(CoreError),
}

/// Fail-closed outcomes which require driver retirement rather than retry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CoreError {
    /// A drain remained indicated past its finite bound.
    DrainLimit,
    /// The UART exposed an IIR cause encoding outside the 16550 set.
    UnknownInterruptCause(u8),
}

/// Saturating diagnostics retained across a driver attempt.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ErrorCounters {
    /// Hardware line-status overrun events.
    pub hardware_overrun: u32,
    /// Hardware parity errors.
    pub parity: u32,
    /// Hardware framing errors.
    pub framing: u32,
    /// Hardware break indications.
    pub break_indication: u32,
    /// Bytes dropped because the fixed receive ring was full.
    pub rx_software_overrun_bytes: u32,
    /// Modem-status interrupts seen despite MSI being disabled.
    pub unexpected_modem_status: u32,
}

/// Work completed during one bounded interrupt wake.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct InterruptWork {
    /// UART causes serviced before the caller may acknowledge its Interrupt.
    pub causes: u16,
    /// Hardware receive bytes consumed, including dropped-newest bytes.
    pub received: u16,
    /// Bytes supplied to the transmit FIFO.
    pub transmitted: u16,
}

/// A fixed-capacity byte FIFO with no allocation and explicit drop policy.
#[derive(Clone, Debug, Eq, PartialEq)]
struct Ring {
    bytes: [u8; RING_CAPACITY],
    head: usize,
    tail: usize,
    len: usize,
}

impl Ring {
    const fn new() -> Self {
        Self {
            bytes: [0; RING_CAPACITY],
            head: 0,
            tail: 0,
            len: 0,
        }
    }

    fn is_empty(&self) -> bool {
        self.len == 0
    }
    fn is_full(&self) -> bool {
        self.len == RING_CAPACITY
    }
    fn len(&self) -> usize {
        self.len
    }

    fn push(&mut self, byte: u8) -> bool {
        if self.is_full() {
            return false;
        }
        self.bytes[self.tail] = byte;
        self.tail = (self.tail + 1) % RING_CAPACITY;
        self.len += 1;
        true
    }

    fn pop(&mut self) -> Option<u8> {
        if self.is_empty() {
            return None;
        }
        let byte = self.bytes[self.head];
        self.head = (self.head + 1) % RING_CAPACITY;
        self.len -= 1;
        Some(byte)
    }

    fn copy_to(&self, output: &mut [u8]) -> usize {
        let count = core::cmp::min(self.len, output.len());
        for (index, byte) in output[..count].iter_mut().enumerate() {
            *byte = self.bytes[(self.head + index) % RING_CAPACITY];
        }
        count
    }

    fn discard(&mut self, count: usize) -> usize {
        let count = core::cmp::min(count, self.len);
        self.head = (self.head + count) % RING_CAPACITY;
        self.len -= count;
        count
    }
}

/// Pure UART policy state, parameterized only by its byte-register adapter.
#[derive(Debug)]
pub struct Uart16550<I> {
    io: I,
    rx: Ring,
    tx: Ring,
    state: CoreState,
    errors: ErrorCounters,
}

impl<I: ByteRegisterIo> Uart16550<I> {
    /// Creates a reset core.  This performs no device I/O.
    pub fn new(io: I) -> Self {
        Self {
            io,
            rx: Ring::new(),
            tx: Ring::new(),
            state: CoreState::Reset,
            errors: ErrorCounters::default(),
        }
    }

    /// Returns the injected adapter after all policy work is complete.
    pub fn into_io(self) -> I {
        self.io
    }
    #[cfg(test)]
    fn test_io_mut(&mut self) -> &mut I {
        &mut self.io
    }
    /// Returns the staged lifecycle state.
    pub fn state(&self) -> CoreState {
        self.state
    }
    /// Returns sticky, saturating diagnostics.
    pub fn error_counters(&self) -> ErrorCounters {
        self.errors
    }
    /// Returns queued receive bytes.
    pub fn rx_len(&self) -> usize {
        self.rx.len()
    }
    /// Returns queued transmit bytes.
    pub fn tx_len(&self) -> usize {
        self.tx.len()
    }
    /// Removes one previously received byte without touching hardware.
    pub fn dequeue_rx(&mut self) -> Option<u8> {
        self.rx.pop()
    }

    /// Copies queued receive bytes without removing them. D3 uses this to
    /// retain bytes in the UART ring across a WRST send `WOULD_BLOCK` race.
    pub fn copy_rx(&self, output: &mut [u8]) -> usize {
        self.rx.copy_to(output)
    }

    /// Removes exactly the prefix committed by a successful WRST send.
    pub fn discard_rx(&mut self, count: usize) -> usize {
        self.rx.discard(count)
    }

    /// Performs the exact silent initialization phase required before an
    /// Interrupt capability is staged.  It always leaves IER zero.
    pub fn initialize_quiesced(&mut self) -> Result<(), CoreError> {
        self.io.write(IER_DLM, 0);
        self.io.write(LCR, LCR_DLAB);
        self.io.write(RBR_THR_DLL, 1);
        self.io.write(IER_DLM, 0);
        self.io.write(LCR, LCR_8N1);
        self.io.write(IIR_FCR, FCR_ENABLE_AND_CLEAR);
        self.io.write(MCR, MCR_OUT2_RTS_DTR);
        self.rx = Ring::new();
        self.tx = Ring::new();
        self.state = CoreState::Quiesced;
        self.stale_drain()
    }

    /// Enables RDI and RLSI, plus THRI exactly when transmit work was queued
    /// during the quiesced stage.
    pub fn activate_interrupts(&mut self) {
        if self.state == CoreState::Quiesced {
            let ier = if self.tx.is_empty() {
                IER_RDI_RLSI
            } else {
                IER_RDI_RLSI | IER_THRI
            };
            self.io.write(IER_DLM, ier);
            self.state = CoreState::Active;
        }
    }

    /// Enqueues as many bytes as fit.  Unlike RX, callers retain the suffix
    /// when this fixed ring fills; no transmit byte is silently dropped.
    pub fn enqueue_tx(&mut self, bytes: &[u8]) -> usize {
        let was_empty = self.tx.is_empty();
        let mut count = 0;
        for &byte in bytes {
            if !self.tx.push(byte) {
                break;
            }
            count += 1;
        }
        if count != 0 && was_empty && self.state == CoreState::Active {
            self.io.write(IER_DLM, IER_RDI_RLSI | IER_THRI);
        }
        count
    }

    /// Services all currently indicated UART causes before the caller performs
    /// the one corresponding kernel `interrupt_ack`.
    pub fn handle_interrupt(&mut self) -> Result<InterruptWork, CoreError> {
        if self.state != CoreState::Active {
            return Ok(InterruptWork::default());
        }
        let mut work = InterruptWork::default();
        for _ in 0..DRAIN_LIMIT {
            let iir = self.io.read(IIR_FCR);
            if iir & IIR_NO_INTERRUPT != 0 {
                return Ok(work);
            }
            work.causes = work.causes.saturating_add(1);
            match iir & IIR_CAUSE_MASK {
                IIR_RLSI => self.handle_line_status(&mut work)?,
                IIR_RDI | IIR_RX_TIMEOUT => self.drain_receive(&mut work)?,
                IIR_THRI => self.fill_transmit(&mut work),
                IIR_MSI => {
                    let _ = self.io.read(MSR);
                    self.errors.unexpected_modem_status =
                        self.errors.unexpected_modem_status.saturating_add(1);
                }
                _ => return Err(self.fail(CoreError::UnknownInterruptCause(iir))),
            }
        }
        if self.io.read(IIR_FCR) & IIR_NO_INTERRUPT != 0 {
            return Ok(work);
        }
        Err(self.fail(CoreError::DrainLimit))
    }

    fn stale_drain(&mut self) -> Result<(), CoreError> {
        for _ in 0..DRAIN_LIMIT {
            let lsr = self.io.read(LSR);
            self.account_line_status(lsr);
            if lsr & LSR_DR != 0 {
                let _ = self.io.read(RBR_THR_DLL);
            }
            let _ = self.io.read(MSR);
            if self.io.read(IIR_FCR) & IIR_NO_INTERRUPT != 0 {
                return Ok(());
            }
        }
        if self.io.read(IIR_FCR) & IIR_NO_INTERRUPT != 0 {
            return Ok(());
        }
        Err(self.fail(CoreError::DrainLimit))
    }

    fn handle_line_status(&mut self, work: &mut InterruptWork) -> Result<(), CoreError> {
        let lsr = self.io.read(LSR);
        self.account_line_status(lsr);
        if lsr & LSR_DR != 0 {
            self.receive_one(work);
        }
        Ok(())
    }

    fn drain_receive(&mut self, work: &mut InterruptWork) -> Result<(), CoreError> {
        for _ in 0..DRAIN_LIMIT {
            let lsr = self.io.read(LSR);
            self.account_line_status(lsr);
            if lsr & LSR_DR == 0 {
                return Ok(());
            }
            self.receive_one(work);
        }
        let lsr = self.io.read(LSR);
        self.account_line_status(lsr);
        if lsr & LSR_DR == 0 {
            return Ok(());
        }
        Err(self.fail(CoreError::DrainLimit))
    }

    fn receive_one(&mut self, work: &mut InterruptWork) {
        let byte = self.io.read(RBR_THR_DLL);
        if !self.rx.push(byte) {
            self.errors.rx_software_overrun_bytes =
                self.errors.rx_software_overrun_bytes.saturating_add(1);
        }
        work.received = work.received.saturating_add(1);
    }

    fn fill_transmit(&mut self, work: &mut InterruptWork) {
        for _ in 0..TX_FIFO_CAPACITY {
            let Some(byte) = self.tx.pop() else {
                break;
            };
            self.io.write(RBR_THR_DLL, byte);
            work.transmitted = work.transmitted.saturating_add(1);
        }
        if self.tx.is_empty() {
            self.io.write(IER_DLM, IER_RDI_RLSI);
        }
    }

    fn account_line_status(&mut self, lsr: u8) {
        if lsr & LSR_OE != 0 {
            self.errors.hardware_overrun = self.errors.hardware_overrun.saturating_add(1);
        }
        if lsr & LSR_PE != 0 {
            self.errors.parity = self.errors.parity.saturating_add(1);
        }
        if lsr & LSR_FE != 0 {
            self.errors.framing = self.errors.framing.saturating_add(1);
        }
        if lsr & LSR_BI != 0 {
            self.errors.break_indication = self.errors.break_indication.saturating_add(1);
        }
    }

    fn fail(&mut self, error: CoreError) -> CoreError {
        self.io.write(IER_DLM, 0);
        self.state = CoreState::Failed(error);
        error
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::vec::Vec;

    #[derive(Debug)]
    struct FakeIo {
        reads: [VecDeque<u8>; 8],
        writes: Vec<(u8, u8)>,
    }

    impl FakeIo {
        fn new() -> Self {
            Self {
                reads: core::array::from_fn(|_| VecDeque::new()),
                writes: Vec::new(),
            }
        }

        fn push_reads(&mut self, offset: u8, values: impl IntoIterator<Item = u8>) {
            self.reads[usize::from(offset)].extend(values);
        }
    }

    impl ByteRegisterIo for FakeIo {
        fn read(&mut self, offset: u8) -> u8 {
            self.reads[usize::from(offset)]
                .pop_front()
                .unwrap_or(if offset == IIR_FCR {
                    IIR_NO_INTERRUPT
                } else {
                    0
                })
        }

        fn write(&mut self, offset: u8, value: u8) {
            self.writes.push((offset, value));
        }
    }

    fn active() -> Uart16550<FakeIo> {
        let mut uart = Uart16550::new(FakeIo::new());
        uart.initialize_quiesced().unwrap();
        uart.activate_interrupts();
        uart
    }

    #[test]
    fn quiesced_init_has_exact_writes_and_never_enables_ier() {
        let mut uart = Uart16550::new(FakeIo::new());
        uart.initialize_quiesced().unwrap();
        assert_eq!(uart.state(), CoreState::Quiesced);
        let fake = uart.into_io();
        assert_eq!(
            fake.writes,
            [
                (IER_DLM, 0),
                (LCR, LCR_DLAB),
                (RBR_THR_DLL, 1),
                (IER_DLM, 0),
                (LCR, LCR_8N1),
                (IIR_FCR, FCR_ENABLE_AND_CLEAR),
                (MCR, MCR_OUT2_RTS_DTR),
            ]
        );
    }

    #[test]
    fn activation_enables_only_receive_and_line_status() {
        let uart = active();
        assert_eq!(uart.state(), CoreState::Active);
        assert_eq!(uart.into_io().writes.last(), Some(&(IER_DLM, IER_RDI_RLSI)));
    }

    #[test]
    fn queued_quiesced_tx_enables_thri_on_activation_and_drains() {
        let mut uart = Uart16550::new(FakeIo::new());
        uart.initialize_quiesced().unwrap();
        let writes_before_queue = uart.test_io_mut().writes.len();
        assert_eq!(uart.enqueue_tx(&[0x41, 0x42]), 2);
        assert_eq!(uart.test_io_mut().writes.len(), writes_before_queue);
        uart.activate_interrupts();
        assert_eq!(
            uart.test_io_mut().writes.last(),
            Some(&(IER_DLM, IER_RDI_RLSI | IER_THRI))
        );
        uart.test_io_mut()
            .push_reads(IIR_FCR, [IIR_THRI, IIR_NO_INTERRUPT]);
        assert_eq!(uart.handle_interrupt().unwrap().transmitted, 2);
        assert_eq!(uart.tx_len(), 0);
        assert_eq!(
            uart.test_io_mut().writes.last(),
            Some(&(IER_DLM, IER_RDI_RLSI))
        );
    }

    #[test]
    fn all_iir_causes_are_bounded_and_accounted() {
        let mut uart = active();
        {
            let fake = uart.test_io_mut();
            fake.push_reads(
                IIR_FCR,
                [IIR_RLSI, IIR_RDI, IIR_RX_TIMEOUT, IIR_MSI, IIR_NO_INTERRUPT],
            );
            fake.push_reads(
                LSR,
                [
                    LSR_DR | LSR_OE | LSR_PE | LSR_FE | LSR_BI,
                    LSR_DR,
                    0,
                    LSR_DR,
                    0,
                ],
            );
            fake.push_reads(RBR_THR_DLL, [0x41, 0x42, 0x43]);
            fake.push_reads(MSR, [0x80]);
        }
        let work = uart.handle_interrupt().unwrap();
        assert_eq!(work.causes, 4);
        assert_eq!(work.received, 3);
        assert_eq!(
            uart.error_counters(),
            ErrorCounters {
                hardware_overrun: 1,
                parity: 1,
                framing: 1,
                break_indication: 1,
                rx_software_overrun_bytes: 0,
                unexpected_modem_status: 1,
            }
        );
        assert_eq!(
            [uart.dequeue_rx(), uart.dequeue_rx(), uart.dequeue_rx()],
            [Some(0x41), Some(0x42), Some(0x43)]
        );
    }

    #[test]
    fn timeout_is_receive_work_and_unknown_iir_fails_closed() {
        let mut uart = active();
        {
            let fake = uart.test_io_mut();
            fake.push_reads(IIR_FCR, [IIR_RX_TIMEOUT, IIR_NO_INTERRUPT]);
            fake.push_reads(LSR, [LSR_DR, 0]);
            fake.push_reads(RBR_THR_DLL, [0x55]);
        }
        assert_eq!(uart.handle_interrupt().unwrap().received, 1);
        uart.test_io_mut().push_reads(IIR_FCR, [0x08]);
        assert_eq!(
            uart.handle_interrupt(),
            Err(CoreError::UnknownInterruptCause(0x08))
        );
        assert_eq!(
            uart.state(),
            CoreState::Failed(CoreError::UnknownInterruptCause(0x08))
        );
        assert_eq!(uart.into_io().writes.last(), Some(&(IER_DLM, 0)));
    }

    #[test]
    fn tx_interrupt_tracks_empty_transitions_and_never_polls_idle_hardware() {
        let uart = active();
        let writes_after_activation = uart.into_io().writes.len();
        let mut uart = active();
        assert_eq!(uart.enqueue_tx(&[1, 2, 3]), 3);
        assert_eq!(uart.test_io_mut().writes.len(), writes_after_activation + 1);
        assert_eq!(
            uart.test_io_mut().writes.last(),
            Some(&(IER_DLM, IER_RDI_RLSI | IER_THRI))
        );
        uart.test_io_mut()
            .push_reads(IIR_FCR, [IIR_THRI, IIR_NO_INTERRUPT]);
        assert_eq!(uart.handle_interrupt().unwrap().transmitted, 3);
        let fake = uart.into_io();
        assert_eq!(fake.writes.last(), Some(&(IER_DLM, IER_RDI_RLSI)));
    }

    #[test]
    fn thri_supplies_at_most_one_q35_fifo() {
        let mut uart = active();
        let bytes = [0x5a; TX_FIFO_CAPACITY + 1];
        assert_eq!(uart.enqueue_tx(&bytes), bytes.len());
        uart.test_io_mut()
            .push_reads(IIR_FCR, [IIR_THRI, IIR_NO_INTERRUPT]);
        let work = uart.handle_interrupt().unwrap();
        assert_eq!(work.transmitted, TX_FIFO_CAPACITY as u16);
        assert_eq!(uart.tx_len(), 1);
        assert_eq!(uart.test_io_mut().writes.last(), Some(&(RBR_THR_DLL, 0x5a)));
    }

    #[test]
    fn rx_overflow_drops_newest_and_saturates_counter() {
        let mut uart = active();
        {
            let fake = uart.test_io_mut();
            for byte in 0..RING_CAPACITY + 1 {
                fake.push_reads(IIR_FCR, [IIR_RDI, IIR_NO_INTERRUPT]);
                fake.push_reads(LSR, [LSR_DR, 0]);
                fake.push_reads(RBR_THR_DLL, [byte as u8]);
            }
        }
        for _ in 0..RING_CAPACITY + 1 {
            uart.handle_interrupt().unwrap();
        }
        assert_eq!(uart.rx_len(), RING_CAPACITY);
        assert_eq!(uart.error_counters().rx_software_overrun_bytes, 1);
    }

    #[test]
    fn drain_limit_accepts_256_causes_and_rejects_a_257th() {
        let mut uart = active();
        let fake = uart.test_io_mut();
        fake.push_reads(
            IIR_FCR,
            core::iter::repeat_n(IIR_RDI, DRAIN_LIMIT).chain([IIR_NO_INTERRUPT]),
        );
        fake.push_reads(LSR, core::iter::repeat_n(LSR_DR, DRAIN_LIMIT).chain([0]));
        fake.push_reads(RBR_THR_DLL, core::iter::repeat_n(0x5a, DRAIN_LIMIT));
        assert_eq!(uart.handle_interrupt().unwrap().causes, DRAIN_LIMIT as u16);

        let mut uart = active();
        let fake = uart.test_io_mut();
        fake.push_reads(IIR_FCR, core::iter::repeat_n(IIR_RDI, DRAIN_LIMIT + 1));
        fake.push_reads(LSR, core::iter::repeat_n(LSR_DR, DRAIN_LIMIT + 1));
        fake.push_reads(RBR_THR_DLL, core::iter::repeat_n(0x5a, DRAIN_LIMIT + 1));
        assert_eq!(uart.handle_interrupt(), Err(CoreError::DrainLimit));
    }

    #[test]
    fn diagnostics_are_sticky_and_saturating() {
        let mut uart = active();
        uart.errors.hardware_overrun = u32::MAX;
        uart.errors.rx_software_overrun_bytes = u32::MAX;
        uart.rx.len = RING_CAPACITY;
        {
            let fake = uart.test_io_mut();
            fake.push_reads(IIR_FCR, [IIR_RLSI, IIR_RDI, IIR_NO_INTERRUPT]);
            fake.push_reads(LSR, [LSR_OE, LSR_DR, 0]);
            fake.push_reads(RBR_THR_DLL, [0x44]);
        }
        uart.handle_interrupt().unwrap();
        assert_eq!(uart.error_counters().hardware_overrun, u32::MAX);
        assert_eq!(uart.error_counters().rx_software_overrun_bytes, u32::MAX);
    }
}
