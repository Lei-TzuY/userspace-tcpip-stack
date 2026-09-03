//! PTP Hardware Clock (PHC) Emulation & Cross-Timestamping Subsystem (IEEE 1588-2019 / Linux ptp_clock).
//!
//! Models physical network interface card (NIC) and PHY PTP Hardware Clocks (PHC),
//! hardware frequency tuning (ppb) with sub-nanosecond fractional accumulation, hardware
//! phase step adjustments, high-precision cross-timestamping (PTP_SYS_OFFSET_PRECISE) for
//! host system clock disciplining, and hardware TX/RX event timestamping FIFO ring buffers.

use crate::ptp::{PTP_MSG_DELAY_REQ, PTP_MSG_SYNC, PtpPacket, PtpTimestamp};
use std::collections::VecDeque;

/// Sub-nanosecond scale factor (2^32 fractional units per nanosecond).
pub const FRACT_NS_SCALE: f64 = 4_294_967_296.0;

/// PTP Hardware Clock (PHC) Device Emulation.
#[derive(Debug, Clone, PartialEq)]
pub struct PtpHardwareClock {
    pub seconds: u64,
    pub nanoseconds: u32,
    pub sub_nanoseconds_fract: u32, // Fraction of 1 ns in units of 2^-32 ns
    pub freq_adjustment_ppb: f64,   // Frequency steering offset in parts-per-billion
    pub total_stepped_ns: i64,      // Total cumulative stepped phase
}

impl Default for PtpHardwareClock {
    fn default() -> Self {
        Self::new(0, 0)
    }
}

impl PtpHardwareClock {
    pub fn new(seconds: u64, nanoseconds: u32) -> Self {
        Self {
            seconds,
            nanoseconds: nanoseconds.min(999_999_999),
            sub_nanoseconds_fract: 0,
            freq_adjustment_ppb: 0.0,
            total_stepped_ns: 0,
        }
    }

    /// Reads current hardware timestamp.
    pub fn get_time(&self) -> PtpTimestamp {
        PtpTimestamp::new(self.seconds, self.nanoseconds)
    }

    /// Sets hardware time counter to target timestamp.
    pub fn set_time(&mut self, ts: PtpTimestamp) {
        self.seconds = ts.seconds;
        self.nanoseconds = ts.nanoseconds.min(999_999_999);
        self.sub_nanoseconds_fract = 0;
    }

    /// Adjusts hardware oscillator frequency by `ppb` parts-per-billion (IEEE 1588 adjfreq).
    pub fn adj_freq_ppb(&mut self, ppb: f64) {
        self.freq_adjustment_ppb = ppb.clamp(-1_000_000.0, 1_000_000.0);
    }

    /// Steps the hardware clock phase by `step_ns` nanoseconds (IEEE 1588 adjtime).
    pub fn step_time_ns(&mut self, step_ns: i64) {
        self.total_stepped_ns += step_ns;

        let total_ns =
            (self.seconds as i128) * 1_000_000_000 + (self.nanoseconds as i128) + (step_ns as i128);

        if total_ns >= 0 {
            self.seconds = (total_ns / 1_000_000_000) as u64;
            self.nanoseconds = (total_ns % 1_000_000_000) as u32;
        } else {
            self.seconds = 0;
            self.nanoseconds = 0;
        }
    }

    /// Advances the hardware clock counter by `elapsed_real_ns` nanoseconds,
    /// taking into account the active frequency steering rate and fractional sub-nanoseconds.
    pub fn tick_ns(&mut self, elapsed_real_ns: u64) {
        let scale = 1.0 + (self.freq_adjustment_ppb / 1_000_000_000.0);
        let current_fraction = (self.sub_nanoseconds_fract as f64) / FRACT_NS_SCALE;

        let total_advanced_ns = (elapsed_real_ns as f64) * scale + current_fraction;
        let whole_ns = total_advanced_ns.floor() as u64;
        let new_fraction = total_advanced_ns - (whole_ns as f64);

        self.sub_nanoseconds_fract = (new_fraction * FRACT_NS_SCALE).round() as u32;

        let total_ns = (self.nanoseconds as u64) + whole_ns;
        self.seconds += total_ns / 1_000_000_000;
        self.nanoseconds = (total_ns % 1_000_000_000) as u32;
    }
}

/// Precision Cross-Timestamping Entry (IEEE 1588-2019 Clause 9.2.5 / Linux PTP_SYS_OFFSET_PRECISE).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PtpCrossTimestamp {
    /// PTP Hardware Clock (device) counter snapshot
    pub device_time: PtpTimestamp,
    /// System clock captured immediately before reading hardware counter
    pub sys_time_before: PtpTimestamp,
    /// System clock captured immediately after reading hardware counter
    pub sys_time_after: PtpTimestamp,
}

impl PtpCrossTimestamp {
    pub fn new(
        device_time: PtpTimestamp,
        sys_time_before: PtpTimestamp,
        sys_time_after: PtpTimestamp,
    ) -> Self {
        Self {
            device_time,
            sys_time_before,
            sys_time_after,
        }
    }

    /// Returns PCIe/bus round-trip latency in nanoseconds: (sys_after - sys_before).
    pub fn bus_read_latency_ns(&self) -> u64 {
        let before_ns = self.sys_time_before.to_total_nanoseconds();
        let after_ns = self.sys_time_after.to_total_nanoseconds();
        if after_ns >= before_ns {
            (after_ns - before_ns) as u64
        } else {
            0
        }
    }

    /// Verifies if cross-timestamp bus read latency is within acceptable tolerance.
    pub fn is_valid_latency(&self, max_bus_latency_ns: u64) -> bool {
        self.bus_read_latency_ns() <= max_bus_latency_ns
    }

    /// Computes bus-latency-compensated host-to-device clock offset in nanoseconds:
    /// Offset = device_time - midpoint(sys_before, sys_after)
    pub fn compute_offset_ns(&self) -> i64 {
        let dev_ns = self.device_time.to_total_nanoseconds();
        let before_ns = self.sys_time_before.to_total_nanoseconds();
        let after_ns = self.sys_time_after.to_total_nanoseconds();

        let sys_midpoint = (before_ns + after_ns) / 2;
        (dev_ns - sys_midpoint) as i64
    }
}

/// Egress hardware timestamp record in NIC TX timestamp queue.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PhcTxTimestampEntry {
    pub sequence_id: u16,
    pub message_type: u8,
    pub timestamp: PtpTimestamp,
}

/// Hardware TX Event Timestamping FIFO Queue (e.g. for Two-Step Sync / Delay_Req).
#[derive(Debug, Clone)]
pub struct PhcTxTimestampRing {
    pub capacity: usize,
    pub queue: VecDeque<PhcTxTimestampEntry>,
}

impl Default for PhcTxTimestampRing {
    fn default() -> Self {
        Self::new(32)
    }
}

impl PhcTxTimestampRing {
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity: capacity.max(4),
            queue: VecDeque::with_capacity(capacity),
        }
    }

    /// Pushes an egress hardware timestamp into the FIFO queue.
    pub fn push_egress_ts(&mut self, sequence_id: u16, message_type: u8, ts: PtpTimestamp) {
        if self.queue.len() >= self.capacity {
            self.queue.pop_front();
        }
        self.queue.push_back(PhcTxTimestampEntry {
            sequence_id,
            message_type,
            timestamp: ts,
        });
    }

    /// Retrieves and removes the matched egress timestamp for a message type and sequence ID.
    pub fn take_egress_ts(&mut self, sequence_id: u16, message_type: u8) -> Option<PtpTimestamp> {
        if let Some(pos) = self
            .queue
            .iter()
            .position(|e| e.sequence_id == sequence_id && e.message_type == message_type)
        {
            Some(self.queue.remove(pos).unwrap().timestamp)
        } else {
            None
        }
    }

    /// Number of entries currently stored in the TX timestamp queue.
    pub fn len(&self) -> usize {
        self.queue.len()
    }

    /// Checks if TX timestamp queue is empty.
    pub fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }
}

/// Hardware Packet Timestamping & Ingress/Egress Tagger.
#[derive(Debug, Clone, Default)]
pub struct PhcPacketTagger;

impl PhcPacketTagger {
    /// Ingress event: captures exact PHC hardware timestamp upon packet arrival.
    pub fn tag_rx(phc: &PtpHardwareClock) -> PtpTimestamp {
        phc.get_time()
    }

    /// Egress event: tags outgoing PTP packet and pushes timestamp into TX FIFO queue.
    pub fn tag_tx(
        phc: &PtpHardwareClock,
        packet: &mut PtpPacket,
        tx_ring: &mut PhcTxTimestampRing,
    ) -> PtpTimestamp {
        let ts = phc.get_time();
        let msg_type = packet.header.message_type;
        let seq_id = packet.header.sequence_id;

        // Two-step flag (bit 9 in PTP header flags: 0x0200)
        let is_two_step = (packet.header.flags & 0x0200) != 0;

        if !is_two_step && (msg_type == PTP_MSG_SYNC || msg_type == PTP_MSG_DELAY_REQ) {
            // One-step: timestamp placed directly into header
            packet.origin_timestamp = Some(ts);
        } else {
            // Two-step: timestamp pushed into FIFO for subsequent Follow_Up retrieval
            tx_ring.push_egress_ts(seq_id, msg_type, ts);
        }

        ts
    }
}
