//! 3GPP Release 18/19 5G-Advanced L4S DualQ Coupled AQM Engine.
//!
//! Standards Reference:
//! - 3GPP TS 23.501 Rel-18 §5.37.4: "Support for Low Latency Low Loss Scalable Throughput (L4S)"
//! - 3GPP TS 38.300 Rel-18: "L4S indication in 5G QoS Profile and RAN Congestion Handling"
//! - 3GPP TS 26.114 Rel-18: "Multimedia Telephony Services - L4S and RAN Feedback for Real-time Media"
//! - IETF RFC 9330: "Low Latency, Low Loss, and Scalable Throughput (L4S) Internet Service: Architecture"
//! - IETF RFC 9331: "The Addition of Explicit Congestion Notification (ECN) to Identify L4S Packets: The ECT(1) Codepoint"
//! - IETF RFC 9332: "Dual-Queue Coupled Active Queue Management (AQM) for Low-Latency, Low-Loss, and Scalable Throughput (L4S)"
//!
//! This module implements the Dual-Queue Coupled Active Queue Management (DualQ AQM)
//! engine deployed at the 5G UPF and gNB MAC/RLC layer to support ultra-low latency XR,
//! interactive cloud gaming, and mission-critical URLLC flows alongside classic TCP traffic.

use std::collections::VecDeque;
use std::fmt;

// ---------------------------------------------------------------------------
// Constants & Magic Numbers
// ---------------------------------------------------------------------------

/// Wire framing magic identifier: "L4SQ" (0x4C, 0x34, 0x53, 0x51).
pub const L4S_WIRE_MAGIC: [u8; 4] = [0x4C, 0x34, 0x53, 0x51];

/// Binary wire framing size in bytes.
pub const L4S_WIRE_PDU_SIZE: usize = 30;

// ---------------------------------------------------------------------------
// Error Types
// ---------------------------------------------------------------------------

/// Errors encountered in L4S DualQ AQM processing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum L4sError {
    InvalidEcnCodepoint(u8),
    InvalidQfi(u8),
    BufferOverflow {
        queue: &'static str,
        capacity_bytes: usize,
    },
    InvalidTimeSequence {
        current_us: u64,
        advance_to_us: u64,
    },
    WireBufferTooSmall {
        required: usize,
        provided: usize,
    },
    InvalidWireMagic([u8; 4]),
    WireCrcMismatch {
        expected: u16,
        calculated: u16,
    },
    InvalidConfiguration(String),
}

impl fmt::Display for L4sError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            L4sError::InvalidEcnCodepoint(c) => write!(
                f,
                "Invalid IP ECN codepoint: {:#04b} (must be 0b00..0b11)",
                c
            ),
            L4sError::InvalidQfi(q) => write!(f, "Invalid 5G QFI: {} (must be 1..=64)", q),
            L4sError::BufferOverflow {
                queue,
                capacity_bytes,
            } => {
                write!(
                    f,
                    "DualQ {} buffer overflow: exceeds {} bytes",
                    queue, capacity_bytes
                )
            }
            L4sError::InvalidTimeSequence {
                current_us,
                advance_to_us,
            } => {
                write!(
                    f,
                    "Cannot advance time backwards: current {} us, target {} us",
                    current_us, advance_to_us
                )
            }
            L4sError::WireBufferTooSmall { required, provided } => {
                write!(
                    f,
                    "Wire buffer too small: required {} bytes, provided {}",
                    required, provided
                )
            }
            L4sError::InvalidWireMagic(m) => write!(f, "Invalid wire magic: {:02X?}", m),
            L4sError::WireCrcMismatch {
                expected,
                calculated,
            } => {
                write!(
                    f,
                    "Wire CRC-16 mismatch: expected {:#06X}, calculated {:#06X}",
                    expected, calculated
                )
            }
            L4sError::InvalidConfiguration(msg) => write!(f, "Invalid DualQ config: {}", msg),
        }
    }
}

// ---------------------------------------------------------------------------
// ECN Field & Packet Data Structures
// ---------------------------------------------------------------------------

/// IP Explicit Congestion Notification (ECN) 2-bit field (RFC 3168 / RFC 9331).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IpEcnField {
    /// Non-ECN-Capable Transport (0b00).
    NotEct = 0b00,
    /// L4S-Capable Transport (0b01) per RFC 9331.
    Ect1 = 0b01,
    /// Classic ECN-Capable Transport (0b10) per RFC 3168.
    Ect0 = 0b10,
    /// Congestion Experienced (0b11).
    Ce = 0b11,
}

impl IpEcnField {
    /// Parse from lower 2 bits of IPv4 DSCP/ECN or IPv6 Traffic Class.
    pub fn from_bits(bits: u8) -> Result<Self, L4sError> {
        match bits & 0x03 {
            0b00 => Ok(IpEcnField::NotEct),
            0b01 => Ok(IpEcnField::Ect1),
            0b10 => Ok(IpEcnField::Ect0),
            0b11 => Ok(IpEcnField::Ce),
            other => Err(L4sError::InvalidEcnCodepoint(other)),
        }
    }

    /// Return the raw 2-bit representation.
    pub fn to_bits(self) -> u8 {
        self as u8
    }

    /// True if packet is identified as L4S traffic (`ECT(1)` or `CE` classified to L).
    pub fn is_l4s_traffic(self) -> bool {
        matches!(self, IpEcnField::Ect1 | IpEcnField::Ce)
    }

    /// True if packet is ECN-capable (`ECT(1)`, `ECT(0)`, or `CE`).
    pub fn is_ecn_capable(self) -> bool {
        !matches!(self, IpEcnField::NotEct)
    }
}

/// Action to be taken on a dequeued packet by the AQM scheduler.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum L4sPacketAction {
    /// Forward packet without altering the IP header.
    ForwardUnchanged,
    /// Mark ECN field as Congestion Experienced (`CE`, 0b11).
    MarkCe,
    /// Drop packet due to congestion (Classic Not-ECT) or buffer overflow.
    Drop,
}

/// Packet structure traversing the DualQ AQM engine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct L4sPacket {
    /// Unique packet sequence or tracking identifier.
    pub id: u64,
    /// 3GPP QoS Flow Identifier (QFI, 1..=64).
    pub qfi: u8,
    /// IP payload size in bytes.
    pub size_bytes: usize,
    /// Current IP ECN marking.
    pub ecn: IpEcnField,
    /// Timestamp when packet entered the queue (in microseconds).
    pub arrival_time_us: u64,
}

impl L4sPacket {
    /// Create a new packet with current timestamp.
    pub fn new(
        id: u64,
        qfi: u8,
        size_bytes: usize,
        ecn: IpEcnField,
        arrival_time_us: u64,
    ) -> Result<Self, L4sError> {
        if qfi == 0 || qfi > 64 {
            return Err(L4sError::InvalidQfi(qfi));
        }
        Ok(Self {
            id,
            qfi,
            size_bytes,
            ecn,
            arrival_time_us,
        })
    }
}

// ---------------------------------------------------------------------------
// Configuration & Telemetry
// ---------------------------------------------------------------------------

/// Configuration parameters for DualQ Coupled AQM.
#[derive(Debug, Clone)]
pub struct DualQConfig {
    /// Link capacity in bits per second (e.g., 100_000_000 for 100 Mbps).
    pub link_capacity_bps: u64,
    /// Target queuing delay for the Classic queue in microseconds (e.g. 15,000 us = 15 ms).
    pub target_latency_classic_us: u64,
    /// Target queuing delay for the L4S queue in microseconds (e.g. 800 us).
    pub target_latency_l4s_us: u64,
    /// Minimum threshold for L4S queue ramp marking in microseconds (e.g. 500 us).
    pub l_min_us: u64,
    /// Maximum threshold for L4S queue ramp marking in microseconds (e.g. 1,500 us, at which mark prob = 100%).
    pub l_max_us: u64,
    /// Coupling factor k (RFC 9332: p_L = min(1.0, k * (p_C)^2)). Default 1.0 or 2.0.
    pub coupling_factor_k: f64,
    /// PI2 controller proportional gain alpha (e.g. 0.16).
    pub pi2_alpha: f64,
    /// PI2 controller integral gain beta (e.g. 0.032).
    pub pi2_beta: f64,
    /// PI2 controller update interval in microseconds (e.g. 16,000 us = 16 ms).
    pub update_interval_us: u64,
    /// Maximum buffer size for Classic queue in bytes.
    pub max_buffer_bytes_classic: usize,
    /// Maximum buffer size for L4S queue in bytes.
    pub max_buffer_bytes_l4s: usize,
    /// Deficit Round Robin weight for Classic queue.
    pub classic_weight: u32,
    /// Deficit Round Robin weight for L4S queue.
    pub l4s_weight: u32,
}

impl Default for DualQConfig {
    fn default() -> Self {
        Self {
            link_capacity_bps: 100_000_000,    // 100 Mbps
            target_latency_classic_us: 15_000, // 15 ms
            target_latency_l4s_us: 800,        // 800 us
            l_min_us: 400,                     // 400 us
            l_max_us: 1_200,                   // 1200 us
            coupling_factor_k: 1.0,
            pi2_alpha: 0.16,
            pi2_beta: 0.032,
            update_interval_us: 16_000, // 16 ms
            max_buffer_bytes_classic: 1_000_000,
            max_buffer_bytes_l4s: 200_000,
            classic_weight: 1,
            l4s_weight: 9,
        }
    }
}

/// Real-time statistics collected by DualQ AQM.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DualQStats {
    pub total_classic_enqueued: u64,
    pub total_l4s_enqueued: u64,
    pub total_classic_dequeued: u64,
    pub total_l4s_dequeued: u64,
    pub total_classic_dropped: u64,
    pub total_l4s_dropped: u64,
    pub total_classic_marked_ce: u64,
    pub total_l4s_marked_ce: u64,
    pub max_observed_qdelay_classic_us: u64,
    pub max_observed_qdelay_l4s_us: u64,
}

/// Congestion level classification for RAN feedback (TS 26.114).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RanCongestionLevel {
    None,
    Mild,
    Moderate,
    Severe,
}

/// 3GPP TS 26.114 RAN Congestion Feedback Report for real-time XR video.
#[derive(Debug, Clone, PartialEq)]
pub struct RanFeedbackReport {
    pub current_time_us: u64,
    pub l4s_qdelay_us: u64,
    pub classic_qdelay_us: u64,
    pub prob_classic: f64,
    pub prob_l4s: f64,
    pub congestion_level: RanCongestionLevel,
    /// Bitrate delta multiplier recommended for XR encoder (-0.3 = -30%, 0.0 = maintain, +0.1 = +10%).
    pub bitrate_adjustment_factor: f64,
}

// ---------------------------------------------------------------------------
// DualQ Coupled AQM Engine
// ---------------------------------------------------------------------------

/// Dual-Queue Coupled Active Queue Management Engine.
pub struct DualQCoupledAqm {
    config: DualQConfig,
    classic_queue: VecDeque<L4sPacket>,
    l4s_queue: VecDeque<L4sPacket>,
    classic_bytes: usize,
    l4s_bytes: usize,
    current_time_us: u64,
    last_pi2_update_us: u64,
    prob_classic: f64,
    prob_l4s: f64,
    prev_qdelay_classic_us: u64,
    classic_deficit: i64,
    l4s_deficit: i64,
    prng_state: u64,
    stats: DualQStats,
}

impl DualQCoupledAqm {
    /// Initialize a new DualQ engine with specified configuration.
    pub fn new(config: DualQConfig) -> Self {
        Self {
            config,
            classic_queue: VecDeque::new(),
            l4s_queue: VecDeque::new(),
            classic_bytes: 0,
            l4s_bytes: 0,
            current_time_us: 0,
            last_pi2_update_us: 0,
            prob_classic: 0.0,
            prob_l4s: 0.0,
            prev_qdelay_classic_us: 0,
            classic_deficit: 0,
            l4s_deficit: 0,
            prng_state: 0x123456789ABCDEF0,
            stats: DualQStats::default(),
        }
    }

    /// Advance internal simulation/system time in microseconds.
    ///
    /// Iteratively steps through PI2 controller update epochs if multiple intervals have elapsed.
    pub fn advance_time(&mut self, new_time_us: u64) -> Result<(), L4sError> {
        if new_time_us < self.current_time_us {
            return Err(L4sError::InvalidTimeSequence {
                current_us: self.current_time_us,
                advance_to_us: new_time_us,
            });
        }

        while self.current_time_us + self.config.update_interval_us <= new_time_us {
            self.current_time_us += self.config.update_interval_us;
            self.update_pi2_controller();
            self.last_pi2_update_us = self.current_time_us;
        }
        self.current_time_us = new_time_us;

        Ok(())
    }

    /// Explicitly override internal drop/mark probabilities (useful for deterministic testing and manual control).
    pub fn set_probabilities(&mut self, prob_classic: f64, prob_l4s: f64) {
        self.prob_classic = prob_classic.clamp(0.0, 1.0);
        self.prob_l4s = prob_l4s.clamp(0.0, 1.0);
    }

    /// Dynamically update RAN link capacity (e.g. upon wireless link adaptation or AMC change).
    pub fn update_link_capacity(&mut self, capacity_bps: u64) {
        if capacity_bps > 0 {
            self.config.link_capacity_bps = capacity_bps;
        }
    }

    /// Get current configuration.
    pub fn config(&self) -> &DualQConfig {
        &self.config
    }

    /// Get accumulated telemetry statistics.
    pub fn stats(&self) -> &DualQStats {
        &self.stats
    }

    /// Current Classic queue depth in bytes.
    pub fn classic_queue_bytes(&self) -> usize {
        self.classic_bytes
    }

    /// Current L4S queue depth in bytes.
    pub fn l4s_queue_bytes(&self) -> usize {
        self.l4s_bytes
    }

    /// Number of packets in Classic queue.
    pub fn classic_packet_count(&self) -> usize {
        self.classic_queue.len()
    }

    /// Number of packets in L4S queue.
    pub fn l4s_packet_count(&self) -> usize {
        self.l4s_queue.len()
    }

    /// Current coupled marking probability for L4S queue.
    pub fn coupled_l4s_probability(&self) -> f64 {
        self.prob_l4s
    }

    /// Current Classic queue drop/mark probability.
    pub fn classic_probability(&self) -> f64 {
        self.prob_classic
    }

    /// Enqueue a packet into the DualQ AQM.
    ///
    /// Packets marked `ECT(1)` are directed to the L4S queue;
    /// Packets marked `Not-ECT` or `ECT(0)` are directed to the Classic queue.
    pub fn enqueue(&mut self, packet: L4sPacket) -> Result<(), L4sError> {
        let is_l4s = packet.ecn.is_l4s_traffic();

        if is_l4s {
            if self.l4s_bytes + packet.size_bytes > self.config.max_buffer_bytes_l4s {
                self.stats.total_l4s_dropped += 1;
                return Err(L4sError::BufferOverflow {
                    queue: "L4S",
                    capacity_bytes: self.config.max_buffer_bytes_l4s,
                });
            }
            self.l4s_bytes += packet.size_bytes;
            self.l4s_queue.push_back(packet);
            self.stats.total_l4s_enqueued += 1;
        } else {
            if self.classic_bytes + packet.size_bytes > self.config.max_buffer_bytes_classic {
                self.stats.total_classic_dropped += 1;
                return Err(L4sError::BufferOverflow {
                    queue: "Classic",
                    capacity_bytes: self.config.max_buffer_bytes_classic,
                });
            }
            self.classic_bytes += packet.size_bytes;
            self.classic_queue.push_back(packet);
            self.stats.total_classic_enqueued += 1;
        }

        Ok(())
    }

    /// Dequeue the next packet according to the DualQ scheduler and coupled AQM logic.
    ///
    /// Returns the packet and the action to take (`ForwardUnchanged`, `MarkCe`, or `Drop`).
    pub fn dequeue(&mut self) -> Option<(L4sPacket, L4sPacketAction)> {
        if self.l4s_queue.is_empty() && self.classic_queue.is_empty() {
            return None;
        }

        // Deficit Round Robin selection
        let serve_l4s = if self.l4s_queue.is_empty() {
            false
        } else if self.classic_queue.is_empty() {
            true
        } else {
            // Both queues have packets
            if self.l4s_deficit <= 0 && self.classic_deficit <= 0 {
                self.l4s_deficit += self.config.l4s_weight as i64 * 1500;
                self.classic_deficit += self.config.classic_weight as i64 * 1500;
            }

            if self.l4s_deficit > 0 { true } else { false }
        };

        if serve_l4s {
            self.dequeue_l4s()
        } else {
            self.dequeue_classic()
        }
    }

    fn dequeue_l4s(&mut self) -> Option<(L4sPacket, L4sPacketAction)> {
        let mut packet = self.l4s_queue.pop_front()?;
        self.l4s_bytes = self.l4s_bytes.saturating_sub(packet.size_bytes);
        self.l4s_deficit = self.l4s_deficit.saturating_sub(packet.size_bytes as i64);
        self.stats.total_l4s_dequeued += 1;

        let sojourn_us = self.current_time_us.saturating_sub(packet.arrival_time_us);
        if sojourn_us > self.stats.max_observed_qdelay_l4s_us {
            self.stats.max_observed_qdelay_l4s_us = sojourn_us;
        }

        // L4S ramp marking probability
        let ramp_p = if sojourn_us <= self.config.l_min_us {
            0.0
        } else if sojourn_us >= self.config.l_max_us {
            1.0
        } else {
            let span = (self.config.l_max_us - self.config.l_min_us) as f64;
            (sojourn_us - self.config.l_min_us) as f64 / span
        };

        // Effective probability: max of ramp and coupled probability p_L
        let eff_p = ramp_p.max(self.prob_l4s);
        let u = self.next_random_f64();

        if u < eff_p {
            packet.ecn = IpEcnField::Ce;
            self.stats.total_l4s_marked_ce += 1;
            Some((packet, L4sPacketAction::MarkCe))
        } else {
            Some((packet, L4sPacketAction::ForwardUnchanged))
        }
    }

    fn dequeue_classic(&mut self) -> Option<(L4sPacket, L4sPacketAction)> {
        let mut packet = self.classic_queue.pop_front()?;
        self.classic_bytes = self.classic_bytes.saturating_sub(packet.size_bytes);
        self.classic_deficit = self
            .classic_deficit
            .saturating_sub(packet.size_bytes as i64);
        self.stats.total_classic_dequeued += 1;

        let sojourn_us = self.current_time_us.saturating_sub(packet.arrival_time_us);
        if sojourn_us > self.stats.max_observed_qdelay_classic_us {
            self.stats.max_observed_qdelay_classic_us = sojourn_us;
        }

        let u = self.next_random_f64();
        if u < self.prob_classic {
            if packet.ecn == IpEcnField::Ect0 {
                packet.ecn = IpEcnField::Ce;
                self.stats.total_classic_marked_ce += 1;
                Some((packet, L4sPacketAction::MarkCe))
            } else if packet.ecn == IpEcnField::NotEct {
                self.stats.total_classic_dropped += 1;
                Some((packet, L4sPacketAction::Drop))
            } else {
                // Already CE or unexpected
                Some((packet, L4sPacketAction::ForwardUnchanged))
            }
        } else {
            Some((packet, L4sPacketAction::ForwardUnchanged))
        }
    }

    /// Update PI2 controller state on epoch expiry (RFC 9332 §2.4).
    fn update_pi2_controller(&mut self) {
        let current_sojourn_us = if let Some(front) = self.classic_queue.front() {
            self.current_time_us.saturating_sub(front.arrival_time_us)
        } else {
            0
        };

        // Delay error in seconds
        let delay_sec = current_sojourn_us as f64 / 1_000_000.0;
        let target_sec = self.config.target_latency_classic_us as f64 / 1_000_000.0;
        let prev_delay_sec = self.prev_qdelay_classic_us as f64 / 1_000_000.0;

        let error = delay_sec - target_sec;
        let delta_error = delay_sec - prev_delay_sec;

        // PI update: p_C = p_C + alpha * error + beta * delta_error
        let delta_p = self.config.pi2_alpha * error + self.config.pi2_beta * delta_error;
        let new_p_c = (self.prob_classic + delta_p).clamp(0.0, 1.0);

        self.prob_classic = new_p_c;
        self.prev_qdelay_classic_us = current_sojourn_us;

        // Coupled probability calculation: p_L = min(1.0, k * (p_C)^2)
        let p_l =
            (self.config.coupling_factor_k * self.prob_classic * self.prob_classic).clamp(0.0, 1.0);
        self.prob_l4s = p_l;
    }

    /// Generate TS 26.114 RAN Congestion Feedback Report for application adaptation.
    pub fn generate_ran_feedback(&self) -> RanFeedbackReport {
        let l4s_sojourn = if let Some(front) = self.l4s_queue.front() {
            self.current_time_us.saturating_sub(front.arrival_time_us)
        } else {
            0
        };

        let classic_sojourn = if let Some(front) = self.classic_queue.front() {
            self.current_time_us.saturating_sub(front.arrival_time_us)
        } else {
            0
        };

        let (congestion_level, bitrate_adjustment_factor) =
            if self.prob_classic > 0.4 || self.prob_l4s > 0.5 {
                (RanCongestionLevel::Severe, -0.35)
            } else if self.prob_classic > 0.2 || self.prob_l4s > 0.2 {
                (RanCongestionLevel::Moderate, -0.20)
            } else if self.prob_classic > 0.05 || self.prob_l4s > 0.05 {
                (RanCongestionLevel::Mild, -0.05)
            } else {
                (RanCongestionLevel::None, 0.05)
            };

        RanFeedbackReport {
            current_time_us: self.current_time_us,
            l4s_qdelay_us: l4s_sojourn,
            classic_qdelay_us: classic_sojourn,
            prob_classic: self.prob_classic,
            prob_l4s: self.prob_l4s,
            congestion_level,
            bitrate_adjustment_factor,
        }
    }

    /// Simple linear congruential pseudo-random generator returning [0.0, 1.0).
    fn next_random_f64(&mut self) -> f64 {
        self.prng_state = self
            .prng_state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        let val = (self.prng_state >> 32) as u32;
        val as f64 / 4294967296.0
    }
}

// ---------------------------------------------------------------------------
// Wire Protocol Framing & CRC-16
// ---------------------------------------------------------------------------

/// CRC-16 CCITT (polynomial 0x1021, init 0xFFFF).
pub fn compute_crc16(data: &[u8]) -> u16 {
    let mut crc: u16 = 0xFFFF;
    for &byte in data {
        crc ^= (byte as u16) << 8;
        for _ in 0..8 {
            if (crc & 0x8000) != 0 {
                crc = (crc << 1) ^ 0x1021;
            } else {
                crc <<= 1;
            }
        }
    }
    crc
}

/// Binary Wire PDU for DualQ AQM telemetry and synchronization.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NrL4sWirePdu {
    /// System Frame Number (0..1023).
    pub sfn: u16,
    /// Subframe/Slot index (0..159).
    pub slot: u8,
    /// QoS Flow Identifier (1..64).
    pub qfi: u8,
    /// L4S queue depth in bytes.
    pub l4s_bytes: u32,
    /// Classic queue depth in bytes.
    pub classic_bytes: u32,
    /// Current L4S Head-of-Line queuing delay in microseconds.
    pub l4s_qdelay_us: u32,
    /// Current Classic Head-of-Line queuing delay in microseconds.
    pub classic_qdelay_us: u32,
    /// Scaled Classic probability: `(p_C * 10000.0) as u16`.
    pub prob_classic_scaled: u16,
    /// Scaled L4S probability: `(p_L * 10000.0) as u16`.
    pub prob_l4s_scaled: u16,
}

impl NrL4sWirePdu {
    /// Serialize PDU into standard 30-byte wire representation.
    pub fn to_wire_bytes(&self) -> [u8; L4S_WIRE_PDU_SIZE] {
        let mut buf = [0u8; L4S_WIRE_PDU_SIZE];
        // 0..4: Magic
        buf[0..4].copy_from_slice(&L4S_WIRE_MAGIC);
        // 4..6: SFN
        buf[4..6].copy_from_slice(&self.sfn.to_be_bytes());
        // 6: Slot
        buf[6] = self.slot;
        // 7: QFI
        buf[7] = self.qfi;
        // 8..12: L4S queue bytes
        buf[8..12].copy_from_slice(&self.l4s_bytes.to_be_bytes());
        // 12..16: Classic queue bytes
        buf[12..16].copy_from_slice(&self.classic_bytes.to_be_bytes());
        // 16..20: L4S delay
        buf[16..20].copy_from_slice(&self.l4s_qdelay_us.to_be_bytes());
        // 20..24: Classic delay
        buf[20..24].copy_from_slice(&self.classic_qdelay_us.to_be_bytes());
        // 24..26: Scaled classic probability
        buf[24..26].copy_from_slice(&self.prob_classic_scaled.to_be_bytes());
        // 26..28: Scaled L4S probability
        buf[26..28].copy_from_slice(&self.prob_l4s_scaled.to_be_bytes());

        // 28..30: CRC-16 CCITT over bytes 0..28
        let crc = compute_crc16(&buf[0..28]);
        buf[28..30].copy_from_slice(&crc.to_be_bytes());

        buf
    }

    /// Parse and validate wire PDU.
    pub fn from_wire_bytes(buf: &[u8]) -> Result<Self, L4sError> {
        if buf.len() < L4S_WIRE_PDU_SIZE {
            return Err(L4sError::WireBufferTooSmall {
                required: L4S_WIRE_PDU_SIZE,
                provided: buf.len(),
            });
        }

        let magic = [buf[0], buf[1], buf[2], buf[3]];
        if magic != L4S_WIRE_MAGIC {
            return Err(L4sError::InvalidWireMagic(magic));
        }

        let expected_crc = u16::from_be_bytes([buf[28], buf[29]]);
        let calc_crc = compute_crc16(&buf[0..28]);
        if expected_crc != calc_crc {
            return Err(L4sError::WireCrcMismatch {
                expected: expected_crc,
                calculated: calc_crc,
            });
        }

        let sfn = u16::from_be_bytes([buf[4], buf[5]]);
        let slot = buf[6];
        let qfi = buf[7];
        let l4s_bytes = u32::from_be_bytes([buf[8], buf[9], buf[10], buf[11]]);
        let classic_bytes = u32::from_be_bytes([buf[12], buf[13], buf[14], buf[15]]);
        let l4s_qdelay_us = u32::from_be_bytes([buf[16], buf[17], buf[18], buf[19]]);
        let classic_qdelay_us = u32::from_be_bytes([buf[20], buf[21], buf[22], buf[23]]);
        let prob_classic_scaled = u16::from_be_bytes([buf[24], buf[25]]);
        let prob_l4s_scaled = u16::from_be_bytes([buf[26], buf[27]]);

        Ok(Self {
            sfn,
            slot,
            qfi,
            l4s_bytes,
            classic_bytes,
            l4s_qdelay_us,
            classic_qdelay_us,
            prob_classic_scaled,
            prob_l4s_scaled,
        })
    }
}
