//! 3GPP Release 18 (5G-Advanced) Smart Grid & Industrial Automation TSN Deterministic QoS Framework.
//!
//! Standards Reference:
//! - 3GPP TS 23.501 §5.27: "Support for Time Sensitive Communication and Time-Synchronization"
//! - 3GPP TS 23.548: "5G System Enhancements for support of Time-Sensitive Communication and Time-Synchronization"
//! - 3GPP TS 38.300 §16.5: "Time Sensitive Communication"
//! - IEEE 802.1Q: Virtual Bridged Local Area Networks (VLAN & Priority Code Point PCP 0..7)
//! - IEEE 802.1CB: Frame Replication and Elimination for Reliability (FRER)
//! - IEC 61850-9-2 (Sampled Values SV) & IEC 61850-8-1 (GOOSE) for smart grid protection.
//!
//! This module implements the end-to-end deterministic TSN-over-5G framework:
//! 1. Device-Side & Network-Side TSN Translators (DS-TT & NW-TT) with virtual bridge port management.
//! 2. 3GPP Delay-Critical 5QIs (5QI 80, 82, 83, 84, 85, 86) and automatic QoS profile mapping.
//! 3. Time-Sensitive Communication Assistance Information (TSCAI) for gNodeB radio slot scheduling.
//! 4. Industrial Survival Time ($T_{survival}$) state machine with transient tolerance, RAN priority boost, and safe application trip.
//! 5. Egress Hold-and-Forward de-jittering buffer bounding egress packet release jitter to $< 1\ \mu\text{s}$.
//! 6. IEEE 802.1CB dual-path frame replication and sequence-based duplicate elimination (FRER).
//! 7. Comprehensive stream telemetry, bridge delay reporting, and failure protection.

use std::collections::{HashMap, VecDeque};
use std::fmt;

// ---------------------------------------------------------------------------
// Error Types
// ---------------------------------------------------------------------------

/// Errors encountered in the TSN Deterministic QoS subsystem.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TscError {
    InvalidPcp(u8),
    InvalidPeriodicity(u64),
    InvalidBurstSize(u32),
    StreamNotFound(u32),
    StreamAlreadyExists(u32),
    BufferOverflow {
        stream_id: u32,
        capacity: usize,
    },
    PacketTooLate {
        stream_id: u32,
        scheduled_ns: u64,
        current_ns: u64,
    },
    InvalidTranslatorConfiguration(String),
}

impl fmt::Display for TscError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TscError::InvalidPcp(p) => write!(f, "Invalid IEEE 802.1Q PCP: {p} (must be 0..=7)"),
            TscError::InvalidPeriodicity(p) => {
                write!(f, "Invalid TSCAI periodicity: {p} us (must be > 0)")
            }
            TscError::InvalidBurstSize(b) => {
                write!(f, "Invalid burst size: {b} bytes (must be > 0)")
            }
            TscError::StreamNotFound(s) => write!(f, "TSN stream id {s} not found"),
            TscError::StreamAlreadyExists(s) => write!(f, "TSN stream id {s} already exists"),
            TscError::BufferOverflow {
                stream_id,
                capacity,
            } => {
                write!(
                    f,
                    "Hold-and-Forward buffer overflow for stream {stream_id} (capacity: {capacity})"
                )
            }
            TscError::PacketTooLate {
                stream_id,
                scheduled_ns,
                current_ns,
            } => {
                write!(
                    f,
                    "Packet for stream {stream_id} arrived too late: scheduled {scheduled_ns} ns, now {current_ns} ns"
                )
            }
            TscError::InvalidTranslatorConfiguration(msg) => {
                write!(f, "Invalid translator config: {msg}")
            }
        }
    }
}

// ---------------------------------------------------------------------------
// IEEE 802.1Q PCP & Industrial Traffic Classification
// ---------------------------------------------------------------------------

/// IEEE 802.1Q Priority Code Point (PCP 0 to 7).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum EthernetPcp {
    Pcp0BestEffort = 0,
    Pcp1Background = 1,
    Pcp2ExcellentEffort = 2,
    Pcp3CriticalApplications = 3,
    Pcp4Video = 4,
    Pcp5VoiceOrSampledValues = 5,
    Pcp6InternetworkControlOrGoose = 6,
    Pcp7NetworkControlOrPtp = 7,
}

impl EthernetPcp {
    pub fn from_u8(val: u8) -> Result<Self, TscError> {
        match val {
            0 => Ok(EthernetPcp::Pcp0BestEffort),
            1 => Ok(EthernetPcp::Pcp1Background),
            2 => Ok(EthernetPcp::Pcp2ExcellentEffort),
            3 => Ok(EthernetPcp::Pcp3CriticalApplications),
            4 => Ok(EthernetPcp::Pcp4Video),
            5 => Ok(EthernetPcp::Pcp5VoiceOrSampledValues),
            6 => Ok(EthernetPcp::Pcp6InternetworkControlOrGoose),
            7 => Ok(EthernetPcp::Pcp7NetworkControlOrPtp),
            other => Err(TscError::InvalidPcp(other)),
        }
    }

    pub fn as_u8(&self) -> u8 {
        *self as u8
    }
}

/// Industrial and Smart Grid Traffic Categories.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TsnTrafficType {
    /// IEC 61850 GOOSE: Substation teleprotection trip commands (survival time ~3-4 ms).
    Iec61850Goose,
    /// IEC 61850 Sampled Values (SV): Cyclic analogue measurement stream (4 kHz/4.8 kHz).
    Iec61850SampledValues,
    /// Industrial Motion Control: Cyclic real-time control loop (PROFINET IRT / EtherCAT).
    IndustrialMotionControl,
    /// Industrial Telemetry / SCADA.
    IndustrialTelemetry,
    /// Non-deterministic best-effort traffic.
    BestEffort,
}

pub type TscTrafficType = TsnTrafficType;

// ---------------------------------------------------------------------------
// 3GPP Delay-Critical 5QI (TS 23.501 Table 5.7.4-1)
// ---------------------------------------------------------------------------

/// Standard 3GPP Release 18 Delay-Critical 5G QoS Identifiers (5QIs).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DelayCritical5Qi {
    /// 5QI 80: Low-rate discrete automation (Priority 68, PDB 10 ms, PER 10^-6, MDBV 255 B).
    Qi80,
    /// 5QI 82: Discrete automation / motion control (Priority 19, PDB 10 ms, PER 10^-4, MDBV 255 B).
    Qi82,
    /// 5QI 83: Discrete automation large payload (Priority 22, PDB 10 ms, PER 10^-4, MDBV 1354 B).
    Qi83,
    /// 5QI 84: Smart grid substation protection (Priority 24, PDB 30 ms, PER 10^-5, MDBV 1354 B).
    Qi84,
    /// 5QI 85: Smart grid teleprotection / high-speed trip (Priority 21, PDB 5 ms, PER 10^-5, MDBV 255 B).
    Qi85,
    /// 5QI 86: Motion control / robotics (Priority 18, PDB 5 ms, PER 10^-4, MDBV 1354 B).
    Qi86,
}

impl DelayCritical5Qi {
    pub fn five_qi_value(&self) -> u16 {
        match self {
            DelayCritical5Qi::Qi80 => 80,
            DelayCritical5Qi::Qi82 => 82,
            DelayCritical5Qi::Qi83 => 83,
            DelayCritical5Qi::Qi84 => 84,
            DelayCritical5Qi::Qi85 => 85,
            DelayCritical5Qi::Qi86 => 86,
        }
    }

    /// Packet Delay Budget in microseconds.
    pub fn packet_delay_budget_us(&self) -> u64 {
        match self {
            DelayCritical5Qi::Qi80 => 10_000,
            DelayCritical5Qi::Qi82 => 10_000,
            DelayCritical5Qi::Qi83 => 10_000,
            DelayCritical5Qi::Qi84 => 30_000,
            DelayCritical5Qi::Qi85 => 5_000,
            DelayCritical5Qi::Qi86 => 5_000,
        }
    }

    /// Target Packet Error Rate (PER).
    pub fn packet_error_rate(&self) -> f64 {
        match self {
            DelayCritical5Qi::Qi80 => 1e-6,
            DelayCritical5Qi::Qi82 => 1e-4,
            DelayCritical5Qi::Qi83 => 1e-4,
            DelayCritical5Qi::Qi84 => 1e-5,
            DelayCritical5Qi::Qi85 => 1e-5,
            DelayCritical5Qi::Qi86 => 1e-4,
        }
    }

    /// Maximum Data Burst Volume (MDBV) in bytes.
    pub fn max_data_burst_volume(&self) -> u32 {
        match self {
            DelayCritical5Qi::Qi80 => 255,
            DelayCritical5Qi::Qi82 => 255,
            DelayCritical5Qi::Qi83 => 1354,
            DelayCritical5Qi::Qi84 => 1354,
            DelayCritical5Qi::Qi85 => 255,
            DelayCritical5Qi::Qi86 => 1354,
        }
    }

    /// 3GPP Scheduling Priority Level (lower number indicates higher priority).
    pub fn priority_level(&self) -> u8 {
        match self {
            DelayCritical5Qi::Qi80 => 68,
            DelayCritical5Qi::Qi82 => 19,
            DelayCritical5Qi::Qi83 => 22,
            DelayCritical5Qi::Qi84 => 24,
            DelayCritical5Qi::Qi85 => 21,
            DelayCritical5Qi::Qi86 => 18,
        }
    }

    /// Default industrial survival time budget in microseconds.
    pub fn default_survival_time_us(&self) -> u64 {
        match self {
            DelayCritical5Qi::Qi80 => 20_000,
            DelayCritical5Qi::Qi82 => 10_000,
            DelayCritical5Qi::Qi83 => 10_000,
            DelayCritical5Qi::Qi84 => 60_000,
            DelayCritical5Qi::Qi85 => 4_000, // Fast teleprotection trip
            DelayCritical5Qi::Qi86 => 2_000, // High-speed robotics
        }
    }
}

// ---------------------------------------------------------------------------
// TSN QoS Mapper
// ---------------------------------------------------------------------------

/// Maps IEEE 802.1Q PCP and VLAN parameters to 3GPP Delay-Critical 5QIs.
#[derive(Debug, Clone)]
pub struct TsnQosMapper {
    custom_mappings: HashMap<(u8, Option<u16>), DelayCritical5Qi>,
}

impl Default for TsnQosMapper {
    fn default() -> Self {
        Self::new()
    }
}

impl TsnQosMapper {
    pub fn new() -> Self {
        TsnQosMapper {
            custom_mappings: HashMap::new(),
        }
    }

    pub fn set_custom_mapping(&mut self, pcp: u8, vlan_id: Option<u16>, five_qi: DelayCritical5Qi) {
        self.custom_mappings.insert((pcp, vlan_id), five_qi);
    }

    /// Map IEEE 802.1Q PCP and optional VLAN ID to Delay-Critical 5QI.
    pub fn map_qos(&self, pcp: EthernetPcp, vlan_id: Option<u16>) -> DelayCritical5Qi {
        let pcp_val = pcp.as_u8();

        // 1. Check exact match with VLAN
        if let Some(five_qi) = self.custom_mappings.get(&(pcp_val, vlan_id)) {
            return *five_qi;
        }

        // 2. Check match with wildcard VLAN
        if let Some(five_qi) = self.custom_mappings.get(&(pcp_val, None)) {
            return *five_qi;
        }

        // 3. Default standardized mapping
        match pcp {
            EthernetPcp::Pcp7NetworkControlOrPtp => DelayCritical5Qi::Qi85,
            EthernetPcp::Pcp6InternetworkControlOrGoose => DelayCritical5Qi::Qi85,
            EthernetPcp::Pcp5VoiceOrSampledValues => DelayCritical5Qi::Qi82,
            EthernetPcp::Pcp4Video => DelayCritical5Qi::Qi83,
            EthernetPcp::Pcp3CriticalApplications => DelayCritical5Qi::Qi84,
            EthernetPcp::Pcp2ExcellentEffort => DelayCritical5Qi::Qi80,
            EthernetPcp::Pcp1Background => DelayCritical5Qi::Qi80,
            EthernetPcp::Pcp0BestEffort => DelayCritical5Qi::Qi80,
        }
    }

    /// Calculate Guaranteed Flow Bit Rate (GFBR) and Maximum Flow Bit Rate (MFBR) in bits per second.
    pub fn calculate_flow_bitrates(
        burst_size_bytes: u32,
        periodicity_us: u64,
        margin_factor: f64,
    ) -> Result<(u64, u64), TscError> {
        if periodicity_us == 0 {
            return Err(TscError::InvalidPeriodicity(0));
        }
        if burst_size_bytes == 0 {
            return Err(TscError::InvalidBurstSize(0));
        }

        // GFBR = (burst_size * 8) / (periodicity_us * 10^-6) = (burst_size * 8 * 1_000_000) / periodicity_us
        let gfbr_bps = (burst_size_bytes as u64)
            .checked_mul(8_000_000)
            .ok_or(TscError::InvalidBurstSize(burst_size_bytes))?
            / periodicity_us;

        let margin = if margin_factor < 1.0 {
            1.25
        } else {
            margin_factor
        };
        let mfbr_bps = (gfbr_bps as f64 * margin) as u64;

        Ok((gfbr_bps, mfbr_bps))
    }
}

// ---------------------------------------------------------------------------
// TSCAI (Time-Sensitive Communication Assistance Information)
// ---------------------------------------------------------------------------

/// Direction of TSC traffic flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TscFlowDirection {
    Uplink,
    Downlink,
}

/// 5G NR Radio Slot Timing calculated from nanosecond reference timestamp.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NrSlotTiming {
    pub radio_frame: u32,
    pub subframe: u32,
    pub slot: u32,
    pub symbol: u32,
    pub scs_khz: u32,
}

/// Time-Sensitive Communication Assistance Information profile (TS 23.501 §5.27.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TscaiProfile {
    pub stream_id: u32,
    pub direction: TscFlowDirection,
    /// Repetition interval in microseconds (e.g. 1000 µs = 1 ms).
    pub periodicity_us: u64,
    /// Reference Burst Arrival Time (BAT) in nanoseconds relative to 5GS grandmaster clock.
    pub burst_arrival_time_ns: u64,
    /// Maximum burst size in bytes.
    pub burst_size_bytes: u32,
    /// Application survival time budget in microseconds.
    pub survival_time_us: u64,
    /// Allowed arrival jitter window in microseconds around expected BAT.
    pub time_window_us: u64,
}

impl TscaiProfile {
    pub fn new(
        stream_id: u32,
        direction: TscFlowDirection,
        periodicity_us: u64,
        burst_arrival_time_ns: u64,
        burst_size_bytes: u32,
        survival_time_us: u64,
        time_window_us: u64,
    ) -> Result<Self, TscError> {
        if periodicity_us == 0 {
            return Err(TscError::InvalidPeriodicity(0));
        }
        if burst_size_bytes == 0 {
            return Err(TscError::InvalidBurstSize(0));
        }

        Ok(TscaiProfile {
            stream_id,
            direction,
            periodicity_us,
            burst_arrival_time_ns,
            burst_size_bytes,
            survival_time_us,
            time_window_us,
        })
    }

    /// Compute scheduled Burst Arrival Time (BAT) for cycle index `cycle`.
    pub fn scheduled_bat_ns(&self, cycle: u64) -> u64 {
        let period_ns = self.periodicity_us.saturating_mul(1_000);
        self.burst_arrival_time_ns
            .saturating_add(cycle.saturating_mul(period_ns))
    }

    /// Check whether actual arrival timestamp falls within allowed TSCAI window.
    pub fn is_within_window(&self, arrival_time_ns: u64, cycle: u64) -> bool {
        let expected_bat_ns = self.scheduled_bat_ns(cycle);
        let window_ns = self.time_window_us.saturating_mul(1_000);

        let diff_ns = if arrival_time_ns >= expected_bat_ns {
            arrival_time_ns - expected_bat_ns
        } else {
            expected_bat_ns - arrival_time_ns
        };

        diff_ns <= window_ns
    }

    /// Translate nanosecond timestamp into 5G NR frame, subframe, slot, and OFDM symbol.
    pub fn calculate_nr_slot_timing(scs_khz: u32, timestamp_ns: u64) -> NrSlotTiming {
        // SCS: 15 kHz (mu=0), 30 kHz (mu=1), 60 kHz (mu=2), 120 kHz (mu=3)
        let slots_per_subframe = match scs_khz {
            15 => 1,
            30 => 2,
            60 => 4,
            120 => 8,
            _ => 2, // default 30 kHz
        };

        let radio_frame_duration_ns: u64 = 10_000_000; // 10 ms
        let subframe_duration_ns: u64 = 1_000_000; // 1 ms
        let slot_duration_ns: u64 = subframe_duration_ns / (slots_per_subframe as u64);
        let symbol_duration_ns: u64 = slot_duration_ns / 14;

        let radio_frame = (timestamp_ns / radio_frame_duration_ns) as u32;
        let ns_in_frame = timestamp_ns % radio_frame_duration_ns;

        let subframe = (ns_in_frame / subframe_duration_ns) as u32;
        let ns_in_subframe = ns_in_frame % subframe_duration_ns;

        let slot = (ns_in_subframe / slot_duration_ns) as u32;
        let ns_in_slot = ns_in_subframe % slot_duration_ns;

        let symbol = ((ns_in_slot / symbol_duration_ns).min(13)) as u32;

        NrSlotTiming {
            radio_frame,
            subframe,
            slot,
            symbol,
            scs_khz,
        }
    }
}

// ---------------------------------------------------------------------------
// Industrial Survival Time State Machine ($T_{survival}$)
// ---------------------------------------------------------------------------

/// State of the Survival Time State Machine (TS 23.501 §5.27.2.5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SurvivalTimeState {
    /// Normal operation: all cyclic packets arriving on schedule.
    Normal,
    /// Survival time active: consecutive packets missed, clock running towards emergency deadline.
    SurvivalTimeActive {
        consecutive_losses: u32,
        elapsed_survival_us: u64,
        max_survival_us: u64,
    },
    /// Recovered from packet drops prior to expiration.
    Recovered {
        missed_packets: u32,
        duration_us: u64,
    },
    /// Application trip triggered: survival time expired, safety relay opened.
    ApplicationTrip {
        reason: String,
        consecutive_losses: u32,
        duration_us: u64,
    },
}

/// State machine transitions emitted during cycle ticks or packet arrivals.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SurvivalTimeTransition {
    NoChange,
    EnteredSurvivalTime {
        consecutive_losses: u32,
        elapsed_us: u64,
    },
    RecoveredToNormal {
        missed_packets: u32,
        duration_us: u64,
    },
    Tripped {
        reason: String,
        consecutive_losses: u32,
        duration_us: u64,
    },
}

/// Survival Time State Machine for an individual TSN deterministic stream.
#[derive(Debug, Clone)]
pub struct SurvivalTimeStateMachine {
    pub stream_id: u32,
    pub periodicity_us: u64,
    pub survival_time_us: u64,
    pub max_consecutive_losses: u32,
    pub state: SurvivalTimeState,
    pub last_arrival_us: Option<u64>,
    pub next_expected_arrival_us: u64,
    pub consecutive_losses: u32,
    pub active_since_us: Option<u64>,
    pub total_trips: u32,
    pub total_recoveries: u32,
}

impl SurvivalTimeStateMachine {
    pub fn new(stream_id: u32, periodicity_us: u64, survival_time_us: u64) -> Self {
        let max_losses = if periodicity_us > 0 {
            (survival_time_us / periodicity_us).max(1) as u32
        } else {
            1
        };

        SurvivalTimeStateMachine {
            stream_id,
            periodicity_us,
            survival_time_us,
            max_consecutive_losses: max_losses,
            state: SurvivalTimeState::Normal,
            last_arrival_us: None,
            next_expected_arrival_us: 0,
            consecutive_losses: 0,
            active_since_us: None,
            total_trips: 0,
            total_recoveries: 0,
        }
    }

    /// Process a successful packet arrival.
    pub fn on_packet_arrival(&mut self, arrival_us: u64) -> SurvivalTimeTransition {
        self.last_arrival_us = Some(arrival_us);
        self.next_expected_arrival_us = arrival_us.saturating_add(self.periodicity_us);

        match self.state {
            SurvivalTimeState::Normal => {
                self.consecutive_losses = 0;
                SurvivalTimeTransition::NoChange
            }
            SurvivalTimeState::SurvivalTimeActive { .. } => {
                let missed = self.consecutive_losses;
                let duration_us =
                    arrival_us.saturating_sub(self.active_since_us.unwrap_or(arrival_us));
                self.consecutive_losses = 0;
                self.active_since_us = None;
                self.total_recoveries += 1;
                self.state = SurvivalTimeState::Recovered {
                    missed_packets: missed,
                    duration_us,
                };
                SurvivalTimeTransition::RecoveredToNormal {
                    missed_packets: missed,
                    duration_us,
                }
            }
            SurvivalTimeState::Recovered { .. } => {
                self.consecutive_losses = 0;
                self.state = SurvivalTimeState::Normal;
                SurvivalTimeTransition::NoChange
            }
            SurvivalTimeState::ApplicationTrip { .. } => {
                // Once tripped, manual or explicit reset is required in industrial safety systems
                SurvivalTimeTransition::NoChange
            }
        }
    }

    /// Periodic cycle evaluation tick.
    pub fn on_cycle_tick(&mut self, current_us: u64) -> SurvivalTimeTransition {
        if matches!(self.state, SurvivalTimeState::ApplicationTrip { .. }) {
            return SurvivalTimeTransition::NoChange;
        }

        // If no packets have ever arrived, wait for first packet
        if self.last_arrival_us.is_none() {
            return SurvivalTimeTransition::NoChange;
        }

        // Check if next expected arrival has been missed
        if current_us >= self.next_expected_arrival_us {
            let missed_cycles =
                ((current_us - self.next_expected_arrival_us) / self.periodicity_us) + 1;
            self.consecutive_losses = missed_cycles as u32;

            if self.active_since_us.is_none() {
                self.active_since_us = Some(self.next_expected_arrival_us);
            }

            let elapsed_us = current_us.saturating_sub(self.active_since_us.unwrap());

            if elapsed_us >= self.survival_time_us {
                // Trip emergency application protection
                self.total_trips += 1;
                self.state = SurvivalTimeState::ApplicationTrip {
                    reason: format!(
                        "Survival time exceeded: elapsed {} us >= budget {} us",
                        elapsed_us, self.survival_time_us
                    ),
                    consecutive_losses: self.consecutive_losses,
                    duration_us: elapsed_us,
                };
                return SurvivalTimeTransition::Tripped {
                    reason: "Survival time limit exceeded".to_string(),
                    consecutive_losses: self.consecutive_losses,
                    duration_us: elapsed_us,
                };
            } else {
                // Update active survival time state
                self.state = SurvivalTimeState::SurvivalTimeActive {
                    consecutive_losses: self.consecutive_losses,
                    elapsed_survival_us: elapsed_us,
                    max_survival_us: self.survival_time_us,
                };
                return SurvivalTimeTransition::EnteredSurvivalTime {
                    consecutive_losses: self.consecutive_losses,
                    elapsed_us,
                };
            }
        }

        SurvivalTimeTransition::NoChange
    }

    /// Check whether emergency RAN scheduling priority boost is recommended.
    pub fn is_ran_priority_boost_active(&self) -> bool {
        matches!(self.state, SurvivalTimeState::SurvivalTimeActive { .. })
    }

    /// Explicit safety reset after an application trip.
    pub fn reset_trip(&mut self) {
        self.state = SurvivalTimeState::Normal;
        self.consecutive_losses = 0;
        self.active_since_us = None;
        self.last_arrival_us = None;
    }
}

// ---------------------------------------------------------------------------
// Hold-and-Forward De-Jittering Buffer
// ---------------------------------------------------------------------------

/// Packet held in the egress de-jittering buffer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeJitterPacket {
    pub packet_id: u64,
    pub sequence_num: u16,
    pub stream_id: u32,
    pub ingress_time_ns: u64,
    pub scheduled_release_time_ns: u64,
    pub payload: Vec<u8>,
}

/// Telemetry metrics for the de-jittering buffer.
#[derive(Debug, Clone, PartialEq)]
pub struct DeJitterMetrics {
    pub total_enqueued: u64,
    pub total_released: u64,
    pub total_dropped_overflow: u64,
    pub total_dropped_late: u64,
    pub current_queue_depth: usize,
    pub min_jitter_ns: i64,
    pub max_jitter_ns: i64,
    pub avg_jitter_abs_ns: f64,
}

/// Egress Hold-and-Forward De-Jittering Buffer bounding release jitter to < 1 µs.
#[derive(Debug, Clone)]
pub struct HoldAndForwardBuffer {
    pub stream_id: u32,
    /// Target end-to-end deterministic delay in nanoseconds.
    pub target_delay_ns: u64,
    pub max_capacity: usize,
    queue: VecDeque<DeJitterPacket>,
    total_enqueued: u64,
    total_released: u64,
    total_dropped_overflow: u64,
    total_dropped_late: u64,
    min_jitter_ns: i64,
    max_jitter_ns: i64,
    accumulated_jitter_abs_ns: u64,
}

impl HoldAndForwardBuffer {
    pub fn new(stream_id: u32, target_delay_ns: u64, max_capacity: usize) -> Self {
        HoldAndForwardBuffer {
            stream_id,
            target_delay_ns,
            max_capacity,
            queue: VecDeque::with_capacity(max_capacity),
            total_enqueued: 0,
            total_released: 0,
            total_dropped_overflow: 0,
            total_dropped_late: 0,
            min_jitter_ns: i64::MAX,
            max_jitter_ns: i64::MIN,
            accumulated_jitter_abs_ns: 0,
        }
    }

    /// Enqueue an arriving packet, computing its scheduled release boundary.
    pub fn enqueue(
        &mut self,
        packet_id: u64,
        sequence_num: u16,
        ingress_time_ns: u64,
        actual_arrival_ns: u64,
        payload: Vec<u8>,
    ) -> Result<u64, TscError> {
        let scheduled_release_ns = ingress_time_ns.saturating_add(self.target_delay_ns);

        // Check if packet arrived after scheduled release boundary
        if actual_arrival_ns > scheduled_release_ns {
            self.total_dropped_late += 1;
            return Err(TscError::PacketTooLate {
                stream_id: self.stream_id,
                scheduled_ns: scheduled_release_ns,
                current_ns: actual_arrival_ns,
            });
        }

        // Check queue capacity
        if self.queue.len() >= self.max_capacity {
            self.total_dropped_overflow += 1;
            return Err(TscError::BufferOverflow {
                stream_id: self.stream_id,
                capacity: self.max_capacity,
            });
        }

        let packet = DeJitterPacket {
            packet_id,
            sequence_num,
            stream_id: self.stream_id,
            ingress_time_ns,
            scheduled_release_time_ns: scheduled_release_ns,
            payload,
        };

        // Insert in chronological scheduled release order
        let insert_idx = self
            .queue
            .binary_search_by_key(&packet.scheduled_release_time_ns, |p| {
                p.scheduled_release_time_ns
            })
            .unwrap_or_else(|idx| idx);

        self.queue.insert(insert_idx, packet);
        self.total_enqueued += 1;

        Ok(scheduled_release_ns)
    }

    /// Pop and release all packets scheduled for release up to `current_time_ns`.
    pub fn release_ready(&mut self, current_time_ns: u64) -> Vec<DeJitterPacket> {
        let mut released = Vec::new();

        while let Some(front) = self.queue.front() {
            if front.scheduled_release_time_ns <= current_time_ns {
                let packet = self.queue.pop_front().unwrap();

                // Calculate jitter relative to exact scheduled release time
                let jitter_ns =
                    (current_time_ns as i64) - (packet.scheduled_release_time_ns as i64);

                self.min_jitter_ns = self.min_jitter_ns.min(jitter_ns);
                self.max_jitter_ns = self.max_jitter_ns.max(jitter_ns);
                self.accumulated_jitter_abs_ns += jitter_ns.unsigned_abs();
                self.total_released += 1;

                released.push(packet);
            } else {
                break;
            }
        }

        released
    }

    /// Retrieve telemetry metrics.
    pub fn metrics(&self) -> DeJitterMetrics {
        let avg_jitter = if self.total_released > 0 {
            (self.accumulated_jitter_abs_ns as f64) / (self.total_released as f64)
        } else {
            0.0
        };

        DeJitterMetrics {
            total_enqueued: self.total_enqueued,
            total_released: self.total_released,
            total_dropped_overflow: self.total_dropped_overflow,
            total_dropped_late: self.total_dropped_late,
            current_queue_depth: self.queue.len(),
            min_jitter_ns: if self.min_jitter_ns == i64::MAX {
                0
            } else {
                self.min_jitter_ns
            },
            max_jitter_ns: if self.max_jitter_ns == i64::MIN {
                0
            } else {
                self.max_jitter_ns
            },
            avg_jitter_abs_ns: avg_jitter,
        }
    }
}

// ---------------------------------------------------------------------------
// IEEE 802.1CB Frame Replication and Elimination for Reliability (FRER)
// ---------------------------------------------------------------------------

/// Outcome of FRER sequence inspection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FrerResult {
    /// New sequence accepted.
    Accepted { sequence: u16 },
    /// Duplicate frame discarded.
    DuplicateDiscarded { sequence: u16 },
    /// Out-of-order frame accepted within sliding history window.
    OutOfOrderAccepted { sequence: u16, distance: i32 },
}

/// IEEE 802.1CB Frame Deduplication Engine using sliding window algorithm.
#[derive(Debug, Clone)]
pub struct FrerDeduplicator {
    pub stream_id: u32,
    pub history_window_size: usize,
    highest_sequence: Option<u16>,
    history_bitmap: u128,
    pub total_received: u64,
    pub total_accepted: u64,
    pub total_duplicates: u64,
    pub total_out_of_order: u64,
}

impl FrerDeduplicator {
    pub fn new(stream_id: u32, history_window_size: usize) -> Self {
        let window = history_window_size.clamp(16, 128);
        FrerDeduplicator {
            stream_id,
            history_window_size: window,
            highest_sequence: None,
            history_bitmap: 0,
            total_received: 0,
            total_accepted: 0,
            total_duplicates: 0,
            total_out_of_order: 0,
        }
    }

    /// Process an arriving 16-bit sequence number.
    pub fn process_sequence(&mut self, seq: u16) -> FrerResult {
        self.total_received += 1;

        match self.highest_sequence {
            None => {
                // First sequence ever received
                self.highest_sequence = Some(seq);
                self.history_bitmap = 1;
                self.total_accepted += 1;
                FrerResult::Accepted { sequence: seq }
            }
            Some(highest) => {
                // 16-bit sequence difference with wrap-around
                let diff = (seq.wrapping_sub(highest)) as i16;

                if diff > 0 {
                    // Forward in-order progression
                    let shift = (diff as usize).min(128);
                    if shift >= 128 {
                        self.history_bitmap = 1;
                    } else {
                        self.history_bitmap = (self.history_bitmap << shift) | 1;
                    }
                    self.highest_sequence = Some(seq);
                    self.total_accepted += 1;
                    FrerResult::Accepted { sequence: seq }
                } else {
                    // diff <= 0: either duplicate or past out-of-order frame
                    let age = (-diff) as usize;

                    if age >= self.history_window_size || age >= 128 {
                        // Beyond window: treat as expired / duplicate discard
                        self.total_duplicates += 1;
                        FrerResult::DuplicateDiscarded { sequence: seq }
                    } else {
                        let bit_mask = 1u128 << age;
                        if (self.history_bitmap & bit_mask) != 0 {
                            // Already received! Duplicate elimination
                            self.total_duplicates += 1;
                            FrerResult::DuplicateDiscarded { sequence: seq }
                        } else {
                            // Valid out-of-order within history window
                            self.history_bitmap |= bit_mask;
                            self.total_accepted += 1;
                            self.total_out_of_order += 1;
                            FrerResult::OutOfOrderAccepted {
                                sequence: seq,
                                distance: diff as i32,
                            }
                        }
                    }
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// TSN Translators & Virtual Bridge Port Delays
// ---------------------------------------------------------------------------

/// TSN Translator Type (TS 23.501 §5.27.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TscTranslatorType {
    /// Device-side TSN Translator (collocated with UE).
    DsTt { ds_tt_port_id: u32, ue_id: u64 },
    /// Network-side TSN Translator (collocated with UPF).
    NwTt { nw_tt_port_id: u32, upf_id: u32 },
}

/// Virtual bridge port delay report (TS 23.501 §5.27.1.4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TscBridgePortDelayReport {
    pub ingress_port: u32,
    pub egress_port: u32,
    pub traffic_class_pcp: u8,
    pub min_bridge_delay_ns: u64,
    pub max_bridge_delay_ns: u64,
    pub nominal_bridge_delay_ns: u64,
}

// ---------------------------------------------------------------------------
// Top-Level TSN Deterministic Engine
// ---------------------------------------------------------------------------

/// Ingress outcome after TSN packet ingestion.
#[derive(Debug, Clone, PartialEq)]
pub struct TscIngressOutcome {
    pub stream_id: u32,
    pub sequence_num: u16,
    pub five_qi: DelayCritical5Qi,
    pub gfbr_bps: u64,
    pub mfbr_bps: u64,
    pub pdb_us: u64,
    pub ingress_time_ns: u64,
    pub frer_result: FrerResult,
}

/// Egress outcome after 5GS transmission and buffer ingestion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TscEgressArrivalOutcome {
    pub stream_id: u32,
    pub sequence_num: u16,
    pub scheduled_release_ns: u64,
    pub frer_result: FrerResult,
}

/// Notifications generated by the TSC engine during cycle ticks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TscEngineNotification {
    SurvivalTransition {
        stream_id: u32,
        transition: SurvivalTimeTransition,
    },
    PacketsReleased {
        stream_id: u32,
        count: usize,
    },
}

/// Combined telemetry for a deterministic TSN stream.
#[derive(Debug, Clone, PartialEq)]
pub struct TscStreamTelemetry {
    pub stream_id: u32,
    pub five_qi: DelayCritical5Qi,
    pub survival_state: SurvivalTimeState,
    pub dejitter_metrics: DeJitterMetrics,
    pub frer_accepted: u64,
    pub frer_duplicates: u64,
    pub total_trips: u32,
    pub total_recoveries: u32,
}

/// Internal per-stream context within the TSC engine.
struct StreamContext {
    profile: TscaiProfile,
    five_qi: DelayCritical5Qi,
    gfbr_bps: u64,
    mfbr_bps: u64,
    dejitter_buffer: HoldAndForwardBuffer,
    survival_state_machine: SurvivalTimeStateMachine,
    ingress_frer: FrerDeduplicator,
    egress_frer: FrerDeduplicator,
    next_packet_id: u64,
}

/// Top-level 3GPP Release 18 Smart Grid & Industrial Automation TSN Deterministic Engine.
pub struct TscEngine {
    pub translator: TscTranslatorType,
    pub bridge_id: [u8; 8],
    pub qos_mapper: TsnQosMapper,
    streams: HashMap<u32, StreamContext>,
}

impl TscEngine {
    /// Create a new TSN Deterministic Engine.
    pub fn new(translator: TscTranslatorType, bridge_id: [u8; 8]) -> Self {
        TscEngine {
            translator,
            bridge_id,
            qos_mapper: TsnQosMapper::new(),
            streams: HashMap::new(),
        }
    }

    /// Register a deterministic TSN stream with TSCAI, target delay, and de-jitter capacity.
    pub fn register_stream(
        &mut self,
        profile: TscaiProfile,
        pcp: EthernetPcp,
        vlan_id: Option<u16>,
        target_delay_ns: u64,
        buffer_capacity: usize,
        frer_window_size: usize,
    ) -> Result<(), TscError> {
        if self.streams.contains_key(&profile.stream_id) {
            return Err(TscError::StreamAlreadyExists(profile.stream_id));
        }

        let five_qi = self.qos_mapper.map_qos(pcp, vlan_id);
        let (gfbr, mfbr) = TsnQosMapper::calculate_flow_bitrates(
            profile.burst_size_bytes,
            profile.periodicity_us,
            1.25,
        )?;

        let survival_machine = SurvivalTimeStateMachine::new(
            profile.stream_id,
            profile.periodicity_us,
            profile.survival_time_us,
        );

        let dejitter =
            HoldAndForwardBuffer::new(profile.stream_id, target_delay_ns, buffer_capacity);
        let ingress_frer = FrerDeduplicator::new(profile.stream_id, frer_window_size);
        let egress_frer = FrerDeduplicator::new(profile.stream_id, frer_window_size);

        let ctx = StreamContext {
            profile: profile.clone(),
            five_qi,
            gfbr_bps: gfbr,
            mfbr_bps: mfbr,
            dejitter_buffer: dejitter,
            survival_state_machine: survival_machine,
            ingress_frer,
            egress_frer,
            next_packet_id: 1,
        };

        self.streams.insert(profile.stream_id, ctx);
        Ok(())
    }

    /// Process ingress TSN frame arriving from external industrial/substation network.
    pub fn process_ingress(
        &mut self,
        stream_id: u32,
        seq: u16,
        ingress_time_ns: u64,
    ) -> Result<TscIngressOutcome, TscError> {
        let stream = self
            .streams
            .get_mut(&stream_id)
            .ok_or(TscError::StreamNotFound(stream_id))?;

        let frer_res = stream.ingress_frer.process_sequence(seq);

        Ok(TscIngressOutcome {
            stream_id,
            sequence_num: seq,
            five_qi: stream.five_qi,
            gfbr_bps: stream.gfbr_bps,
            mfbr_bps: stream.mfbr_bps,
            pdb_us: stream.five_qi.packet_delay_budget_us(),
            ingress_time_ns,
            frer_result: frer_res,
        })
    }

    /// Process egress frame arrival at egress translator (after traversing 5G air interface).
    pub fn process_egress_arrival(
        &mut self,
        stream_id: u32,
        seq: u16,
        payload: Vec<u8>,
        ingress_time_ns: u64,
        actual_arrival_ns: u64,
    ) -> Result<TscEgressArrivalOutcome, TscError> {
        let stream = self
            .streams
            .get_mut(&stream_id)
            .ok_or(TscError::StreamNotFound(stream_id))?;

        // 1. Check FRER deduplication on egress if dual-path was used
        let frer_res = stream.egress_frer.process_sequence(seq);

        if matches!(frer_res, FrerResult::DuplicateDiscarded { .. }) {
            return Ok(TscEgressArrivalOutcome {
                stream_id,
                sequence_num: seq,
                scheduled_release_ns: 0,
                frer_result: frer_res,
            });
        }

        // 2. Notify survival time state machine of packet arrival
        let arrival_us = actual_arrival_ns / 1_000;
        stream.survival_state_machine.on_packet_arrival(arrival_us);

        // 3. Enqueue in hold-and-forward de-jittering buffer
        let packet_id = stream.next_packet_id;
        stream.next_packet_id += 1;

        let scheduled_release = stream.dejitter_buffer.enqueue(
            packet_id,
            seq,
            ingress_time_ns,
            actual_arrival_ns,
            payload,
        )?;

        Ok(TscEgressArrivalOutcome {
            stream_id,
            sequence_num: seq,
            scheduled_release_ns: scheduled_release,
            frer_result: frer_res,
        })
    }

    /// Release ready packets from de-jitter buffer at scheduled time boundary.
    pub fn release_ready_packets(
        &mut self,
        stream_id: u32,
        current_time_ns: u64,
    ) -> Result<Vec<DeJitterPacket>, TscError> {
        let stream = self
            .streams
            .get_mut(&stream_id)
            .ok_or(TscError::StreamNotFound(stream_id))?;

        Ok(stream.dejitter_buffer.release_ready(current_time_ns))
    }

    /// Periodic cycle tick for all registered streams.
    pub fn tick(&mut self, current_time_us: u64) -> Vec<TscEngineNotification> {
        let mut notifications = Vec::new();

        for (&stream_id, stream) in self.streams.iter_mut() {
            let transition = stream.survival_state_machine.on_cycle_tick(current_time_us);
            if transition != SurvivalTimeTransition::NoChange {
                notifications.push(TscEngineNotification::SurvivalTransition {
                    stream_id,
                    transition,
                });
            }
        }

        notifications
    }

    /// Retrieve the TSCAI profile for a registered stream.
    pub fn get_stream_profile(&self, stream_id: u32) -> Option<&TscaiProfile> {
        self.streams.get(&stream_id).map(|s| &s.profile)
    }

    /// Retrieve telemetry metrics for a stream.
    pub fn get_stream_telemetry(&self, stream_id: u32) -> Option<TscStreamTelemetry> {
        let stream = self.streams.get(&stream_id)?;
        Some(TscStreamTelemetry {
            stream_id,
            five_qi: stream.five_qi,
            survival_state: stream.survival_state_machine.state.clone(),
            dejitter_metrics: stream.dejitter_buffer.metrics(),
            frer_accepted: stream.egress_frer.total_accepted,
            frer_duplicates: stream.egress_frer.total_duplicates,
            total_trips: stream.survival_state_machine.total_trips,
            total_recoveries: stream.survival_state_machine.total_recoveries,
        })
    }

    /// Generate port delay report for a stream.
    pub fn report_bridge_delays(&self, stream_id: u32) -> Option<TscBridgePortDelayReport> {
        let stream = self.streams.get(&stream_id)?;
        let nominal_delay = stream.dejitter_buffer.target_delay_ns;
        let min_delay = nominal_delay.saturating_sub(500_000); // Nominal minus 500 µs
        let max_delay = nominal_delay.saturating_add(200_000); // Nominal plus 200 µs margin

        let (ingress_p, egress_p) = match self.translator {
            TscTranslatorType::DsTt { ds_tt_port_id, .. } => (ds_tt_port_id, 1),
            TscTranslatorType::NwTt { nw_tt_port_id, .. } => (nw_tt_port_id, 2),
        };

        Some(TscBridgePortDelayReport {
            ingress_port: ingress_p,
            egress_port: egress_p,
            traffic_class_pcp: EthernetPcp::Pcp6InternetworkControlOrGoose.as_u8(),
            min_bridge_delay_ns: min_delay,
            max_bridge_delay_ns: max_delay,
            nominal_bridge_delay_ns: nominal_delay,
        })
    }
}
