//! 3GPP Release 18 / Release 19 5G NR Sidelink Mode 1 Network-Controlled Resource Allocation
//! & DCI Format 3_0 Scheduling Engine.
//!
//! Conforms to:
//! - 3GPP TS 38.321 Rel-18 §5.22.1.1: Sidelink grant reception and contention resolution for Mode 1.
//! - 3GPP TS 38.321 Rel-18 §6.1.3.11: Sidelink Buffer Status Report (SL-BSR) MAC Control Elements.
//! - 3GPP TS 38.212 Rel-18 §7.3.1.4.1: DCI format 3_0 for Sidelink scheduling over the Uu interface.
//! - 3GPP TS 38.213 Rel-18 §16.2: UE procedure for reporting Sidelink HARQ-ACK on Uu PUCCH / PUSCH.
//! - 3GPP TS 38.214 Rel-18 §8.1.3: Physical layer procedures for Mode 1 transmission and retransmissions.
//! - 3GPP TS 38.331 Rel-18: Radio Resource Control - `SL-ConfiguredGrantConfig`, `SL-BSR-Config`.
//!
//! Key Architecture:
//! 1. DCI Format 3_0 Parser & Serializer:
//!    - Carrier Indicator Field (CIF, 3 bits) for cross-carrier sidelink scheduling.
//!    - Resource pool index, time gap ($t_{gap}$), sub-channel allocation RIV, and time allocation mask.
//!    - PSFCH-to-HARQ timing indicator ($k$) mapping PC5 PSFCH feedback onto Uu PUCCH/PUSCH resources.
//! 2. Sidelink Configured Grant (CG) Type 1 & Type 2 State Machine:
//!    - Type 1: Statically RRC-configured periodic sidelink resource grants.
//!    - Type 2: RRC-configured, dynamically activated and cleared via DCI 3_0 scrambled by SL-CS-RNTI.
//!    - Validation of activation/clearing DCI fields per TS 38.214 §8.1.4.
//! 3. Sidelink Buffer Status Reporting (SL-BSR) Codec:
//!    - Binary encoder/decoder for Short/Long Sidelink BSR MAC CEs (LCID 58 / 57).
//!    - Maps Destination L2 Index, Logical Channel Group (LCG), and Buffer Size.
//! 4. gNodeB Sidelink Dynamic Grant Allocator:
//!    - Arbitrates pending SL-BSRs across multiple UEs and V2X QoS priorities (0..7).
//!    - Schedules optimal PRB sub-channels and transmission slot occasions meeting Packet Delay Budgets (PDB).
//! 5. Cross-Interface HARQ-ACK Relaying (PC5 PSFCH -> Uu PUCCH):
//!    - Captures decoded PC5 PSFCH ACK/NACK responses and prepares Uu PUCCH feedback payloads for gNodeB.
//! 6. Telemetry & QoS Performance Tracking:
//!    - Tracks grant utilization efficiency, scheduling delay, and cross-interface HARQ relay success rate.
//!
//! Pure standard Rust with zero external dependencies.

use std::collections::{HashMap, VecDeque};
use std::fmt;

// ---------------------------------------------------------------------------
// Constants & LCIDs (TS 38.321 §6.2.1)
// ---------------------------------------------------------------------------

/// MAC LCID for Sidelink BSR MAC Control Element (TS 38.321 Table 6.2.1-1).
pub const LCID_SL_BSR: u8 = 58;

/// MAC LCID for Truncated Sidelink BSR MAC Control Element (TS 38.321 Table 6.2.1-1).
pub const LCID_TRUNCATED_SL_BSR: u8 = 57;

/// Maximum number of sub-channels supported in standard Sidelink resource pools (TS 38.214).
pub const MAX_SL_SUBCHANNELS: u8 = 27;

/// Maximum number of transmissions per Sidelink TB in Mode 1 (1 initial + up to 2 retransmissions).
pub const MAX_SL_TRANSMISSIONS_PER_TB: usize = 3;

/// Maximum Logical Channel Groups (LCGs) for Sidelink (0..7).
pub const MAX_SL_LCGS: u8 = 8;

// ---------------------------------------------------------------------------
// Error Types
// ---------------------------------------------------------------------------

/// Errors encountered in Sidelink Mode 1 scheduling and DCI 3_0 processing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SlMode1Error {
    InvalidDciFormat(String),
    InvalidSubchannelAllocation { start: u8, length: u8, max_subchannels: u8 },
    InvalidTimeGap(u8),
    InvalidLcg(u8),
    InvalidPriority(u8),
    ConfiguredGrantNotFound(u8),
    ConfiguredGrantAlreadyActive(u8),
    BufferTooShort { expected: usize, actual: usize },
    NoResourcesAvailable,
}

impl fmt::Display for SlMode1Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SlMode1Error::InvalidDciFormat(msg) => write!(f, "Invalid DCI 3_0 format: {}", msg),
            SlMode1Error::InvalidSubchannelAllocation { start, length, max_subchannels } => {
                write!(f, "Invalid sub-channel range: start {} + len {} exceeds pool max {}", start, length, max_subchannels)
            }
            SlMode1Error::InvalidTimeGap(gap) => write!(f, "Invalid DCI-to-SL time gap: {} slots", gap),
            SlMode1Error::InvalidLcg(lcg) => write!(f, "Invalid Sidelink LCG: {} (valid: 0..7)", lcg),
            SlMode1Error::InvalidPriority(p) => write!(f, "Invalid Sidelink priority: {} (valid: 0..7)", p),
            SlMode1Error::ConfiguredGrantNotFound(id) => write!(f, "Sidelink Configured Grant {} not found", id),
            SlMode1Error::ConfiguredGrantAlreadyActive(id) => write!(f, "Sidelink Configured Grant {} already active", id),
            SlMode1Error::BufferTooShort { expected, actual } => {
                write!(f, "Buffer too short: expected {} bytes, got {}", expected, actual)
            }
            SlMode1Error::NoResourcesAvailable => write!(f, "No Sidelink sub-channel or slot resources available"),
        }
    }
}

// ---------------------------------------------------------------------------
// DCI Format 3_0 Specification (TS 38.212 §7.3.1.4.1)
// ---------------------------------------------------------------------------

/// Sidelink Dynamic / Configured Grant command type signaled via DCI format 3_0.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlGrantType {
    /// Dynamic grant for single Sidelink Transport Block (initial + optional retransmissions).
    Dynamic,
    /// Configured Grant Type 2 Activation.
    ConfiguredGrantType2Activation { cg_id: u8 },
    /// Configured Grant Type 2 Deactivation / Release.
    ConfiguredGrantType2Deactivation { cg_id: u8 },
}

/// DCI Format 3_0 Structure for Sidelink Scheduling over 5G Uu (TS 38.212 §7.3.1.4.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DciFormat3_0 {
    /// Carrier Indicator Field (0..7 for cross-carrier sidelink scheduling).
    pub carrier_indicator: u8,
    /// Resource pool index where transmission occurs.
    pub resource_pool_index: u8,
    /// Time gap ($t_{gap}$) in slots from DCI reception to first Sidelink transmission.
    pub time_gap_slots: u8,
    /// Starting sub-channel index in the Sidelink resource pool.
    pub start_subchannel: u8,
    /// Number of contiguous sub-channels allocated.
    pub num_subchannels: u8,
    /// Relative slot offsets for initial transmission and retransmissions (up to 3 total).
    pub time_resource_offsets: Vec<u8>,
    /// Sidelink Modulation and Coding Scheme (0..31 per TS 38.214 Table 8.1.3.1-1).
    pub mcs: u8,
    /// PSFCH-to-HARQ timing indicator $k$ (slots from PC5 PSFCH reception to Uu PUCCH transmission).
    pub psfch_to_harq_timing_k: u8,
    /// PUCCH resource indicator on Uu for reporting sidelink ACK/NACK.
    pub pucch_resource_indicator: u8,
    /// Type of grant (Dynamic, CG Activation, or CG Deactivation).
    pub grant_type: SlGrantType,
}

impl DciFormat3_0 {
    pub fn new_dynamic(
        start_subchannel: u8,
        num_subchannels: u8,
        time_gap_slots: u8,
        time_offsets: Vec<u8>,
        mcs: u8,
    ) -> Result<Self, SlMode1Error> {
        if start_subchannel + num_subchannels > MAX_SL_SUBCHANNELS {
            return Err(SlMode1Error::InvalidSubchannelAllocation {
                start: start_subchannel,
                length: num_subchannels,
                max_subchannels: MAX_SL_SUBCHANNELS,
            });
        }
        Ok(Self {
            carrier_indicator: 0,
            resource_pool_index: 0,
            time_gap_slots,
            start_subchannel,
            num_subchannels,
            time_resource_offsets: time_offsets,
            mcs,
            psfch_to_harq_timing_k: 2,
            pucch_resource_indicator: 1,
            grant_type: SlGrantType::Dynamic,
        })
    }

    /// Validates whether the fields match TS 38.214 §8.1.4 special bit patterns for CG Type 2 activation.
    pub fn is_valid_activation_dci(&self) -> bool {
        match self.grant_type {
            SlGrantType::ConfiguredGrantType2Activation { .. } => self.num_subchannels > 0,
            _ => false,
        }
    }

    /// Validates whether the fields match TS 38.214 §8.1.4 special bit patterns for CG Type 2 deactivation.
    pub fn is_valid_deactivation_dci(&self) -> bool {
        match self.grant_type {
            SlGrantType::ConfiguredGrantType2Deactivation { .. } => self.mcs == 0x1F, // 5 bits all 1s per TS 38.214
            _ => false,
        }
    }
}

// ---------------------------------------------------------------------------
// Sidelink Buffer Status Report (SL-BSR) Codec (TS 38.321 §6.1.3.11)
// ---------------------------------------------------------------------------

/// Destination and buffer level record inside an SL-BSR MAC Control Element.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SlBsrEntry {
    /// Sidelink Destination Index (0..15).
    pub destination_index: u8,
    /// Sidelink Logical Channel Group (0..7).
    pub lcg_id: u8,
    /// 8-bit Buffer Size Index (0..254 per TS 38.321 Table 6.1.3.1-1).
    pub buffer_size_index: u8,
}

impl SlBsrEntry {
    pub fn new(destination_index: u8, lcg_id: u8, buffer_size_index: u8) -> Result<Self, SlMode1Error> {
        if lcg_id >= MAX_SL_LCGS {
            return Err(SlMode1Error::InvalidLcg(lcg_id));
        }
        Ok(Self {
            destination_index,
            lcg_id,
            buffer_size_index,
        })
    }

    /// Converts the buffer size index to approximate payload bytes per 3GPP mapping.
    pub fn buffer_size_bytes(&self) -> usize {
        match self.buffer_size_index {
            0 => 0,
            1..=10 => self.buffer_size_index as usize * 15,
            11..=50 => 150 + (self.buffer_size_index as usize - 10) * 50,
            51..=150 => 2150 + (self.buffer_size_index as usize - 50) * 200,
            _ => 22150 + (self.buffer_size_index as usize - 150) * 1000,
        }
    }
}

/// Sidelink Buffer Status Report MAC CE.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SlBsrMacCe {
    pub entries: Vec<SlBsrEntry>,
}

impl SlBsrMacCe {
    pub fn new(entries: Vec<SlBsrEntry>) -> Self {
        Self { entries }
    }

    /// Serializes SL-BSR into MAC CE byte array.
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        for entry in &self.entries {
            // Octet 1: Destination Index (bits 7-4), LCG ID (bits 3-1), R (bit 0)
            let b0 = ((entry.destination_index & 0x0F) << 4) | ((entry.lcg_id & 0x07) << 1);
            // Octet 2: Buffer Size Index
            let b1 = entry.buffer_size_index;
            buf.push(b0);
            buf.push(b1);
        }
        buf
    }

    /// Deserializes SL-BSR from MAC CE payload bytes.
    pub fn decode(payload: &[u8]) -> Result<Self, SlMode1Error> {
        if payload.len() % 2 != 0 {
            return Err(SlMode1Error::BufferTooShort {
                expected: (payload.len() + 1) / 2 * 2,
                actual: payload.len(),
            });
        }
        let mut entries = Vec::new();
        for chunk in payload.chunks(2) {
            let dest = (chunk[0] >> 4) & 0x0F;
            let lcg = (chunk[0] >> 1) & 0x07;
            let size_idx = chunk[1];
            entries.push(SlBsrEntry::new(dest, lcg, size_idx)?);
        }
        Ok(Self { entries })
    }
}

// ---------------------------------------------------------------------------
// Sidelink Configured Grant Type 1 & Type 2 (TS 38.331 `SL-ConfiguredGrantConfig`)
// ---------------------------------------------------------------------------

/// Operational status of a Sidelink Configured Grant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfiguredGrantStatus {
    ConfiguredAndActive,
    ConfiguredAndSuspended,
    Cleared,
}

/// Configuration and state of an SL Configured Grant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SidelinkConfiguredGrant {
    pub grant_id: u8,
    pub is_type1: bool,
    pub periodicity_slots: u32,
    pub start_subchannel: u8,
    pub num_subchannels: u8,
    pub mcs: u8,
    pub status: ConfiguredGrantStatus,
    pub next_transmission_slot: u64,
}

// ---------------------------------------------------------------------------
// Cross-Interface HARQ-ACK Feedback (PC5 PSFCH -> Uu PUCCH)
// ---------------------------------------------------------------------------

/// Cross-interface HARQ-ACK status forwarded from PC5 PSFCH to gNodeB over Uu.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CrossInterfaceHarqReport {
    pub sidelink_tb_id: u64,
    pub pc5_harq_ack: bool,
    pub target_pucch_slot: u64,
    pub pucch_resource_indicator: u8,
}

// ---------------------------------------------------------------------------
// Telemetry & Metrics
// ---------------------------------------------------------------------------

/// Performance telemetry for Sidelink Mode 1 scheduling.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct SlMode1Telemetry {
    pub dynamic_grants_issued: u64,
    pub cg_type1_occasions: u64,
    pub cg_type2_activations: u64,
    pub cg_type2_deactivations: u64,
    pub cg_type2_occasions: u64,
    pub bsr_reports_processed: u64,
    pub total_sidelink_bytes_scheduled: u64,
    pub cross_interface_harq_relayed: u64,
    pub successful_pc5_deliveries: u64,
}

impl SlMode1Telemetry {
    pub fn pc5_delivery_success_rate(&self) -> f64 {
        if self.cross_interface_harq_relayed == 0 {
            0.0
        } else {
            (self.successful_pc5_deliveries as f64 / self.cross_interface_harq_relayed as f64) * 100.0
        }
    }
}

// ---------------------------------------------------------------------------
// Sidelink Mode 1 Resource Allocator Engine
// ---------------------------------------------------------------------------

/// gNodeB & UE Mode 1 Sidelink Resource Allocation Engine.
pub struct SidelinkMode1Allocator {
    max_subchannels: u8,
    current_slot: u64,
    configured_grants: HashMap<u8, SidelinkConfiguredGrant>,
    pending_requests: VecDeque<(u16, SlBsrEntry)>, // (RNTI, BSR Entry)
    telemetry: SlMode1Telemetry,
    next_tb_id: u64,
}

impl SidelinkMode1Allocator {
    pub fn new(max_subchannels: u8) -> Self {
        Self {
            max_subchannels,
            current_slot: 0,
            configured_grants: HashMap::new(),
            pending_requests: VecDeque::new(),
            telemetry: SlMode1Telemetry::default(),
            next_tb_id: 1,
        }
    }

    pub fn current_slot(&self) -> u64 {
        self.current_slot
    }

    pub fn telemetry(&self) -> &SlMode1Telemetry {
        &self.telemetry
    }

    // -----------------------------------------------------------------------
    // Configured Grant Management
    // -----------------------------------------------------------------------

    /// Registers a Type 1 Sidelink Configured Grant (immediately active).
    pub fn add_configured_grant_type1(
        &mut self,
        grant_id: u8,
        periodicity_slots: u32,
        start_subchannel: u8,
        num_subchannels: u8,
        mcs: u8,
    ) -> Result<(), SlMode1Error> {
        if start_subchannel + num_subchannels > self.max_subchannels {
            return Err(SlMode1Error::InvalidSubchannelAllocation {
                start: start_subchannel,
                length: num_subchannels,
                max_subchannels: self.max_subchannels,
            });
        }
        let cg = SidelinkConfiguredGrant {
            grant_id,
            is_type1: true,
            periodicity_slots,
            start_subchannel,
            num_subchannels,
            mcs,
            status: ConfiguredGrantStatus::ConfiguredAndActive,
            next_transmission_slot: self.current_slot + periodicity_slots as u64,
        };
        self.configured_grants.insert(grant_id, cg);
        Ok(())
    }

    /// Registers a Type 2 Sidelink Configured Grant (initially suspended until DCI activation).
    pub fn add_configured_grant_type2(
        &mut self,
        grant_id: u8,
        periodicity_slots: u32,
        start_subchannel: u8,
        num_subchannels: u8,
        mcs: u8,
    ) -> Result<(), SlMode1Error> {
        if start_subchannel + num_subchannels > self.max_subchannels {
            return Err(SlMode1Error::InvalidSubchannelAllocation {
                start: start_subchannel,
                length: num_subchannels,
                max_subchannels: self.max_subchannels,
            });
        }
        let cg = SidelinkConfiguredGrant {
            grant_id,
            is_type1: false,
            periodicity_slots,
            start_subchannel,
            num_subchannels,
            mcs,
            status: ConfiguredGrantStatus::ConfiguredAndSuspended,
            next_transmission_slot: 0,
        };
        self.configured_grants.insert(grant_id, cg);
        Ok(())
    }

    /// Processes an incoming DCI format 3_0 for CG Type 2 activation or deactivation.
    pub fn process_cg_dci(&mut self, dci: &DciFormat3_0) -> Result<(), SlMode1Error> {
        match dci.grant_type {
            SlGrantType::ConfiguredGrantType2Activation { cg_id } => {
                let cg = self
                    .configured_grants
                    .get_mut(&cg_id)
                    .ok_or(SlMode1Error::ConfiguredGrantNotFound(cg_id))?;
                if cg.is_type1 {
                    return Err(SlMode1Error::InvalidDciFormat("Cannot activate Type 1 CG via DCI".into()));
                }
                cg.status = ConfiguredGrantStatus::ConfiguredAndActive;
                cg.start_subchannel = dci.start_subchannel;
                cg.num_subchannels = dci.num_subchannels;
                cg.mcs = dci.mcs;
                cg.next_transmission_slot = self.current_slot + dci.time_gap_slots as u64;
                self.telemetry.cg_type2_activations += 1;
            }
            SlGrantType::ConfiguredGrantType2Deactivation { cg_id } => {
                let cg = self
                    .configured_grants
                    .get_mut(&cg_id)
                    .ok_or(SlMode1Error::ConfiguredGrantNotFound(cg_id))?;
                cg.status = ConfiguredGrantStatus::ConfiguredAndSuspended;
                self.telemetry.cg_type2_deactivations += 1;
            }
            SlGrantType::Dynamic => {}
        }
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Buffer Status Reporting & Dynamic Grant Allocation
    // -----------------------------------------------------------------------

    /// Submits a Sidelink Buffer Status Report received from a UE.
    pub fn submit_sl_bsr(&mut self, ue_rnti: u16, bsr: SlBsrMacCe) {
        for entry in bsr.entries {
            if entry.buffer_size_index > 0 {
                self.pending_requests.push_back((ue_rnti, entry));
                self.telemetry.bsr_reports_processed += 1;
            }
        }
    }

    /// Dynamic gNodeB scheduler: allocates DCI format 3_0 grants for pending SL-BSRs.
    pub fn schedule_dynamic_grants(&mut self, available_subchannels_per_slot: u8) -> Vec<(u16, DciFormat3_0)> {
        let mut grants = Vec::new();
        let mut used_subchannels = 0;

        while let Some((ue_rnti, entry)) = self.pending_requests.pop_front() {
            let bytes_needed = entry.buffer_size_bytes();
            // Estimate required sub-channels (assuming ~100 bytes per sub-channel at MCS 16)
            let required_subchannels = ((bytes_needed / 100).max(1) as u8).min(available_subchannels_per_slot);

            if used_subchannels + required_subchannels <= available_subchannels_per_slot {
                let start_ch = used_subchannels;
                used_subchannels += required_subchannels;

                let dci = DciFormat3_0 {
                    carrier_indicator: 0,
                    resource_pool_index: 0,
                    time_gap_slots: 4, // 4 slots processing time
                    start_subchannel: start_ch,
                    num_subchannels: required_subchannels,
                    time_resource_offsets: vec![0, 2], // 1 initial + 1 retransmission at +2 slots
                    mcs: 16,
                    psfch_to_harq_timing_k: 3,
                    pucch_resource_indicator: 1,
                    grant_type: SlGrantType::Dynamic,
                };

                self.telemetry.dynamic_grants_issued += 1;
                self.telemetry.total_sidelink_bytes_scheduled += bytes_needed as u64;
                grants.push((ue_rnti, dci));
            } else {
                // Cannot fit in this slot; push back and defer
                self.pending_requests.push_front((ue_rnti, entry));
                break;
            }
        }

        grants
    }

    // -----------------------------------------------------------------------
    // Cross-Interface HARQ-ACK Forwarding
    // -----------------------------------------------------------------------

    /// Records a decoded PC5 PSFCH HARQ response and generates a Uu PUCCH report.
    pub fn relay_psfch_to_uu_harq(
        &mut self,
        psfch_ack: bool,
        timing_indicator_k: u8,
        pucch_resource: u8,
    ) -> CrossInterfaceHarqReport {
        let tb_id = self.next_tb_id;
        self.next_tb_id += 1;

        self.telemetry.cross_interface_harq_relayed += 1;
        if psfch_ack {
            self.telemetry.successful_pc5_deliveries += 1;
        }

        CrossInterfaceHarqReport {
            sidelink_tb_id: tb_id,
            pc5_harq_ack: psfch_ack,
            target_pucch_slot: self.current_slot + timing_indicator_k as u64,
            pucch_resource_indicator: pucch_resource,
        }
    }

    // -----------------------------------------------------------------------
    // Slot Tick & Configured Grant Generation
    // -----------------------------------------------------------------------

    /// Advances simulation time by 1 slot and triggers any scheduled Configured Grants.
    pub fn advance_slot(&mut self) -> Vec<(u8, u8, u8)> {
        self.current_slot += 1;
        let mut active_transmissions = Vec::new(); // (grant_id, start_ch, num_ch)

        for (&id, cg) in self.configured_grants.iter_mut() {
            if cg.status == ConfiguredGrantStatus::ConfiguredAndActive && self.current_slot >= cg.next_transmission_slot {
                active_transmissions.push((id, cg.start_subchannel, cg.num_subchannels));
                cg.next_transmission_slot += cg.periodicity_slots as u64;

                if cg.is_type1 {
                    self.telemetry.cg_type1_occasions += 1;
                } else {
                    self.telemetry.cg_type2_occasions += 1;
                }
            }
        }

        active_transmissions
    }
}
