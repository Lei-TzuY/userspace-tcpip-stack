//! 3GPP Release 18/19 5G-Advanced NR MAC-Layer Scheduler Engine.
//!
//! Standards Reference:
//! - 3GPP TS 38.321 Rel-18: Medium Access Control (MAC) protocol specification.
//! - 3GPP TS 38.214 Rel-18 §5.1: Downlink resource allocation.
//! - 3GPP TS 38.214 Rel-18 §6.1: Uplink resource allocation.
//! - 3GPP TS 38.214 Rel-18 §5.2: MCS / CQI tables (including 1024QAM Table 5.2.2.1-5).
//!
//! Features:
//! 1. Round-Robin and Proportional Fair scheduling algorithms.
//! 2. Per-UE buffer status tracking (BSR decoding).
//! 3. CQI→MCS→TBS mapping with Rel-18 1024QAM support.
//! 4. PRB allocation with configurable bandwidth parts.
//! 5. HARQ process management (up to 16 processes per UE).
//! 6. QoS-aware priority scheduling (5QI-based).
//! 7. DRX-aware scheduling: skip UEs in inactive DRX state.
//! 8. Binary wire framing with CRC-16 CCITT integrity.

use std::fmt;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Magic bytes for MAC Scheduler Wire PDU: "MACS" (0x4D414353).
pub const MAC_SCHED_WIRE_MAGIC: u32 = 0x4D414353;

/// CRC-16 CCITT polynomial.
pub const CRC16_POLY: u16 = 0x1021;

/// Maximum HARQ processes per UE (TS 38.321).
pub const MAX_HARQ_PROCESSES: usize = 16;

/// Maximum number of UEs the scheduler can handle.
pub const MAX_UES: usize = 256;

/// Maximum PRBs in a slot for FR1 (100 MHz, SCS 30 kHz → 273 PRBs).
pub const MAX_PRBS_FR1: usize = 273;

/// Maximum PRBs in a slot for FR2 (400 MHz, SCS 120 kHz → 264 PRBs).
pub const MAX_PRBS_FR2: usize = 264;

// ---------------------------------------------------------------------------
// Error Types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MacSchedError {
    UeNotFound(u16),
    NoPrbsAvailable,
    InvalidCqi(u8),
    InvalidMcs(u8),
    HarqExhausted(u16),
    BufferEmpty(u16),
    InvalidBwpConfig(String),
    SerializationError(String),
    DeserializationError(String),
}

impl fmt::Display for MacSchedError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MacSchedError::UeNotFound(rnti) => write!(f, "UE RNTI 0x{:04X} not found", rnti),
            MacSchedError::NoPrbsAvailable => write!(f, "No PRBs available for allocation"),
            MacSchedError::InvalidCqi(c) => write!(f, "Invalid CQI value: {}", c),
            MacSchedError::InvalidMcs(m) => write!(f, "Invalid MCS index: {}", m),
            MacSchedError::HarqExhausted(rnti) => {
                write!(f, "All HARQ processes exhausted for RNTI 0x{:04X}", rnti)
            }
            MacSchedError::BufferEmpty(rnti) => {
                write!(f, "Buffer empty for RNTI 0x{:04X}", rnti)
            }
            MacSchedError::InvalidBwpConfig(s) => write!(f, "Invalid BWP config: {}", s),
            MacSchedError::SerializationError(s) => write!(f, "Serialization error: {}", s),
            MacSchedError::DeserializationError(s) => write!(f, "Deserialization error: {}", s),
        }
    }
}

impl std::error::Error for MacSchedError {}

// ---------------------------------------------------------------------------
// Scheduling Algorithm Selection
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SchedulingAlgorithm {
    RoundRobin,
    ProportionalFair,
    MaxCqi,
    QosAware,
}

// ---------------------------------------------------------------------------
// CQI → MCS → TBS Mapping (TS 38.214 Table 5.2.2.1-2 / -5)
// ---------------------------------------------------------------------------

/// CQI-to-MCS mapping entry.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct CqiMcsEntry {
    pub cqi: u8,
    pub modulation_order: u8, // Qm: 2=QPSK, 4=16QAM, 6=64QAM, 8=256QAM, 10=1024QAM
    pub code_rate_x1024: u16,
    pub spectral_efficiency: f64,
    pub mcs_index: u8,
}

/// Standard CQI table (TS 38.214 Table 5.2.2.1-2 + Rel-18 1024QAM extension).
pub fn get_cqi_table() -> Vec<CqiMcsEntry> {
    vec![
        CqiMcsEntry { cqi: 0,  modulation_order: 0,  code_rate_x1024: 0,    spectral_efficiency: 0.0,    mcs_index: 0 },
        CqiMcsEntry { cqi: 1,  modulation_order: 2,  code_rate_x1024: 78,   spectral_efficiency: 0.1523, mcs_index: 0 },
        CqiMcsEntry { cqi: 2,  modulation_order: 2,  code_rate_x1024: 120,  spectral_efficiency: 0.2344, mcs_index: 1 },
        CqiMcsEntry { cqi: 3,  modulation_order: 2,  code_rate_x1024: 193,  spectral_efficiency: 0.3770, mcs_index: 3 },
        CqiMcsEntry { cqi: 4,  modulation_order: 2,  code_rate_x1024: 308,  spectral_efficiency: 0.6016, mcs_index: 5 },
        CqiMcsEntry { cqi: 5,  modulation_order: 2,  code_rate_x1024: 449,  spectral_efficiency: 0.8770, mcs_index: 7 },
        CqiMcsEntry { cqi: 6,  modulation_order: 2,  code_rate_x1024: 602,  spectral_efficiency: 1.1758, mcs_index: 9 },
        CqiMcsEntry { cqi: 7,  modulation_order: 4,  code_rate_x1024: 378,  spectral_efficiency: 1.4766, mcs_index: 11 },
        CqiMcsEntry { cqi: 8,  modulation_order: 4,  code_rate_x1024: 490,  spectral_efficiency: 1.9141, mcs_index: 13 },
        CqiMcsEntry { cqi: 9,  modulation_order: 4,  code_rate_x1024: 616,  spectral_efficiency: 2.4063, mcs_index: 15 },
        CqiMcsEntry { cqi: 10, modulation_order: 6,  code_rate_x1024: 466,  spectral_efficiency: 2.7305, mcs_index: 18 },
        CqiMcsEntry { cqi: 11, modulation_order: 6,  code_rate_x1024: 567,  spectral_efficiency: 3.3223, mcs_index: 20 },
        CqiMcsEntry { cqi: 12, modulation_order: 6,  code_rate_x1024: 666,  spectral_efficiency: 3.9023, mcs_index: 22 },
        CqiMcsEntry { cqi: 13, modulation_order: 6,  code_rate_x1024: 772,  spectral_efficiency: 4.5234, mcs_index: 24 },
        CqiMcsEntry { cqi: 14, modulation_order: 8,  code_rate_x1024: 873,  spectral_efficiency: 5.1152, mcs_index: 26 },
        CqiMcsEntry { cqi: 15, modulation_order: 10, code_rate_x1024: 948,  spectral_efficiency: 5.5547, mcs_index: 28 },
    ]
}

/// Maps CQI index to MCS entry.
pub fn cqi_to_mcs(cqi: u8) -> Result<CqiMcsEntry, MacSchedError> {
    if cqi > 15 {
        return Err(MacSchedError::InvalidCqi(cqi));
    }
    let table = get_cqi_table();
    Ok(table[cqi as usize])
}

/// Computes approximate Transport Block Size (TBS) in bits.
/// Simplified from TS 38.214 §5.1.3.2.
pub fn compute_tbs(
    n_prb: usize,
    n_re_per_prb: usize,  // typically 12 subcarriers * symbols_per_slot (minus DMRS)
    mcs_entry: &CqiMcsEntry,
    n_layers: usize,
) -> usize {
    if mcs_entry.modulation_order == 0 {
        return 0;
    }
    let n_re = n_prb * n_re_per_prb;
    let n_info = (n_re as f64
        * mcs_entry.modulation_order as f64
        * (mcs_entry.code_rate_x1024 as f64 / 1024.0)
        * n_layers as f64) as usize;

    // Quantize to byte boundary
    if n_info <= 3824 {
        // Use small TBS quantization
        let n = ((n_info as f64 / 8.0).floor() as usize).max(1) * 8;
        n
    } else {
        // Large TBS: round to nearest 8 bits
        let n = ((n_info + 7) / 8) * 8;
        n
    }
}

// ---------------------------------------------------------------------------
// UE Context
// ---------------------------------------------------------------------------

/// HARQ process state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HarqState {
    Idle,
    WaitingForAck,
    NackRetransmit,
}

/// Single HARQ process.
#[derive(Debug, Clone)]
pub struct HarqProcess {
    pub id: u8,
    pub state: HarqState,
    pub ndi: bool,         // New Data Indicator
    pub rv: u8,            // Redundancy Version (0-3)
    pub retx_count: u8,
    pub max_retx: u8,
    pub tbs: usize,
    pub mcs: u8,
    pub prb_start: usize,
    pub prb_count: usize,
}

impl HarqProcess {
    pub fn new(id: u8, max_retx: u8) -> Self {
        Self {
            id,
            state: HarqState::Idle,
            ndi: false,
            rv: 0,
            retx_count: 0,
            max_retx,
            tbs: 0,
            mcs: 0,
            prb_start: 0,
            prb_count: 0,
        }
    }

    pub fn is_idle(&self) -> bool {
        self.state == HarqState::Idle
    }

    pub fn start_new_tx(&mut self, tbs: usize, mcs: u8, prb_start: usize, prb_count: usize) {
        self.state = HarqState::WaitingForAck;
        self.ndi = !self.ndi;
        self.rv = 0;
        self.retx_count = 0;
        self.tbs = tbs;
        self.mcs = mcs;
        self.prb_start = prb_start;
        self.prb_count = prb_count;
    }

    pub fn ack(&mut self) {
        self.state = HarqState::Idle;
    }

    pub fn nack(&mut self) -> bool {
        if self.retx_count >= self.max_retx {
            self.state = HarqState::Idle;
            return false; // Exhausted
        }
        self.retx_count += 1;
        self.rv = [0, 2, 3, 1][self.retx_count as usize % 4]; // RV cycling
        self.state = HarqState::NackRetransmit;
        true
    }
}

/// DRX state for a UE.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DrxState {
    Active,
    OnDurationTimer,
    InactivityTimer,
    ShortCycle,
    LongCycle,
}

/// 5QI-based QoS parameters (TS 23.501 Table 5.7.4-1).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct QosParams {
    pub five_qi: u8,
    pub priority_level: u8,       // 1 (highest) to 127 (lowest)
    pub packet_delay_budget_ms: u32,
    pub packet_error_rate_exp: u8, // 10^-N
    pub is_gbr: bool,
    pub guaranteed_bitrate_kbps: u64,
    pub max_bitrate_kbps: u64,
}

impl QosParams {
    /// Returns default QoS for common 5QI values.
    pub fn from_5qi(five_qi: u8) -> Self {
        match five_qi {
            1 => QosParams {
                five_qi: 1, priority_level: 20, packet_delay_budget_ms: 100,
                packet_error_rate_exp: 2, is_gbr: true,
                guaranteed_bitrate_kbps: 0, max_bitrate_kbps: 0,
            },
            5 => QosParams {
                five_qi: 5, priority_level: 10, packet_delay_budget_ms: 100,
                packet_error_rate_exp: 6, is_gbr: false,
                guaranteed_bitrate_kbps: 0, max_bitrate_kbps: 0,
            },
            9 => QosParams {
                five_qi: 9, priority_level: 90, packet_delay_budget_ms: 300,
                packet_error_rate_exp: 6, is_gbr: false,
                guaranteed_bitrate_kbps: 0, max_bitrate_kbps: 0,
            },
            _ => QosParams {
                five_qi, priority_level: 50, packet_delay_budget_ms: 150,
                packet_error_rate_exp: 3, is_gbr: false,
                guaranteed_bitrate_kbps: 0, max_bitrate_kbps: 0,
            },
        }
    }
}

/// Per-UE scheduling context.
#[derive(Debug, Clone)]
pub struct UeContext {
    pub rnti: u16,
    pub cqi: u8,
    pub buffer_size_bytes: u64,
    pub harq_processes: Vec<HarqProcess>,
    pub drx_state: DrxState,
    pub qos: QosParams,
    pub avg_throughput: f64,  // For Proportional Fair metric (exponential moving average)
    pub last_scheduled_slot: u64,
    pub total_bytes_scheduled: u64,
}

impl UeContext {
    pub fn new(rnti: u16, five_qi: u8) -> Self {
        let mut harq = Vec::with_capacity(MAX_HARQ_PROCESSES);
        for i in 0..MAX_HARQ_PROCESSES {
            harq.push(HarqProcess::new(i as u8, 4));
        }
        Self {
            rnti,
            cqi: 7, // default mid-range
            buffer_size_bytes: 0,
            harq_processes: harq,
            drx_state: DrxState::Active,
            qos: QosParams::from_5qi(five_qi),
            avg_throughput: 1.0, // Avoid division by zero
            last_scheduled_slot: 0,
            total_bytes_scheduled: 0,
        }
    }

    /// Update CQI from CSI report.
    pub fn update_cqi(&mut self, cqi: u8) {
        self.cqi = cqi.min(15);
    }

    /// Update buffer status from BSR MAC CE.
    pub fn update_buffer_status(&mut self, bytes: u64) {
        self.buffer_size_bytes = bytes;
    }

    /// Get an idle HARQ process.
    pub fn get_idle_harq(&self) -> Option<u8> {
        self.harq_processes
            .iter()
            .find(|h| h.is_idle())
            .map(|h| h.id)
    }

    /// Get a HARQ process needing retransmission.
    pub fn get_retx_harq(&self) -> Option<u8> {
        self.harq_processes
            .iter()
            .find(|h| h.state == HarqState::NackRetransmit)
            .map(|h| h.id)
    }

    /// Update exponential moving average throughput.
    pub fn update_avg_throughput(&mut self, bits_this_slot: f64, alpha: f64) {
        self.avg_throughput = alpha * bits_this_slot + (1.0 - alpha) * self.avg_throughput;
        if self.avg_throughput < 1.0 {
            self.avg_throughput = 1.0; // Floor to prevent division by zero
        }
    }

    /// Is this UE schedulable?
    pub fn is_schedulable(&self) -> bool {
        self.drx_state == DrxState::Active || self.drx_state == DrxState::OnDurationTimer
    }
}

// ---------------------------------------------------------------------------
// PRB Allocation Map
// ---------------------------------------------------------------------------

/// Tracks PRB allocation within a single slot.
#[derive(Debug, Clone)]
pub struct PrbAllocationMap {
    pub total_prbs: usize,
    pub allocated: Vec<bool>,
}

impl PrbAllocationMap {
    pub fn new(total_prbs: usize) -> Self {
        Self {
            total_prbs,
            allocated: vec![false; total_prbs],
        }
    }

    /// Find and allocate a contiguous block of `count` PRBs.
    pub fn allocate_contiguous(&mut self, count: usize) -> Option<usize> {
        if count == 0 || count > self.total_prbs {
            return None;
        }
        let mut start = 0;
        while start + count <= self.total_prbs {
            let block_free = (start..start + count).all(|i| !self.allocated[i]);
            if block_free {
                for i in start..start + count {
                    self.allocated[i] = true;
                }
                return Some(start);
            }
            start += 1;
        }
        None
    }

    /// Release PRBs.
    pub fn release(&mut self, start: usize, count: usize) {
        for i in start..start.saturating_add(count).min(self.total_prbs) {
            self.allocated[i] = false;
        }
    }

    /// Count free PRBs.
    pub fn free_count(&self) -> usize {
        self.allocated.iter().filter(|&&a| !a).count()
    }

    /// Reset all PRBs for new slot.
    pub fn reset(&mut self) {
        self.allocated.fill(false);
    }
}

// ---------------------------------------------------------------------------
// Scheduling Decision Output
// ---------------------------------------------------------------------------

/// A single scheduling grant (DCI content equivalent).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SchedGrant {
    pub rnti: u16,
    pub harq_id: u8,
    pub prb_start: usize,
    pub prb_count: usize,
    pub mcs: u8,
    pub ndi: bool,
    pub rv: u8,
    pub tbs_bits: usize,
    pub is_retransmission: bool,
}

/// Result of a scheduling round.
#[derive(Debug, Clone)]
pub struct SchedResult {
    pub slot_index: u64,
    pub grants: Vec<SchedGrant>,
    pub total_prbs_used: usize,
    pub total_prbs_available: usize,
}

// ---------------------------------------------------------------------------
// MAC Scheduler Engine
// ---------------------------------------------------------------------------

pub struct MacScheduler {
    pub algorithm: SchedulingAlgorithm,
    pub ue_contexts: Vec<UeContext>,
    pub total_prbs: usize,
    pub n_re_per_prb: usize,  // Typically ~156 (12 SC * 14 symbols - DMRS overhead)
    pub n_layers: usize,
    pub current_slot: u64,
    rr_index: usize,          // Round-robin pointer
    pf_alpha: f64,            // PF throughput smoothing factor
}

impl MacScheduler {
    pub fn new(
        algorithm: SchedulingAlgorithm,
        total_prbs: usize,
        n_re_per_prb: usize,
        n_layers: usize,
    ) -> Self {
        Self {
            algorithm,
            ue_contexts: Vec::new(),
            total_prbs,
            n_re_per_prb,
            n_layers,
            current_slot: 0,
            rr_index: 0,
            pf_alpha: 0.01, // Slow EMA for throughput averaging
        }
    }

    /// Add a UE to the scheduler.
    pub fn add_ue(&mut self, rnti: u16, five_qi: u8) {
        if !self.ue_contexts.iter().any(|u| u.rnti == rnti) {
            self.ue_contexts.push(UeContext::new(rnti, five_qi));
        }
    }

    /// Remove a UE from the scheduler.
    pub fn remove_ue(&mut self, rnti: u16) -> bool {
        let before = self.ue_contexts.len();
        self.ue_contexts.retain(|u| u.rnti != rnti);
        self.ue_contexts.len() < before
    }

    /// Get mutable reference to a UE context.
    pub fn get_ue_mut(&mut self, rnti: u16) -> Option<&mut UeContext> {
        self.ue_contexts.iter_mut().find(|u| u.rnti == rnti)
    }

    /// Get immutable reference to a UE context.
    pub fn get_ue(&self, rnti: u16) -> Option<&UeContext> {
        self.ue_contexts.iter().find(|u| u.rnti == rnti)
    }

    /// Process HARQ ACK/NACK feedback.
    pub fn process_harq_feedback(
        &mut self,
        rnti: u16,
        harq_id: u8,
        is_ack: bool,
    ) -> Result<(), MacSchedError> {
        let ue = self.ue_contexts.iter_mut().find(|u| u.rnti == rnti)
            .ok_or(MacSchedError::UeNotFound(rnti))?;

        if (harq_id as usize) < ue.harq_processes.len() {
            if is_ack {
                ue.harq_processes[harq_id as usize].ack();
            } else {
                ue.harq_processes[harq_id as usize].nack();
            }
        }
        Ok(())
    }

    /// Run one scheduling round for the current slot.
    pub fn schedule_slot(&mut self) -> SchedResult {
        let slot = self.current_slot;
        self.current_slot += 1;

        let mut prb_map = PrbAllocationMap::new(self.total_prbs);
        let mut grants = Vec::new();

        match self.algorithm {
            SchedulingAlgorithm::RoundRobin => {
                self.schedule_round_robin(&mut prb_map, &mut grants, slot);
            }
            SchedulingAlgorithm::ProportionalFair => {
                self.schedule_proportional_fair(&mut prb_map, &mut grants, slot);
            }
            SchedulingAlgorithm::MaxCqi => {
                self.schedule_max_cqi(&mut prb_map, &mut grants, slot);
            }
            SchedulingAlgorithm::QosAware => {
                self.schedule_qos_aware(&mut prb_map, &mut grants, slot);
            }
        }

        let total_used = self.total_prbs - prb_map.free_count();

        SchedResult {
            slot_index: slot,
            grants,
            total_prbs_used: total_used,
            total_prbs_available: self.total_prbs,
        }
    }

    fn schedule_round_robin(
        &mut self,
        prb_map: &mut PrbAllocationMap,
        grants: &mut Vec<SchedGrant>,
        slot: u64,
    ) {
        let n_ue = self.ue_contexts.len();
        if n_ue == 0 {
            return;
        }

        // Distribute PRBs equally among schedulable UEs
        let schedulable: Vec<usize> = (0..n_ue)
            .filter(|&i| {
                self.ue_contexts[i].is_schedulable()
                    && (self.ue_contexts[i].buffer_size_bytes > 0
                        || self.ue_contexts[i].get_retx_harq().is_some())
            })
            .collect();

        if schedulable.is_empty() {
            return;
        }

        let prbs_per_ue = (self.total_prbs / schedulable.len()).max(1);

        // Start from the round-robin pointer
        for offset in 0..schedulable.len() {
            let idx = schedulable[(self.rr_index + offset) % schedulable.len()];

            if let Some(grant) = self.try_allocate_ue(idx, prbs_per_ue, prb_map, slot) {
                grants.push(grant);
            }

            if prb_map.free_count() == 0 {
                break;
            }
        }

        self.rr_index = (self.rr_index + 1) % schedulable.len().max(1);
    }

    fn schedule_proportional_fair(
        &mut self,
        prb_map: &mut PrbAllocationMap,
        grants: &mut Vec<SchedGrant>,
        slot: u64,
    ) {
        let n_re_per_prb = self.n_re_per_prb;
        let n_layers = self.n_layers;

        // Compute PF metric for each schedulable UE
        let mut pf_scores: Vec<(usize, f64)> = Vec::new();
        for (i, ue) in self.ue_contexts.iter().enumerate() {
            if !ue.is_schedulable() {
                continue;
            }
            if ue.buffer_size_bytes == 0 && ue.get_retx_harq().is_none() {
                continue;
            }

            // PF metric = achievable_rate / avg_throughput
            let mcs_entry = cqi_to_mcs(ue.cqi).unwrap_or_else(|_| get_cqi_table()[1]);
            let achievable = compute_tbs(1, n_re_per_prb, &mcs_entry, n_layers) as f64;
            let metric = achievable / ue.avg_throughput;
            pf_scores.push((i, metric));
        }

        // Sort by PF metric descending
        pf_scores.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));

        // Allocate PRBs greedily by PF priority
        let prbs_per_ue = if pf_scores.is_empty() {
            0
        } else {
            (self.total_prbs / pf_scores.len()).max(1)
        };

        for (idx, _score) in &pf_scores {
            if prb_map.free_count() == 0 {
                break;
            }
            let alloc = prbs_per_ue.min(prb_map.free_count());
            if let Some(grant) = self.try_allocate_ue(*idx, alloc, prb_map, slot) {
                grants.push(grant);
            }
        }

        // Update avg throughput for all UEs
        let alpha = self.pf_alpha;
        for (i, ue) in self.ue_contexts.iter_mut().enumerate() {
            let bits = grants
                .iter()
                .filter(|g| g.rnti == ue.rnti)
                .map(|g| g.tbs_bits as f64)
                .sum::<f64>();
            ue.update_avg_throughput(bits, alpha);
            let _ = i;
        }
    }

    fn schedule_max_cqi(
        &mut self,
        prb_map: &mut PrbAllocationMap,
        grants: &mut Vec<SchedGrant>,
        slot: u64,
    ) {
        // Sort UEs by CQI descending (max throughput first)
        let mut candidates: Vec<(usize, u8)> = self
            .ue_contexts
            .iter()
            .enumerate()
            .filter(|(_, ue)| {
                ue.is_schedulable()
                    && (ue.buffer_size_bytes > 0 || ue.get_retx_harq().is_some())
            })
            .map(|(i, ue)| (i, ue.cqi))
            .collect();

        candidates.sort_by(|a, b| b.1.cmp(&a.1));

        let prbs_per_ue = if candidates.is_empty() {
            0
        } else {
            (self.total_prbs / candidates.len()).max(1)
        };

        for (idx, _cqi) in &candidates {
            if prb_map.free_count() == 0 {
                break;
            }
            let alloc = prbs_per_ue.min(prb_map.free_count());
            if let Some(grant) = self.try_allocate_ue(*idx, alloc, prb_map, slot) {
                grants.push(grant);
            }
        }
    }

    fn schedule_qos_aware(
        &mut self,
        prb_map: &mut PrbAllocationMap,
        grants: &mut Vec<SchedGrant>,
        slot: u64,
    ) {
        // Sort by QoS priority level (lower = higher priority)
        let mut candidates: Vec<(usize, u8)> = self
            .ue_contexts
            .iter()
            .enumerate()
            .filter(|(_, ue)| {
                ue.is_schedulable()
                    && (ue.buffer_size_bytes > 0 || ue.get_retx_harq().is_some())
            })
            .map(|(i, ue)| (i, ue.qos.priority_level))
            .collect();

        candidates.sort_by(|a, b| a.1.cmp(&b.1)); // Lower priority_level = higher priority

        let prbs_per_ue = if candidates.is_empty() {
            0
        } else {
            (self.total_prbs / candidates.len()).max(1)
        };

        for (idx, _prio) in &candidates {
            if prb_map.free_count() == 0 {
                break;
            }
            let alloc = prbs_per_ue.min(prb_map.free_count());
            if let Some(grant) = self.try_allocate_ue(*idx, alloc, prb_map, slot) {
                grants.push(grant);
            }
        }
    }

    /// Try to allocate PRBs to a UE and create a scheduling grant.
    fn try_allocate_ue(
        &mut self,
        ue_idx: usize,
        max_prbs: usize,
        prb_map: &mut PrbAllocationMap,
        slot: u64,
    ) -> Option<SchedGrant> {
        let ue = &self.ue_contexts[ue_idx];

        // Check for retransmission first
        let (harq_id, is_retx) = if let Some(hid) = ue.get_retx_harq() {
            (hid, true)
        } else if let Some(hid) = ue.get_idle_harq() {
            (hid, false)
        } else {
            return None;
        };

        let mcs_entry = cqi_to_mcs(ue.cqi).ok()?;
        if mcs_entry.modulation_order == 0 {
            return None; // CQI 0 → out of range
        }

        let n_re_per_prb = self.n_re_per_prb;
        let n_layers = self.n_layers;

        // For retransmissions, use the original allocation size
        let prb_count = if is_retx {
            let hp = &ue.harq_processes[harq_id as usize];
            hp.prb_count.min(prb_map.free_count())
        } else {
            max_prbs.min(prb_map.free_count())
        };

        if prb_count == 0 {
            return None;
        }

        let prb_start = prb_map.allocate_contiguous(prb_count)?;
        let tbs = if is_retx {
            self.ue_contexts[ue_idx].harq_processes[harq_id as usize].tbs
        } else {
            compute_tbs(prb_count, n_re_per_prb, &mcs_entry, n_layers)
        };

        let ue = &mut self.ue_contexts[ue_idx];
        let hp = &mut ue.harq_processes[harq_id as usize];

        let (ndi, rv) = if is_retx {
            (hp.ndi, hp.rv)
        } else {
            hp.start_new_tx(tbs, mcs_entry.mcs_index, prb_start, prb_count);
            (hp.ndi, hp.rv)
        };

        // Deduct from buffer
        if !is_retx {
            let tbs_bytes = tbs / 8;
            if ue.buffer_size_bytes >= tbs_bytes as u64 {
                ue.buffer_size_bytes -= tbs_bytes as u64;
            } else {
                ue.buffer_size_bytes = 0;
            }
            ue.total_bytes_scheduled += tbs_bytes as u64;
        }
        ue.last_scheduled_slot = slot;

        Some(SchedGrant {
            rnti: ue.rnti,
            harq_id,
            prb_start,
            prb_count,
            mcs: mcs_entry.mcs_index,
            ndi,
            rv,
            tbs_bits: tbs,
            is_retransmission: is_retx,
        })
    }
}

// ---------------------------------------------------------------------------
// BSR Decoding (TS 38.321 Table 6.1.3.1-1 / 6.1.3.1-2)
// ---------------------------------------------------------------------------

/// Decodes a BSR index (0-63) to buffer size in bytes.
/// Based on TS 38.321 Table 6.1.3.1-1 (Short BSR / Long BSR).
pub fn decode_bsr_index(index: u8) -> u64 {
    // Simplified lookup matching TS 38.321 Table 6.1.3.1-1
    match index {
        0 => 0,
        1 => 10,
        2 => 14,
        3 => 20,
        4 => 28,
        5 => 38,
        6 => 53,
        7 => 74,
        8 => 102,
        9 => 142,
        10 => 198,
        11 => 276,
        12 => 384,
        13 => 535,
        14 => 745,
        15 => 1038,
        16 => 1446,
        17 => 2014,
        18 => 2806,
        19 => 3909,
        20 => 5447,
        21 => 7590,
        22 => 10_576,
        23 => 14_736,
        24 => 20_527,
        25 => 28_600,
        26 => 39_846,
        27 => 55_506,
        28 => 77_330,
        29 => 107_725,
        30 => 150_060,
        31 => 209_053,
        32 => 291_200,
        33 => 405_650,
        34 => 565_120,
        35 => 787_200,
        36 => 1_096_640,
        37 => 1_527_680,
        38 => 2_128_384,
        39 => 2_965_504,
        40 => 4_131_328,
        41 => 5_755_904,
        42 => 8_021_248,
        43 => 11_177_984,
        44 => 15_575_040,
        45 => 21_700_608,
        46 => 30_233_088,
        47 => 42_138_624,
        48 => 58_720_256,
        49 => 81_838_080,
        50 => 114_041_856,
        51 => 158_894_080,
        52 => 221_394_944,
        53 => 308_524_032,
        54 => 429_837_312,
        55 => 598_931_456,
        56 => 834_609_152,
        57 => 1_162_932_224,
        58 => 1_620_508_672,
        59 => 2_258_463_744,
        60 => 3_147_481_088,
        61 => 4_386_251_776,
        62 => 6_112_006_144,
        63 => 8_516_386_816,
        _ => 8_516_386_816, // Saturate
    }
}

// ---------------------------------------------------------------------------
// Binary Wire Framing & CRC-16
// ---------------------------------------------------------------------------

/// Wire frame PDU for scheduling grants.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MacSchedWirePdu {
    pub magic: u32,
    pub slot_idx: u64,
    pub num_grants: u8,
    pub payload: Vec<u8>,
    pub crc16: u16,
}

/// Computes CRC-16 CCITT.
pub fn compute_crc16(data: &[u8]) -> u16 {
    let mut crc: u16 = 0xFFFF;
    for &byte in data {
        crc ^= (byte as u16) << 8;
        for _ in 0..8 {
            if (crc & 0x8000) != 0 {
                crc = (crc << 1) ^ CRC16_POLY;
            } else {
                crc <<= 1;
            }
        }
    }
    crc
}

impl MacSchedWirePdu {
    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(16 + self.payload.len());
        buf.extend_from_slice(&self.magic.to_be_bytes());
        buf.extend_from_slice(&self.slot_idx.to_be_bytes());
        buf.push(self.num_grants);
        buf.extend_from_slice(&(self.payload.len() as u16).to_be_bytes());
        buf.extend_from_slice(&self.payload);

        let crc = compute_crc16(&buf);
        buf.extend_from_slice(&crc.to_be_bytes());
        buf
    }

    pub fn deserialize(data: &[u8]) -> Result<Self, MacSchedError> {
        if data.len() < 15 {
            return Err(MacSchedError::DeserializationError("Buffer too small".into()));
        }

        let magic = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
        if magic != MAC_SCHED_WIRE_MAGIC {
            return Err(MacSchedError::DeserializationError(format!(
                "Invalid magic: 0x{:08X}", magic
            )));
        }

        let slot_idx = u64::from_be_bytes([
            data[4], data[5], data[6], data[7],
            data[8], data[9], data[10], data[11],
        ]);
        let num_grants = data[12];
        let payload_len = u16::from_be_bytes([data[13], data[14]]) as usize;

        if data.len() < 15 + payload_len + 2 {
            return Err(MacSchedError::DeserializationError("Truncated payload".into()));
        }

        let payload = data[15..15 + payload_len].to_vec();
        let expected_crc = compute_crc16(&data[..15 + payload_len]);
        let rx_crc = u16::from_be_bytes([data[15 + payload_len], data[15 + payload_len + 1]]);

        if rx_crc != expected_crc {
            return Err(MacSchedError::DeserializationError(format!(
                "CRC mismatch: expected 0x{:04X}, got 0x{:04X}", expected_crc, rx_crc
            )));
        }

        Ok(Self {
            magic,
            slot_idx,
            num_grants,
            payload,
            crc16: rx_crc,
        })
    }
}
