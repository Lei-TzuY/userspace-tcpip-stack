//! 3GPP Release 18 (5G-Advanced) Sidelink Dynamic HARQ Feedback & Groupcast Adaptation Engine.
//!
//! Standards Reference:
//! - 3GPP TS 38.213 Rel-18 §16.2 / §16.5: "Sidelink HARQ-ACK reporting on PSFCH and PUCCH"
//! - 3GPP TS 38.214 Rel-18 §8.4: "Physical Sidelink Feedback Channel (PSFCH) procedures"
//! - 3GPP TS 38.321 Rel-18 §5.22: "MAC procedures - SL HARQ process management, Discontinuous Transmission (DTX) detection, and PSFCH transmission"
//! - 3GPP TS 38.211 Rel-18 §8.3: "Physical sidelink feedback channel format 0"
//! - 3GPP TS 38.331 Rel-18: "Sidelink RRC configuration (SL-PSFCH-Config, SL-BWP-Config)"
//!
//! Pure standard Rust (`std` / `core` only) with zero external dependencies.

use std::collections::HashMap;
use std::fmt;

// ============================================================================
// 1. Error Types
// ============================================================================

/// Errors encountered in 3GPP Rel-18 Sidelink HARQ operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SlHarqError {
    /// Subchannel index exceeds configured bandwidth part.
    InvalidSubchannel { subchannel: u16, max_allowed: u16 },
    /// Slot index is invalid or in the past.
    InvalidSlot(u32),
    /// PRB index is outside PSFCH resource set.
    InvalidPrbIndex { prb: u16, max_allowed: u16 },
    /// HARQ process ID not found or already closed.
    ProcessNotFound(u8),
    /// Maximum retransmissions reached for this process.
    MaxRetransmissionsReached { process_id: u8, max_retransmissions: u8 },
    /// Power control computation error.
    PowerControlError(String),
    /// Invalid geographic Zone ID or coordinate.
    InvalidZoneConfiguration(String),
    /// Codebook multiplexing buffer overflow.
    CodebookOverflow(String),
}

impl fmt::Display for SlHarqError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SlHarqError::InvalidSubchannel { subchannel, max_allowed } => {
                write!(
                    f,
                    "Invalid subchannel index {subchannel} (max configured: {max_allowed})"
                )
            }
            SlHarqError::InvalidSlot(slot) => write!(f, "Invalid sidelink slot: {slot}"),
            SlHarqError::InvalidPrbIndex { prb, max_allowed } => {
                write!(f, "PRB index {prb} exceeds PSFCH PRB set size {max_allowed}")
            }
            SlHarqError::ProcessNotFound(pid) => {
                write!(f, "Sidelink HARQ process {pid} not found or inactive")
            }
            SlHarqError::MaxRetransmissionsReached { process_id, max_retransmissions } => {
                write!(
                    f,
                    "Process {process_id} reached maximum retransmission limit ({max_retransmissions})"
                )
            }
            SlHarqError::PowerControlError(msg) => write!(f, "PSFCH power control error: {msg}"),
            SlHarqError::InvalidZoneConfiguration(msg) => {
                write!(f, "Invalid zone configuration: {msg}")
            }
            SlHarqError::CodebookOverflow(msg) => {
                write!(f, "SL HARQ codebook multiplexing overflow: {msg}")
            }
        }
    }
}

// ============================================================================
// 2. Core Configurations & Enumerations
// ============================================================================

/// Sidelink communication cast type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlCastType {
    Unicast,
    Groupcast,
    Broadcast,
}

/// Sidelink HARQ feedback mode for Groupcast (3GPP TS 38.214 §8.4.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlHarqFeedbackScheme {
    /// Groupcast Option 1: Distance-based NACK-only feedback.
    Option1DistanceBasedNack,
    /// Groupcast Option 2: Individual ACK/NACK feedback from each group member.
    Option2AckNack,
    /// HARQ feedback is disabled.
    Disabled,
}

/// Feedback report state on PSFCH (TS 38.213 §16.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PsfchFeedbackReport {
    /// Positive Acknowledgment.
    Ack,
    /// Negative Acknowledgment.
    Nack,
    /// Discontinuous Transmission (no PSFCH energy detected).
    Dtx,
}

/// Standard Redundancy Version sequence for NR HARQ (3GPP TS 38.214).
pub const NR_HARQ_RV_SEQUENCE: [u8; 4] = [0, 2, 3, 1];

/// Geographic 2D Zone ID for Groupcast Option 1 distance evaluation (TS 38.214 §8.4.2).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct SlZoneId {
    /// Zone X index (0..=127 per 3GPP modular grid).
    pub x: u8,
    /// Zone Y index (0..=127 per 3GPP modular grid).
    pub y: u8,
    /// Zone grid length $L$ in meters (e.g. 20.0 m).
    pub length_m: f64,
    /// Zone grid width $W$ in meters (e.g. 20.0 m).
    pub width_m: f64,
}

impl SlZoneId {
    pub fn new(x: u8, y: u8, length_m: f64, width_m: f64) -> Result<Self, SlHarqError> {
        if x > 127 || y > 127 {
            return Err(SlHarqError::InvalidZoneConfiguration(format!(
                "Zone coordinate out of range 0..127: ({x}, {y})"
            )));
        }
        if length_m <= 0.0 || width_m <= 0.0 {
            return Err(SlHarqError::InvalidZoneConfiguration(
                "Zone dimensions must be strictly positive".to_string(),
            ));
        }
        Ok(Self {
            x,
            y,
            length_m,
            width_m,
        })
    }

    /// Calculate Euclidean distance between two geographic zones in meters.
    pub fn distance_to(&self, other: &SlZoneId) -> f64 {
        let dx = (self.x as f64 - other.x as f64) * self.length_m;
        let dy = (self.y as f64 - other.y as f64) * self.width_m;
        (dx * dx + dy * dy).sqrt()
    }
}

// ============================================================================
// 3. PSFCH Format 0 Resource Mapper (TS 38.213 §16.2 / TS 38.211 §8.3)
// ============================================================================

/// PSFCH Format 0 transmission occasion and physical resource specification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PsfchFormat0Resource {
    pub slot_idx: u32,
    pub prb_idx: u16,
    pub cyclic_shift_idx: u8, // 0..11
}

/// Configuration for PSFCH resource pool in Sidelink BWP.
#[derive(Debug, Clone, PartialEq)]
pub struct PsfchResourceConfig {
    /// PSFCH periodicity in slots: $N_{\text{PSSCH}}^{\text{PSFCH}} \in \{1, 2, 4\}$.
    pub period_slots: u8,
    /// Minimum processing delay $\Delta$ from PSSCH end to PSFCH occasion in slots (typically 2 or 3).
    pub min_proc_delay_slots: u8,
    /// Starting PRB of PSFCH resource set in the BWP.
    pub start_prb: u16,
    /// Number of PRBs allocated for PSFCH in each PSFCH slot.
    pub num_prbs: u16,
    /// Number of subchannels in the Sidelink resource pool.
    pub num_subchannels: u16,
    /// Cyclic shift pairs supported per PRB for Option 2 / Unicast (typically 6: (0,6), (1,7), etc.).
    pub num_cyclic_shift_pairs: u8,
}

impl PsfchResourceConfig {
    pub fn new(
        period_slots: u8,
        min_proc_delay_slots: u8,
        start_prb: u16,
        num_prbs: u16,
        num_subchannels: u16,
    ) -> Result<Self, SlHarqError> {
        if period_slots != 1 && period_slots != 2 && period_slots != 4 {
            return Err(SlHarqError::PowerControlError(format!(
                "Invalid PSFCH period: {period_slots} (must be 1, 2, or 4 slots)"
            )));
        }
        if num_prbs == 0 || num_subchannels == 0 {
            return Err(SlHarqError::PowerControlError(
                "PSFCH PRBs and subchannels must be non-zero".to_string(),
            ));
        }
        Ok(Self {
            period_slots,
            min_proc_delay_slots,
            start_prb,
            num_prbs,
            num_subchannels,
            num_cyclic_shift_pairs: 6,
        })
    }
}

/// Computes PSFCH Format 0 physical time/frequency/cyclic-shift allocations.
#[derive(Debug)]
pub struct PsfchResourceMapper {
    pub config: PsfchResourceConfig,
}

impl PsfchResourceMapper {
    pub fn new(config: PsfchResourceConfig) -> Self {
        Self { config }
    }

    /// Map PSSCH transmission slot to the associated PSFCH slot (TS 38.213 §16.2).
    ///
    /// Finds the earliest slot $m \ge k + \Delta$ such that $(m \bmod \text{period}) == 0$.
    pub fn map_pssch_to_psfch_slot(&self, pssch_slot: u32) -> u32 {
        let earliest_slot = pssch_slot + (self.config.min_proc_delay_slots as u32);
        let period = self.config.period_slots as u32;
        let rem = earliest_slot % period;
        if rem == 0 {
            earliest_slot
        } else {
            earliest_slot + (period - rem)
        }
    }

    /// Map PSSCH subchannel and member index to PSFCH PRB and cyclic shift.
    ///
    /// - For Groupcast Option 1: cyclic shift is fixed to 0 for NACK.
    /// - For Groupcast Option 2 / Unicast: member index $j$ determines PRB offset and CS pair $(m_{\text{cs}}, m_{\text{cs}}+6)$.
    pub fn map_resource(
        &self,
        pssch_slot: u32,
        subchannel_idx: u16,
        member_idx: u8,
        scheme: SlHarqFeedbackScheme,
        feedback: PsfchFeedbackReport,
    ) -> Result<PsfchFormat0Resource, SlHarqError> {
        if subchannel_idx >= self.config.num_subchannels {
            return Err(SlHarqError::InvalidSubchannel {
                subchannel: subchannel_idx,
                max_allowed: self.config.num_subchannels - 1,
            });
        }

        let slot_idx = self.map_pssch_to_psfch_slot(pssch_slot);

        match scheme {
            SlHarqFeedbackScheme::Option1DistanceBasedNack => {
                // Groupcast Option 1: all NACKs in subchannel share the same PRB and CS=0
                let prb_offset = subchannel_idx % self.config.num_prbs;
                let prb_idx = self.config.start_prb + prb_offset;
                Ok(PsfchFormat0Resource {
                    slot_idx,
                    prb_idx,
                    cyclic_shift_idx: 0,
                })
            }
            SlHarqFeedbackScheme::Option2AckNack | SlHarqFeedbackScheme::Disabled => {
                // Option 2 / Unicast: multiplexed by member ID
                let m = member_idx as u16;
                let prb_stride = self.config.num_subchannels;
                let prb_offset = (subchannel_idx + m * prb_stride) % self.config.num_prbs;
                let prb_idx = self.config.start_prb + prb_offset;

                let cs_pair_idx = (member_idx / (self.config.num_prbs / prb_stride).max(1) as u8)
                    % self.config.num_cyclic_shift_pairs;
                let base_cs = cs_pair_idx * 2; // e.g. 0, 2, 4, 6, 8, 10
                let cs = match feedback {
                    PsfchFeedbackReport::Ack => (base_cs + 6) % 12,
                    PsfchFeedbackReport::Nack => base_cs % 12,
                    PsfchFeedbackReport::Dtx => 0,
                };

                Ok(PsfchFormat0Resource {
                    slot_idx,
                    prb_idx,
                    cyclic_shift_idx: cs,
                })
            }
        }
    }
}

// ============================================================================
// 4. Distance-Based Feedback Evaluator (Groupcast Option 1)
// ============================================================================

/// Evaluates Groupcast Option 1 distance-based NACK-only feedback.
#[derive(Debug, Default)]
pub struct DistanceBasedFeedbackEvaluator;

impl DistanceBasedFeedbackEvaluator {
    pub fn new() -> Self {
        Self
    }

    /// Evaluates whether receiving UE should transmit NACK on PSFCH (TS 38.214 §8.4.2).
    ///
    /// Returns:
    /// - `Some(PsfchFeedbackReport::Nack)` if decoding failed AND distance $\le$ MCR.
    /// - `None` if decoding succeeded (no feedback) OR distance > MCR (out-of-range).
    pub fn evaluate_feedback(
        &self,
        tx_zone: &SlZoneId,
        rx_zone: &SlZoneId,
        min_comm_range_m: f64,
        decoding_success: bool,
    ) -> Option<PsfchFeedbackReport> {
        if decoding_success {
            // Option 1 is NACK-only: successful reception transmits nothing
            return None;
        }

        let distance = tx_zone.distance_to(rx_zone);
        if distance <= min_comm_range_m {
            // Within required communication range and decoding failed -> Send NACK
            Some(PsfchFeedbackReport::Nack)
        } else {
            // Outside communication range requirement -> Suppress NACK to save channel resources
            None
        }
    }
}

// ============================================================================
// 5. Dynamic Groupcast Option 1 vs Option 2 Adapter (Rel-18)
// ============================================================================

/// Configuration parameters for dynamic groupcast mode adaptation.
#[derive(Debug, Clone, PartialEq)]
pub struct DynamicGroupcastConfig {
    /// Channel Busy Ratio (CBR) threshold above which Option 1 is enforced (e.g. 0.60).
    pub cbr_congestion_threshold: f64,
    /// Maximum group member count for Option 2 (e.g. 8). Groups larger than this use Option 1.
    pub max_group_size_for_option2: usize,
    /// Strict latency budget in milliseconds below which Option 2 is prioritized (e.g. 20.0 ms).
    pub ultra_low_latency_budget_ms: f64,
}

impl Default for DynamicGroupcastConfig {
    fn default() -> Self {
        Self {
            cbr_congestion_threshold: 0.65,
            max_group_size_for_option2: 8,
            ultra_low_latency_budget_ms: 20.0,
        }
    }
}

/// Dynamically chooses between Option 1 (NACK-only) and Option 2 (ACK/NACK)
/// based on channel congestion, group size, and QoS latency budgets.
#[derive(Debug, Clone)]
pub struct DynamicGroupcastAdapter {
    pub config: DynamicGroupcastConfig,
}

impl DynamicGroupcastAdapter {
    pub fn new(config: DynamicGroupcastConfig) -> Self {
        Self { config }
    }

    /// Select optimal feedback scheme for a given sidelink group transmission occasion.
    pub fn select_scheme(
        &self,
        group_size: usize,
        measured_cbr: f64,
        latency_budget_ms: f64,
    ) -> SlHarqFeedbackScheme {
        // High channel congestion: Option 1 drastically reduces PSFCH channel load
        if measured_cbr >= self.config.cbr_congestion_threshold {
            return SlHarqFeedbackScheme::Option1DistanceBasedNack;
        }

        // Large group sizes: Option 2 causes PSFCH collisions and feedback storms
        if group_size > self.config.max_group_size_for_option2 {
            return SlHarqFeedbackScheme::Option1DistanceBasedNack;
        }

        // Small tight groups with strict latency requirements (e.g. platooning):
        // Option 2 provides explicit ACK confirmation and immediate retransmissions
        if latency_budget_ms <= self.config.ultra_low_latency_budget_ms {
            return SlHarqFeedbackScheme::Option2AckNack;
        }

        // Default for modest sized groups in uncongested channels
        SlHarqFeedbackScheme::Option2AckNack
    }
}

// ============================================================================
// 6. Sidelink HARQ Codebook Multiplexing (TS 38.213 §16.5)
// ============================================================================

/// Type of Sidelink HARQ-ACK codebook multiplexing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlCodebookType {
    /// Type-1 semi-static codebook (all configured SL occasions).
    Type1SemiStatic,
    /// Type-2 dynamic codebook (based on Downlink Assignment Indicator / DAI).
    Type2Dynamic,
}

/// Sidelink HARQ Codebook generator for reporting SL HARQ-ACK to gNB on PUCCH (Mode 1).
#[derive(Debug, Default)]
pub struct SidelinkHarqCodebookGenerator;

impl SidelinkHarqCodebookGenerator {
    pub fn new() -> Self {
        Self
    }

    /// Generates Type-1 Semi-Static HARQ Codebook bitmap for $N$ candidate occasions.
    pub fn generate_type1_codebook(
        &self,
        occasions: &[Option<PsfchFeedbackReport>],
    ) -> Vec<bool> {
        let mut bits = Vec::with_capacity(occasions.len());
        for occ in occasions {
            match occ {
                Some(PsfchFeedbackReport::Ack) => bits.push(true),
                Some(PsfchFeedbackReport::Nack) | Some(PsfchFeedbackReport::Dtx) | None => {
                    bits.push(false);
                }
            }
        }
        bits
    }

    /// Generates Type-2 Dynamic HARQ Codebook for scheduled sidelink grants.
    pub fn generate_type2_codebook(
        &self,
        scheduled_reports: &[(u8, PsfchFeedbackReport)], // (dai, feedback)
    ) -> Vec<bool> {
        let mut sorted = scheduled_reports.to_vec();
        sorted.sort_by_key(|&(dai, _)| dai);

        let mut bits = Vec::with_capacity(sorted.len());
        for &(_, fb) in &sorted {
            bits.push(fb == PsfchFeedbackReport::Ack);
        }
        bits
    }
}

// ============================================================================
// 7. PSFCH Transmit Power Control & Priority Preemption (TS 38.213 §16.2.4)
// ============================================================================

/// PSFCH Transmit Power Controller.
#[derive(Debug, Clone, PartialEq)]
pub struct PsfchPowerConfig {
    /// Nominal power $P_{\text{O\_PSFCH}}$ in dBm (typically -80 to -50 dBm).
    pub p0_psfch_dbm: f64,
    /// Pathloss compensation factor $\alpha_{\text{PSFCH}} \in [0.0, 1.0]$.
    pub alpha_psfch: f64,
    /// Maximum UE transmit power $P_{\text{CMAX}}$ in dBm (e.g. 23.0 dBm).
    pub pcmax_dbm: f64,
}

impl Default for PsfchPowerConfig {
    fn default() -> Self {
        Self {
            p0_psfch_dbm: -75.0,
            alpha_psfch: 0.8,
            pcmax_dbm: 23.0,
        }
    }
}

/// A pending PSFCH transmission candidate for power and priority arbitration.
#[derive(Debug, Clone, PartialEq)]
pub struct PsfchTxCandidate {
    pub candidate_id: u32,
    pub pppp_priority: u8, // 0..7 (0 = highest priority per 3GPP TS 23.287)
    pub resource: PsfchFormat0Resource,
    pub estimated_pathloss_db: f64,
}

/// Computes open-loop transmit power and arbitrates simultaneous PSFCH conflicts.
#[derive(Debug)]
pub struct PsfchPowerController {
    pub config: PsfchPowerConfig,
}

impl PsfchPowerController {
    pub fn new(config: PsfchPowerConfig) -> Self {
        Self { config }
    }

    /// Calculate transmit power for a single PSFCH Format 0 transmission.
    ///
    /// $P_{\text{PSFCH}} = \min(P_{\text{CMAX}}, P_{\text{O\_PSFCH}} + \alpha_{\text{PSFCH}} \cdot PL_{\text{SL}})$
    pub fn calculate_power(&self, pathloss_db: f64) -> f64 {
        let open_loop = self.config.p0_psfch_dbm + self.config.alpha_psfch * pathloss_db;
        open_loop.min(self.config.pcmax_dbm)
    }

    /// Resolve simultaneous PSFCH transmissions within the same slot.
    ///
    /// When total linear power exceeds $P_{\text{CMAX}}$, drops lower priority candidates (higher PPPP value).
    pub fn arbitrate_candidates(
        &self,
        candidates: &[PsfchTxCandidate],
    ) -> (Vec<PsfchTxCandidate>, Vec<u32>) {
        if candidates.is_empty() {
            return (Vec::new(), Vec::new());
        }

        // Sort by priority ascending (PPPP 0 is highest priority)
        let mut sorted = candidates.to_vec();
        sorted.sort_by_key(|c| c.pppp_priority);

        let p_max_linear = 10.0_f64.powf(self.config.pcmax_dbm / 10.0);
        let mut current_power_linear = 0.0_f64;

        let mut approved = Vec::new();
        let mut dropped_ids = Vec::new();

        for cand in sorted {
            let p_dbm = self.calculate_power(cand.estimated_pathloss_db);
            let p_linear = 10.0_f64.powf(p_dbm / 10.0);

            if current_power_linear + p_linear <= p_max_linear || approved.is_empty() {
                current_power_linear += p_linear;
                approved.push(cand);
            } else {
                dropped_ids.push(cand.candidate_id);
            }
        }

        (approved, dropped_ids)
    }
}

// ============================================================================
// 8. Sidelink HARQ Process Entity & Buffer State Machine (TS 38.321 §5.22)
// ============================================================================

/// State of a single Sidelink HARQ process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlHarqState {
    Idle,
    WaitingForPsfch,
    RetransmissionPending,
    Delivered,
    Failed,
}

/// Sidelink HARQ Process Entity.
#[derive(Debug, Clone)]
pub struct SlHarqProcess {
    pub process_id: u8,
    pub state: SlHarqState,
    pub max_retransmissions: u8,
    pub transmission_count: u8,
    pub rv_index: usize,
    pub expected_psfch_slot: u32,
    pub pppp_priority: u8,
}

impl SlHarqProcess {
    pub fn new(process_id: u8, max_retransmissions: u8, pppp_priority: u8) -> Self {
        Self {
            process_id,
            state: SlHarqState::Idle,
            max_retransmissions,
            transmission_count: 0,
            rv_index: 0,
            expected_psfch_slot: 0,
            pppp_priority,
        }
    }

    /// Trigger initial transmission.
    pub fn start_transmission(&mut self, psfch_slot: u32) {
        self.state = SlHarqState::WaitingForPsfch;
        self.transmission_count = 1;
        self.rv_index = 0;
        self.expected_psfch_slot = psfch_slot;
    }

    /// Handle received PSFCH feedback report.
    pub fn handle_feedback(&mut self, feedback: PsfchFeedbackReport) -> Result<(), SlHarqError> {
        match feedback {
            PsfchFeedbackReport::Ack => {
                self.state = SlHarqState::Delivered;
                Ok(())
            }
            PsfchFeedbackReport::Nack | PsfchFeedbackReport::Dtx => {
                if self.transmission_count >= self.max_retransmissions {
                    self.state = SlHarqState::Failed;
                    Err(SlHarqError::MaxRetransmissionsReached {
                        process_id: self.process_id,
                        max_retransmissions: self.max_retransmissions,
                    })
                } else {
                    self.state = SlHarqState::RetransmissionPending;
                    self.rv_index = (self.rv_index + 1) % NR_HARQ_RV_SEQUENCE.len();
                    Ok(())
                }
            }
        }
    }

    /// Schedule retransmission on granted slot.
    pub fn retransmit(&mut self, next_psfch_slot: u32) {
        self.state = SlHarqState::WaitingForPsfch;
        self.transmission_count += 1;
        self.expected_psfch_slot = next_psfch_slot;
    }

    /// Returns current redundancy version value (0, 2, 3, or 1).
    pub fn current_rv(&self) -> u8 {
        NR_HARQ_RV_SEQUENCE[self.rv_index]
    }
}

// ============================================================================
// 9. End-to-End Sidelink HARQ Engine Coordinator & Metrics
// ============================================================================

/// Performance telemetry metrics for the Sidelink HARQ engine.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SlHarqMetrics {
    pub total_transmissions: u64,
    pub total_retransmissions: u64,
    pub acks_received: u64,
    pub nacks_received: u64,
    pub dtx_detected: u64,
    pub option1_transmissions: u64,
    pub option2_transmissions: u64,
    pub psfch_dropped_by_power: u64,
}

/// Central Sidelink HARQ Engine Coordinator.
#[derive(Debug)]
pub struct SidelinkHarqEngine {
    pub resource_mapper: PsfchResourceMapper,
    pub distance_evaluator: DistanceBasedFeedbackEvaluator,
    pub dynamic_adapter: DynamicGroupcastAdapter,
    pub codebook_generator: SidelinkHarqCodebookGenerator,
    pub power_controller: PsfchPowerController,
    pub processes: HashMap<u8, SlHarqProcess>,
    pub metrics: SlHarqMetrics,
}

impl SidelinkHarqEngine {
    pub fn new(
        resource_config: PsfchResourceConfig,
        power_config: PsfchPowerConfig,
        groupcast_config: DynamicGroupcastConfig,
    ) -> Self {
        Self {
            resource_mapper: PsfchResourceMapper::new(resource_config),
            distance_evaluator: DistanceBasedFeedbackEvaluator::new(),
            dynamic_adapter: DynamicGroupcastAdapter::new(groupcast_config),
            codebook_generator: SidelinkHarqCodebookGenerator::new(),
            power_controller: PsfchPowerController::new(power_config),
            processes: HashMap::new(),
            metrics: SlHarqMetrics::default(),
        }
    }

    /// Register a new HARQ process.
    pub fn register_process(
        &mut self,
        process_id: u8,
        max_retransmissions: u8,
        pppp_priority: u8,
    ) {
        self.processes.insert(
            process_id,
            SlHarqProcess::new(process_id, max_retransmissions, pppp_priority),
        );
    }

    /// Initiate sidelink transmission on a process.
    pub fn transmit_tb(
        &mut self,
        process_id: u8,
        pssch_slot: u32,
    ) -> Result<u32, SlHarqError> {
        let psfch_slot = self.resource_mapper.map_pssch_to_psfch_slot(pssch_slot);
        let proc = self
            .processes
            .get_mut(&process_id)
            .ok_or(SlHarqError::ProcessNotFound(process_id))?;

        proc.start_transmission(psfch_slot);
        self.metrics.total_transmissions += 1;
        Ok(psfch_slot)
    }

    /// Process incoming feedback for a process.
    pub fn receive_feedback(
        &mut self,
        process_id: u8,
        feedback: PsfchFeedbackReport,
    ) -> Result<(), SlHarqError> {
        match feedback {
            PsfchFeedbackReport::Ack => self.metrics.acks_received += 1,
            PsfchFeedbackReport::Nack => self.metrics.nacks_received += 1,
            PsfchFeedbackReport::Dtx => self.metrics.dtx_detected += 1,
        }

        let proc = self
            .processes
            .get_mut(&process_id)
            .ok_or(SlHarqError::ProcessNotFound(process_id))?;

        proc.handle_feedback(feedback)
    }
}
