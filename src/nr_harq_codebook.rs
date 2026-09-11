// 3GPP Rel-18/19 NR HARQ-ACK Codebook Construction & Dynamic Feedback
// Multiplexing Engine
//
// Implements TS 38.213 §9.1 HARQ-ACK codebook assembly, covering:
//   - Type-1 (semi-static) and Type-2 (dynamic) codebook generation
//   - Downlink Assignment Index (DAI) counter/total tracking
//   - Sub-slot based HARQ-ACK feedback for URLLC
//   - Multi-TRP (mTRP) sub-codebook splitting per TS 38.213 §9.1.5
//   - SPS HARQ-ACK and PDSCH release handling
//   - PUCCH resource selection based on codebook size
//   - One-shot HARQ-ACK for Rel-18 multi-cell scheduling
//   - MAC CE HARQ-ACK bitmap serialization per TS 38.321
//
// Zero external dependencies — pure standard Rust.

use std::fmt;

// ─── Constants ───────────────────────────────────────────────────────

/// Maximum number of HARQ processes per DL serving cell (TS 38.214 §5.1).
pub const MAX_HARQ_PROCESSES_PER_CELL: usize = 16;

/// Maximum number of configured DL serving cells (carrier aggregation).
pub const MAX_DL_SERVING_CELLS: usize = 32;

/// Maximum number of PDSCH reception occasions per slot per cell.
pub const MAX_PDSCH_PER_SLOT: usize = 8;

/// Maximum number of transport blocks per PDSCH for a given TRP.
pub const MAX_TB_PER_PDSCH: usize = 2;

/// Maximum number of TRPs for mTRP codebook (TS 38.213 §9.1.5).
pub const MAX_TRPS: usize = 2;

/// Maximum sub-slot count within a slot (for URLLC sub-slot feedback).
pub const MAX_SUB_SLOTS: usize = 7;

/// Number of OFDM symbols per slot in NR.
pub const NR_SYMBOLS_PER_SLOT: usize = 14;

/// Maximum DAI counter value before wrapping (2-bit counter, TS 38.213 Table 9.1.3-1).
pub const DAI_COUNTER_MODULO: u8 = 4;

/// Maximum number of SPS configurations per serving cell (Rel-18).
pub const MAX_SPS_CONFIGS_PER_CELL: usize = 8;

/// Maximum codebook size in bits for PUCCH Format 0/1 resource selection.
pub const PUCCH_FORMAT_01_MAX_BITS: usize = 2;

/// PUCCH Format 2 maximum payload bits.
pub const PUCCH_FORMAT_2_MAX_BITS: usize = 1706;

/// PUCCH Format 3 maximum payload bits.
pub const PUCCH_FORMAT_3_MAX_BITS: usize = 1706;

/// PUCCH Format 4 maximum payload bits.
pub const PUCCH_FORMAT_4_MAX_BITS: usize = 1706;

// ─── Enumerations ────────────────────────────────────────────────────

/// HARQ-ACK codebook type per TS 38.213 §9.1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CodebookType {
    /// Type-1: Semi-static codebook with fixed size based on configured
    /// PDSCH reception occasions (TS 38.213 §9.1.2).
    Type1SemiStatic,
    /// Type-2: Dynamic codebook whose size is determined by the total DAI
    /// field in DCI (TS 38.213 §9.1.3).
    Type2Dynamic,
    /// Type-3: Enhanced dynamic codebook for multi-TRP with sub-codebook
    /// splitting (TS 38.213 §9.1.5, Rel-17/18).
    Type3MultiTrp,
}

/// HARQ-ACK feedback value for a single transport block.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HarqAckBit {
    /// Positive acknowledgement — TB decoded correctly.
    Ack,
    /// Negative acknowledgement — TB decoding failure.
    Nack,
    /// DTX — no PDSCH detected / scheduling occasion missed.
    Dtx,
}

impl HarqAckBit {
    /// Convert to binary bit for codebook insertion.
    /// ACK=1, NACK/DTX=0 per TS 38.213 §9.1.
    pub fn to_bit(self) -> u8 {
        match self {
            HarqAckBit::Ack => 1,
            HarqAckBit::Nack | HarqAckBit::Dtx => 0,
        }
    }
}

/// PUCCH format for HARQ-ACK transmission.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PucchFormat {
    /// Format 0 — short PUCCH, 1-2 bits (sequence-based).
    Format0,
    /// Format 1 — long PUCCH, 1-2 bits (sequence-based).
    Format1,
    /// Format 2 — short PUCCH, >2 bits (coded).
    Format2,
    /// Format 3 — long PUCCH without OCC multiplexing.
    Format3,
    /// Format 4 — long PUCCH with OCC multiplexing.
    Format4,
}

/// PDSCH scheduling type indicating how PDSCH is scheduled.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PdschSchedulingType {
    /// Dynamically scheduled by DCI Format 1_0 or 1_1.
    Dynamic,
    /// Semi-persistent scheduling (SPS) activation.
    SpsActivation,
    /// Semi-persistent scheduling release.
    SpsRelease,
}

/// Sub-slot configuration for URLLC sub-slot HARQ feedback.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SubSlotConfig {
    /// No sub-slot — standard slot-level feedback.
    NoSubSlot,
    /// 2 sub-slots per slot (7 symbols each).
    TwoSubSlots,
    /// 7 sub-slots per slot (2 symbols each).
    SevenSubSlots,
}

impl SubSlotConfig {
    /// Number of sub-slots within a single slot.
    pub fn sub_slots_per_slot(self) -> usize {
        match self {
            SubSlotConfig::NoSubSlot => 1,
            SubSlotConfig::TwoSubSlots => 2,
            SubSlotConfig::SevenSubSlots => 7,
        }
    }

    /// Number of symbols per sub-slot.
    pub fn symbols_per_sub_slot(self) -> usize {
        NR_SYMBOLS_PER_SLOT / self.sub_slots_per_slot()
    }
}

/// TRP index for multi-TRP codebook partitioning.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TrpIndex {
    /// Primary TRP (CORESETPoolIndex = 0).
    Trp0,
    /// Secondary TRP (CORESETPoolIndex = 1).
    Trp1,
}

impl TrpIndex {
    pub fn as_usize(self) -> usize {
        match self {
            TrpIndex::Trp0 => 0,
            TrpIndex::Trp1 => 1,
        }
    }
}

/// Priority level for HARQ-ACK multiplexing (Rel-17+ priority indicator).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum HarqPriority {
    /// Low priority (e.g., eMBB).
    Low,
    /// High priority (e.g., URLLC).
    High,
}

// ─── Core Structures ─────────────────────────────────────────────────

/// Downlink Assignment Index (DAI) tracking per TS 38.213 §9.1.3.
///
/// For Type-2 dynamic codebook, the counter DAI and total DAI fields in
/// DCI are used to determine codebook size and detect missed DCI.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DaiTracker {
    /// Counter DAI value (V_DAI_DL_counter), 2-bit modulo-4 counter.
    pub counter_dai: u8,
    /// Total DAI value (V_DAI_DL_total), indicates total number of
    /// PDSCH assignments in the HARQ-ACK reporting window.
    pub total_dai: u8,
    /// Serving cell index associated with this DAI.
    pub cell_id: u8,
    /// Slot index in which the DCI was received.
    pub slot_index: u16,
}

impl DaiTracker {
    pub fn new(cell_id: u8) -> Self {
        Self {
            counter_dai: 0,
            total_dai: 0,
            cell_id,
            slot_index: 0,
        }
    }

    /// Advance the counter DAI (modulo 4).
    pub fn increment_counter(&mut self) {
        self.counter_dai = (self.counter_dai + 1) % DAI_COUNTER_MODULO;
    }

    /// Update total DAI from the DCI total-DAI field.
    pub fn update_total(&mut self, total: u8) {
        self.total_dai = total % DAI_COUNTER_MODULO;
    }

    /// Detect whether a DCI was missed based on counter/total mismatch.
    /// Returns the number of expected PDSCH assignments.
    pub fn expected_assignments(&self) -> u8 {
        // total_dai encodes the total number of assignments modulo 4.
        // When counter_dai != total_dai, intermediate DCIs were missed.
        self.total_dai
    }
}

/// A single PDSCH reception occasion for codebook construction.
#[derive(Debug, Clone)]
pub struct PdschOccasion {
    /// Serving cell index.
    pub cell_id: u8,
    /// Slot index.
    pub slot_index: u16,
    /// Sub-slot index within the slot (0 if no sub-slot).
    pub sub_slot_index: u8,
    /// HARQ process ID.
    pub harq_process_id: u8,
    /// Number of transport blocks (1 or 2).
    pub num_tb: u8,
    /// HARQ-ACK bits for each TB.
    pub ack_bits: [HarqAckBit; MAX_TB_PER_PDSCH],
    /// Scheduling type.
    pub scheduling_type: PdschSchedulingType,
    /// TRP index for mTRP (None for single-TRP).
    pub trp_index: Option<TrpIndex>,
    /// Priority level.
    pub priority: HarqPriority,
    /// Counter DAI value from DCI (for Type-2 codebook).
    pub counter_dai: u8,
    /// Total DAI value from DCI (for Type-2 codebook).
    pub total_dai: u8,
    /// SPS configuration index (for SPS occasions).
    pub sps_config_index: Option<u8>,
}

impl PdschOccasion {
    /// Create a new dynamically scheduled PDSCH occasion.
    pub fn new_dynamic(
        cell_id: u8,
        slot_index: u16,
        harq_process_id: u8,
        num_tb: u8,
    ) -> Self {
        Self {
            cell_id,
            slot_index,
            sub_slot_index: 0,
            harq_process_id,
            num_tb: num_tb.min(MAX_TB_PER_PDSCH as u8),
            ack_bits: [HarqAckBit::Dtx; MAX_TB_PER_PDSCH],
            scheduling_type: PdschSchedulingType::Dynamic,
            trp_index: None,
            priority: HarqPriority::Low,
            counter_dai: 0,
            total_dai: 0,
            sps_config_index: None,
        }
    }

    /// Create an SPS PDSCH occasion.
    pub fn new_sps(
        cell_id: u8,
        slot_index: u16,
        harq_process_id: u8,
        sps_config_index: u8,
    ) -> Self {
        Self {
            cell_id,
            slot_index,
            sub_slot_index: 0,
            harq_process_id,
            num_tb: 1,
            ack_bits: [HarqAckBit::Dtx; MAX_TB_PER_PDSCH],
            scheduling_type: PdschSchedulingType::SpsActivation,
            trp_index: None,
            priority: HarqPriority::Low,
            counter_dai: 0,
            total_dai: 0,
            sps_config_index: Some(sps_config_index),
        }
    }

    /// Set HARQ-ACK for a specific TB index.
    pub fn set_ack(&mut self, tb_index: usize, value: HarqAckBit) {
        if tb_index < self.num_tb as usize && tb_index < MAX_TB_PER_PDSCH {
            self.ack_bits[tb_index] = value;
        }
    }
}

/// Type-1 semi-static codebook configuration.
///
/// Defines the fixed structure of PDSCH reception occasions per cell/slot
/// combination, as configured by RRC.
#[derive(Debug, Clone)]
pub struct Type1Config {
    /// Number of configured DL serving cells.
    pub num_cells: u8,
    /// Maximum number of PDSCH occasions per slot per cell.
    pub max_pdsch_per_slot_per_cell: u8,
    /// Maximum number of TBs per PDSCH.
    pub max_tb_per_pdsch: u8,
    /// Sub-slot configuration.
    pub sub_slot_config: SubSlotConfig,
    /// Number of DL slots in the monitoring window.
    pub monitoring_window_slots: u16,
}

impl Type1Config {
    /// Calculate the total codebook size in bits.
    pub fn codebook_size(&self) -> usize {
        let cells = self.num_cells as usize;
        let pdsch_per_slot = self.max_pdsch_per_slot_per_cell as usize;
        let tb = self.max_tb_per_pdsch as usize;
        let sub_slots = self.sub_slot_config.sub_slots_per_slot();
        let slots = self.monitoring_window_slots as usize;

        cells * slots * sub_slots * pdsch_per_slot * tb
    }
}

/// Type-2 dynamic codebook configuration.
#[derive(Debug, Clone)]
pub struct Type2Config {
    /// Number of configured DL serving cells.
    pub num_cells: u8,
    /// Maximum number of TBs per PDSCH.
    pub max_tb_per_pdsch: u8,
    /// Sub-slot configuration for URLLC.
    pub sub_slot_config: SubSlotConfig,
    /// Whether to enable one-shot HARQ-ACK for multi-cell (Rel-18).
    pub one_shot_enabled: bool,
}

/// Multi-TRP codebook configuration (Type-3 / TS 38.213 §9.1.5).
#[derive(Debug, Clone)]
pub struct MultiTrpConfig {
    /// Whether to use separate sub-codebooks per TRP.
    pub separate_sub_codebooks: bool,
    /// Number of TBs per PDSCH per TRP.
    pub max_tb_per_pdsch: u8,
    /// HARQ-ACK mode for mTRP.
    pub harq_ack_mode: MultiTrpHarqAckMode,
}

/// HARQ-ACK feedback mode for multi-TRP.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MultiTrpHarqAckMode {
    /// Joint HARQ-ACK: single ACK/NACK per TB across both TRPs.
    Joint,
    /// Separate HARQ-ACK: independent ACK/NACK per TRP per TB.
    Separate,
}

// ─── Error Type ──────────────────────────────────────────────────────

/// Errors from HARQ-ACK codebook construction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HarqCodebookError {
    /// Cell ID exceeds the maximum configured cells.
    CellIdOutOfRange { cell_id: u8, max_cells: u8 },
    /// Too many PDSCH occasions in the codebook window.
    OccasionOverflow { count: usize, max: usize },
    /// DAI mismatch detected — possible missed DCI.
    DaiMismatch {
        cell_id: u8,
        expected: u8,
        received: u8,
    },
    /// Sub-slot index out of range for the configured sub-slot config.
    SubSlotOutOfRange { index: u8, max: u8 },
    /// TRP index required but not provided for multi-TRP config.
    MissingTrpIndex,
    /// Codebook exceeds maximum PUCCH payload capacity.
    CodebookTooLarge { bits: usize, max_bits: usize },
    /// No PDSCH occasions in the codebook — nothing to report.
    EmptyCodebook,
    /// Invalid configuration parameter.
    InvalidConfig(String),
}

impl fmt::Display for HarqCodebookError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CellIdOutOfRange { cell_id, max_cells } => {
                write!(f, "cell_id {} exceeds max {}", cell_id, max_cells)
            }
            Self::OccasionOverflow { count, max } => {
                write!(f, "occasion count {} exceeds max {}", count, max)
            }
            Self::DaiMismatch { cell_id, expected, received } => {
                write!(
                    f,
                    "DAI mismatch on cell {}: expected {} got {}",
                    cell_id, expected, received
                )
            }
            Self::SubSlotOutOfRange { index, max } => {
                write!(f, "sub-slot {} exceeds max {}", index, max)
            }
            Self::MissingTrpIndex => write!(f, "TRP index required for mTRP codebook"),
            Self::CodebookTooLarge { bits, max_bits } => {
                write!(f, "codebook {} bits exceeds PUCCH max {}", bits, max_bits)
            }
            Self::EmptyCodebook => write!(f, "no PDSCH occasions in codebook"),
            Self::InvalidConfig(msg) => write!(f, "invalid config: {}", msg),
        }
    }
}

// ─── Codebook Assembly Result ────────────────────────────────────────

/// Assembled HARQ-ACK codebook ready for transmission.
#[derive(Debug, Clone)]
pub struct AssembledCodebook {
    /// The codebook bit vector (ACK=1, NACK/DTX=0).
    pub bits: Vec<u8>,
    /// Total number of valid bits in the codebook.
    pub num_bits: usize,
    /// Codebook type used.
    pub codebook_type: CodebookType,
    /// Selected PUCCH format for transmission.
    pub pucch_format: PucchFormat,
    /// Number of PDSCH occasions contributing to this codebook.
    pub num_occasions: usize,
    /// Whether any DTX (missed detection) was included.
    pub contains_dtx: bool,
    /// Priority level of the codebook.
    pub priority: HarqPriority,
    /// Sub-codebooks for mTRP (one per TRP), None for single-TRP.
    pub trp_sub_codebooks: Option<[Vec<u8>; MAX_TRPS]>,
}

impl AssembledCodebook {
    /// Check if the entire codebook is all-NACK (no ACK).
    pub fn is_all_nack(&self) -> bool {
        self.bits.iter().all(|&b| b == 0)
    }

    /// Count the number of ACK bits.
    pub fn ack_count(&self) -> usize {
        self.bits.iter().filter(|&&b| b == 1).count()
    }

    /// Count the number of NACK/DTX bits.
    pub fn nack_count(&self) -> usize {
        self.bits.iter().filter(|&&b| b == 0).count()
    }
}

/// PUCCH resource selection result.
#[derive(Debug, Clone)]
pub struct PucchResourceSelection {
    /// Selected PUCCH format.
    pub format: PucchFormat,
    /// PUCCH resource index within the format's resource set.
    pub resource_index: u8,
    /// Number of HARQ-ACK bits that the selected PUCCH can carry.
    pub max_payload_bits: usize,
    /// Number of PRBs allocated for the PUCCH resource.
    pub num_prbs: u8,
    /// Starting symbol for the PUCCH resource.
    pub start_symbol: u8,
    /// Number of symbols for the PUCCH resource.
    pub num_symbols: u8,
}

// ─── MAC CE Serializer ───────────────────────────────────────────────

/// HARQ-ACK bitmap MAC CE structure per TS 38.321 §6.1.3.
#[derive(Debug, Clone)]
pub struct HarqAckMacCe {
    /// Logical Channel ID for the MAC CE.
    pub lcid: u8,
    /// Serialized bitmap payload.
    pub payload: Vec<u8>,
    /// Number of valid bits in the payload.
    pub num_ack_bits: usize,
}

impl HarqAckMacCe {
    /// MAC CE LCID for HARQ-ACK feedback (TS 38.321 Table 6.2.1-1b).
    pub const LCID_HARQ_ACK: u8 = 60;

    /// Serialize an assembled codebook into a MAC CE payload.
    pub fn from_codebook(codebook: &AssembledCodebook) -> Self {
        let num_bytes = (codebook.num_bits + 7) / 8;
        let mut payload = vec![0u8; num_bytes];

        for (i, &bit) in codebook.bits.iter().enumerate().take(codebook.num_bits) {
            if bit != 0 {
                let byte_idx = i / 8;
                let bit_idx = 7 - (i % 8); // MSB first
                if byte_idx < payload.len() {
                    payload[byte_idx] |= 1 << bit_idx;
                }
            }
        }

        Self {
            lcid: Self::LCID_HARQ_ACK,
            payload,
            num_ack_bits: codebook.num_bits,
        }
    }

    /// Serialize to wire bytes: [LCID, length, payload...].
    pub fn serialize(&self) -> Vec<u8> {
        let payload_len = self.payload.len();
        let mut buf = Vec::with_capacity(2 + payload_len);
        buf.push(self.lcid);
        // Variable-length encoding: if <255 bytes, 1-byte length
        if payload_len < 255 {
            buf.push(payload_len as u8);
        } else {
            buf.push(0xFF);
            buf.push((payload_len >> 8) as u8);
            buf.push((payload_len & 0xFF) as u8);
        }
        buf.extend_from_slice(&self.payload);
        buf
    }

    /// Deserialize from wire bytes, returning the MAC CE and bytes consumed.
    pub fn deserialize(data: &[u8]) -> Result<(Self, usize), HarqCodebookError> {
        if data.len() < 2 {
            return Err(HarqCodebookError::InvalidConfig(
                "MAC CE too short".to_string(),
            ));
        }

        let lcid = data[0];
        let (payload_len, header_len) = if data[1] == 0xFF {
            if data.len() < 4 {
                return Err(HarqCodebookError::InvalidConfig(
                    "extended length header truncated".to_string(),
                ));
            }
            let len = ((data[2] as usize) << 8) | (data[3] as usize);
            (len, 4)
        } else {
            (data[1] as usize, 2)
        };

        if data.len() < header_len + payload_len {
            return Err(HarqCodebookError::InvalidConfig(
                "MAC CE payload truncated".to_string(),
            ));
        }

        let payload = data[header_len..header_len + payload_len].to_vec();
        let num_ack_bits = payload_len * 8;

        Ok((
            Self {
                lcid,
                payload,
                num_ack_bits,
            },
            header_len + payload_len,
        ))
    }
}

// ─── Codebook Telemetry ──────────────────────────────────────────────

/// Telemetry for HARQ-ACK codebook construction and feedback.
#[derive(Debug, Clone, Default)]
pub struct CodebookTelemetry {
    /// Total number of codebooks assembled.
    pub codebooks_assembled: u64,
    /// Total ACK bits reported.
    pub total_ack_bits: u64,
    /// Total NACK bits reported.
    pub total_nack_bits: u64,
    /// Total DTX entries (missed PDSCH).
    pub total_dtx_entries: u64,
    /// Number of DAI mismatches detected.
    pub dai_mismatches: u64,
    /// Number of Type-1 codebooks.
    pub type1_count: u64,
    /// Number of Type-2 codebooks.
    pub type2_count: u64,
    /// Number of Type-3 (mTRP) codebooks.
    pub type3_count: u64,
    /// Number of SPS release HARQ-ACKs.
    pub sps_release_acks: u64,
    /// Number of sub-slot codebooks.
    pub sub_slot_codebooks: u64,
    /// PUCCH Format 0/1 selections.
    pub pucch_f01_selections: u64,
    /// PUCCH Format 2/3/4 selections.
    pub pucch_f234_selections: u64,
    /// Codebook bit-error-rate estimate (NACK / total).
    pub estimated_bler: f64,
}

impl CodebookTelemetry {
    pub fn reset(&mut self) {
        *self = Self::default();
    }

    /// Update BLER estimate based on cumulative counts.
    pub fn update_bler(&mut self) {
        let total = self.total_ack_bits + self.total_nack_bits;
        if total > 0 {
            self.estimated_bler = self.total_nack_bits as f64 / total as f64;
        }
    }
}

// ─── HARQ-ACK Codebook Engine ────────────────────────────────────────

/// The main HARQ-ACK codebook construction engine.
///
/// Collects PDSCH occasions, applies DAI tracking, and assembles
/// codebooks according to the configured codebook type.
#[derive(Debug)]
pub struct HarqCodebookEngine {
    /// Codebook type configuration.
    codebook_type: CodebookType,
    /// Type-1 configuration (if applicable).
    type1_config: Option<Type1Config>,
    /// Type-2 configuration (if applicable).
    type2_config: Option<Type2Config>,
    /// Multi-TRP configuration (if applicable).
    mtrp_config: Option<MultiTrpConfig>,
    /// Accumulated PDSCH occasions in current reporting window.
    occasions: Vec<PdschOccasion>,
    /// Per-cell DAI trackers.
    dai_trackers: Vec<DaiTracker>,
    /// Number of configured DL serving cells.
    num_cells: u8,
    /// Telemetry.
    telemetry: CodebookTelemetry,
}

impl HarqCodebookEngine {
    /// Create a new engine with Type-1 semi-static codebook.
    pub fn new_type1(config: Type1Config) -> Result<Self, HarqCodebookError> {
        if config.num_cells == 0 || config.num_cells as usize > MAX_DL_SERVING_CELLS {
            return Err(HarqCodebookError::InvalidConfig(format!(
                "num_cells {} out of range [1..{}]",
                config.num_cells, MAX_DL_SERVING_CELLS
            )));
        }
        if config.max_tb_per_pdsch == 0 || config.max_tb_per_pdsch > MAX_TB_PER_PDSCH as u8 {
            return Err(HarqCodebookError::InvalidConfig(format!(
                "max_tb_per_pdsch {} out of range [1..{}]",
                config.max_tb_per_pdsch, MAX_TB_PER_PDSCH
            )));
        }

        let num_cells = config.num_cells;
        let mut dai_trackers = Vec::with_capacity(num_cells as usize);
        for c in 0..num_cells {
            dai_trackers.push(DaiTracker::new(c));
        }

        Ok(Self {
            codebook_type: CodebookType::Type1SemiStatic,
            type1_config: Some(config),
            type2_config: None,
            mtrp_config: None,
            occasions: Vec::new(),
            dai_trackers,
            num_cells,
            telemetry: CodebookTelemetry::default(),
        })
    }

    /// Create a new engine with Type-2 dynamic codebook.
    pub fn new_type2(config: Type2Config) -> Result<Self, HarqCodebookError> {
        if config.num_cells == 0 || config.num_cells as usize > MAX_DL_SERVING_CELLS {
            return Err(HarqCodebookError::InvalidConfig(format!(
                "num_cells {} out of range [1..{}]",
                config.num_cells, MAX_DL_SERVING_CELLS
            )));
        }

        let num_cells = config.num_cells;
        let mut dai_trackers = Vec::with_capacity(num_cells as usize);
        for c in 0..num_cells {
            dai_trackers.push(DaiTracker::new(c));
        }

        Ok(Self {
            codebook_type: CodebookType::Type2Dynamic,
            type1_config: None,
            type2_config: Some(config),
            mtrp_config: None,
            occasions: Vec::new(),
            dai_trackers,
            num_cells,
            telemetry: CodebookTelemetry::default(),
        })
    }

    /// Create a new engine with Type-3 multi-TRP codebook.
    pub fn new_multi_trp(
        type2_config: Type2Config,
        mtrp_config: MultiTrpConfig,
    ) -> Result<Self, HarqCodebookError> {
        if type2_config.num_cells == 0
            || type2_config.num_cells as usize > MAX_DL_SERVING_CELLS
        {
            return Err(HarqCodebookError::InvalidConfig(format!(
                "num_cells {} out of range [1..{}]",
                type2_config.num_cells, MAX_DL_SERVING_CELLS
            )));
        }

        let num_cells = type2_config.num_cells;
        let mut dai_trackers = Vec::with_capacity(num_cells as usize);
        for c in 0..num_cells {
            dai_trackers.push(DaiTracker::new(c));
        }

        Ok(Self {
            codebook_type: CodebookType::Type3MultiTrp,
            type1_config: None,
            type2_config: Some(type2_config),
            mtrp_config: Some(mtrp_config),
            occasions: Vec::new(),
            dai_trackers,
            num_cells,
            telemetry: CodebookTelemetry::default(),
        })
    }

    /// Add a PDSCH reception occasion to the codebook window.
    pub fn add_occasion(
        &mut self,
        occasion: PdschOccasion,
    ) -> Result<(), HarqCodebookError> {
        // Validate cell ID.
        if occasion.cell_id >= self.num_cells {
            return Err(HarqCodebookError::CellIdOutOfRange {
                cell_id: occasion.cell_id,
                max_cells: self.num_cells,
            });
        }

        // Validate sub-slot index.
        let max_sub_slots = self.sub_slot_config().sub_slots_per_slot() as u8;
        if occasion.sub_slot_index >= max_sub_slots {
            return Err(HarqCodebookError::SubSlotOutOfRange {
                index: occasion.sub_slot_index,
                max: max_sub_slots,
            });
        }

        // For mTRP, TRP index is required.
        if self.codebook_type == CodebookType::Type3MultiTrp
            && occasion.trp_index.is_none()
        {
            return Err(HarqCodebookError::MissingTrpIndex);
        }

        // Update DAI tracker for Type-2/Type-3.
        if self.codebook_type != CodebookType::Type1SemiStatic {
            let cell_idx = occasion.cell_id as usize;
            if cell_idx < self.dai_trackers.len() {
                let tracker = &mut self.dai_trackers[cell_idx];
                // Check for DAI mismatch (counter should match sequential order).
                let expected_counter =
                    (tracker.counter_dai + 1) % DAI_COUNTER_MODULO;
                if occasion.counter_dai != expected_counter
                    && !self.occasions.is_empty()
                    && occasion.scheduling_type == PdschSchedulingType::Dynamic
                {
                    self.telemetry.dai_mismatches += 1;
                }
                tracker.counter_dai = occasion.counter_dai;
                tracker.update_total(occasion.total_dai);
                tracker.slot_index = occasion.slot_index;
            }
        }

        // Track SPS releases.
        if occasion.scheduling_type == PdschSchedulingType::SpsRelease {
            self.telemetry.sps_release_acks += 1;
        }

        self.occasions.push(occasion);
        Ok(())
    }

    /// Assemble the HARQ-ACK codebook from collected occasions.
    pub fn assemble(&mut self) -> Result<AssembledCodebook, HarqCodebookError> {
        if self.occasions.is_empty() {
            return Err(HarqCodebookError::EmptyCodebook);
        }

        let result = match self.codebook_type {
            CodebookType::Type1SemiStatic => self.assemble_type1()?,
            CodebookType::Type2Dynamic => self.assemble_type2()?,
            CodebookType::Type3MultiTrp => self.assemble_type3()?,
        };

        // Update telemetry.
        self.telemetry.codebooks_assembled += 1;
        for &bit in &result.bits {
            if bit == 1 {
                self.telemetry.total_ack_bits += 1;
            } else {
                self.telemetry.total_nack_bits += 1;
            }
        }
        if result.contains_dtx {
            self.telemetry.total_dtx_entries += 1;
        }
        match result.codebook_type {
            CodebookType::Type1SemiStatic => self.telemetry.type1_count += 1,
            CodebookType::Type2Dynamic => self.telemetry.type2_count += 1,
            CodebookType::Type3MultiTrp => self.telemetry.type3_count += 1,
        }
        match result.pucch_format {
            PucchFormat::Format0 | PucchFormat::Format1 => {
                self.telemetry.pucch_f01_selections += 1;
            }
            _ => {
                self.telemetry.pucch_f234_selections += 1;
            }
        }
        if self.sub_slot_config() != SubSlotConfig::NoSubSlot {
            self.telemetry.sub_slot_codebooks += 1;
        }
        self.telemetry.update_bler();

        Ok(result)
    }

    /// Clear the codebook window for the next reporting period.
    pub fn clear_window(&mut self) {
        self.occasions.clear();
        for tracker in &mut self.dai_trackers {
            tracker.counter_dai = 0;
            tracker.total_dai = 0;
        }
    }

    /// Get current telemetry snapshot.
    pub fn telemetry(&self) -> &CodebookTelemetry {
        &self.telemetry
    }

    /// Reset telemetry counters.
    pub fn reset_telemetry(&mut self) {
        self.telemetry.reset();
    }

    /// Get the current codebook type.
    pub fn codebook_type(&self) -> CodebookType {
        self.codebook_type
    }

    /// Number of occasions currently in the window.
    pub fn occasion_count(&self) -> usize {
        self.occasions.len()
    }

    // ─── Internal: Type-1 Assembly ───────────────────────────────────

    fn assemble_type1(&self) -> Result<AssembledCodebook, HarqCodebookError> {
        let config = self.type1_config.as_ref().unwrap();
        let codebook_size = config.codebook_size();

        // Pre-allocate with NACK/DTX (0).
        let mut bits = vec![0u8; codebook_size];
        let mut contains_dtx = false;

        // Map each occasion to its fixed position.
        let sub_slots = config.sub_slot_config.sub_slots_per_slot();
        let pdsch_per_slot = config.max_pdsch_per_slot_per_cell as usize;
        let tb_per_pdsch = config.max_tb_per_pdsch as usize;

        // Build a lookup for which occasions we have.
        let mut occasion_map = std::collections::HashMap::new();
        for occ in &self.occasions {
            let key = (occ.cell_id, occ.slot_index, occ.sub_slot_index);
            occasion_map.entry(key).or_insert_with(Vec::new).push(occ);
        }

        // Fill bits for each fixed position.
        for cell in 0..config.num_cells as usize {
            for slot in 0..config.monitoring_window_slots as usize {
                for sub_slot in 0..sub_slots {
                    let key = (cell as u8, slot as u16, sub_slot as u8);
                    let base_idx = ((cell * config.monitoring_window_slots as usize
                        + slot)
                        * sub_slots
                        + sub_slot)
                        * pdsch_per_slot
                        * tb_per_pdsch;

                    if let Some(occs) = occasion_map.get(&key) {
                        for (pdsch_idx, occ) in occs.iter().enumerate() {
                            if pdsch_idx >= pdsch_per_slot {
                                break;
                            }
                            for tb in 0..occ.num_tb.min(tb_per_pdsch as u8) as usize
                            {
                                let bit_idx =
                                    base_idx + pdsch_idx * tb_per_pdsch + tb;
                                if bit_idx < bits.len() {
                                    bits[bit_idx] = occ.ack_bits[tb].to_bit();
                                    if occ.ack_bits[tb] == HarqAckBit::Dtx {
                                        contains_dtx = true;
                                    }
                                }
                            }
                        }
                    } else {
                        // No PDSCH in this position — DTX.
                        contains_dtx = true;
                    }
                }
            }
        }

        let pucch_format = select_pucch_format(codebook_size);

        Ok(AssembledCodebook {
            bits,
            num_bits: codebook_size,
            codebook_type: CodebookType::Type1SemiStatic,
            pucch_format,
            num_occasions: self.occasions.len(),
            contains_dtx,
            priority: self.max_priority(),
            trp_sub_codebooks: None,
        })
    }

    // ─── Internal: Type-2 Assembly ───────────────────────────────────

    fn assemble_type2(&self) -> Result<AssembledCodebook, HarqCodebookError> {
        let config = self.type2_config.as_ref().unwrap();
        let tb_per_pdsch = config.max_tb_per_pdsch as usize;

        // Sort occasions by (cell_id, slot_index, sub_slot_index, counter_dai).
        let mut sorted: Vec<&PdschOccasion> = self.occasions.iter().collect();
        sorted.sort_by(|a, b| {
            a.cell_id
                .cmp(&b.cell_id)
                .then(a.slot_index.cmp(&b.slot_index))
                .then(a.sub_slot_index.cmp(&b.sub_slot_index))
                .then(a.counter_dai.cmp(&b.counter_dai))
        });

        // The codebook size for Type-2 is determined by the total_dai in the
        // last DCI per cell — giving the total number of PDSCH per cell in
        // the window. For simplicity, we use the actual occasion count.
        let mut bits = Vec::new();
        let mut contains_dtx = false;

        for occ in &sorted {
            for tb in 0..occ.num_tb.min(tb_per_pdsch as u8) as usize {
                bits.push(occ.ack_bits[tb].to_bit());
                if occ.ack_bits[tb] == HarqAckBit::Dtx {
                    contains_dtx = true;
                }
            }
            // If 2-TB mode but occasion only has 1 TB, pad with NACK.
            if tb_per_pdsch == 2 && occ.num_tb == 1 {
                bits.push(0); // NACK for missing second TB
            }
        }

        let codebook_size = bits.len();

        // One-shot HARQ-ACK (Rel-18): append additional marker.
        if config.one_shot_enabled && self.num_cells > 1 {
            // In one-shot mode, all cells' HARQ-ACK are concatenated
            // in a single PUCCH transmission. No additional processing
            // is needed beyond what we've already done.
        }

        let pucch_format = select_pucch_format(codebook_size);

        Ok(AssembledCodebook {
            bits,
            num_bits: codebook_size,
            codebook_type: CodebookType::Type2Dynamic,
            pucch_format,
            num_occasions: self.occasions.len(),
            contains_dtx,
            priority: self.max_priority(),
            trp_sub_codebooks: None,
        })
    }

    // ─── Internal: Type-3 mTRP Assembly ──────────────────────────────

    fn assemble_type3(&self) -> Result<AssembledCodebook, HarqCodebookError> {
        let mtrp_config = self.mtrp_config.as_ref().unwrap();
        let tb_per_pdsch = mtrp_config.max_tb_per_pdsch as usize;

        // Separate occasions by TRP.
        let mut trp0_occs: Vec<&PdschOccasion> = Vec::new();
        let mut trp1_occs: Vec<&PdschOccasion> = Vec::new();

        for occ in &self.occasions {
            match occ.trp_index {
                Some(TrpIndex::Trp0) => trp0_occs.push(occ),
                Some(TrpIndex::Trp1) => trp1_occs.push(occ),
                None => return Err(HarqCodebookError::MissingTrpIndex),
            }
        }

        // Sort each TRP's occasions.
        let sort_fn = |a: &&PdschOccasion, b: &&PdschOccasion| {
            a.cell_id
                .cmp(&b.cell_id)
                .then(a.slot_index.cmp(&b.slot_index))
                .then(a.counter_dai.cmp(&b.counter_dai))
        };
        trp0_occs.sort_by(sort_fn);
        trp1_occs.sort_by(sort_fn);

        let mut contains_dtx = false;

        // Build sub-codebook for each TRP.
        let build_sub = |occs: &[&PdschOccasion]| -> Vec<u8> {
            let mut sub_bits = Vec::new();
            for occ in occs {
                for tb in 0..occ.num_tb.min(tb_per_pdsch as u8) as usize {
                    sub_bits.push(occ.ack_bits[tb].to_bit());
                }
                if tb_per_pdsch == 2 && occ.num_tb == 1 {
                    sub_bits.push(0);
                }
            }
            sub_bits
        };

        let sub0 = build_sub(&trp0_occs);
        let sub1 = build_sub(&trp1_occs);

        // Check for DTX in either sub-codebook.
        for occ in self
            .occasions
            .iter()
        {
            for tb in 0..occ.num_tb as usize {
                if occ.ack_bits[tb] == HarqAckBit::Dtx {
                    contains_dtx = true;
                }
            }
        }

        // For Joint mode: combine by AND'ing corresponding TB ACKs.
        // For Separate mode: concatenate sub-codebooks.
        let bits = if mtrp_config.harq_ack_mode == MultiTrpHarqAckMode::Joint {
            // Joint: one ACK per TB, ACK only if both TRPs ACK.
            // Use the longer sub-codebook as reference, pad shorter with 0.
            let max_len = sub0.len().max(sub1.len());
            let mut joint = Vec::with_capacity(max_len);
            for i in 0..max_len {
                let b0 = sub0.get(i).copied().unwrap_or(0);
                let b1 = sub1.get(i).copied().unwrap_or(0);
                joint.push(b0 & b1);
            }
            joint
        } else {
            // Separate: TRP0 sub-codebook followed by TRP1 sub-codebook.
            let mut concat = Vec::with_capacity(sub0.len() + sub1.len());
            concat.extend_from_slice(&sub0);
            concat.extend_from_slice(&sub1);
            concat
        };

        let codebook_size = bits.len();
        let pucch_format = select_pucch_format(codebook_size);

        Ok(AssembledCodebook {
            bits,
            num_bits: codebook_size,
            codebook_type: CodebookType::Type3MultiTrp,
            pucch_format,
            num_occasions: self.occasions.len(),
            contains_dtx,
            priority: self.max_priority(),
            trp_sub_codebooks: if mtrp_config.separate_sub_codebooks {
                Some([sub0, sub1])
            } else {
                None
            },
        })
    }

    // ─── Helpers ─────────────────────────────────────────────────────

    fn sub_slot_config(&self) -> SubSlotConfig {
        if let Some(ref c) = self.type1_config {
            return c.sub_slot_config;
        }
        if let Some(ref c) = self.type2_config {
            return c.sub_slot_config;
        }
        SubSlotConfig::NoSubSlot
    }

    fn max_priority(&self) -> HarqPriority {
        self.occasions
            .iter()
            .map(|o| o.priority)
            .max()
            .unwrap_or(HarqPriority::Low)
    }
}

/// Select PUCCH format based on the codebook size in bits.
pub fn select_pucch_format(num_bits: usize) -> PucchFormat {
    if num_bits <= PUCCH_FORMAT_01_MAX_BITS {
        PucchFormat::Format1
    } else {
        PucchFormat::Format2
    }
}

/// Select PUCCH resource given the codebook size and a resource set list.
pub fn select_pucch_resource(
    num_bits: usize,
    _num_pucch_f0f1_resources: u8,
    _num_pucch_f2f3_resources: u8,
) -> PucchResourceSelection {
    let format = select_pucch_format(num_bits);
    match format {
        PucchFormat::Format0 | PucchFormat::Format1 => PucchResourceSelection {
            format,
            resource_index: 0,
            max_payload_bits: PUCCH_FORMAT_01_MAX_BITS,
            num_prbs: 1,
            start_symbol: 0,
            num_symbols: if format == PucchFormat::Format0 { 2 } else { 14 },
        },
        PucchFormat::Format2 => {
            // For Format 2, determine number of PRBs based on bit count.
            let prbs_needed = ((num_bits + 15) / 16).max(1).min(16) as u8;
            PucchResourceSelection {
                format: PucchFormat::Format2,
                resource_index: 0,
                max_payload_bits: PUCCH_FORMAT_2_MAX_BITS,
                num_prbs: prbs_needed,
                start_symbol: 0,
                num_symbols: 2,
            }
        }
        PucchFormat::Format3 => PucchResourceSelection {
            format: PucchFormat::Format3,
            resource_index: 0,
            max_payload_bits: PUCCH_FORMAT_3_MAX_BITS,
            num_prbs: ((num_bits + 11) / 12).max(1).min(16) as u8,
            start_symbol: 0,
            num_symbols: 14,
        },
        PucchFormat::Format4 => PucchResourceSelection {
            format: PucchFormat::Format4,
            resource_index: 0,
            max_payload_bits: PUCCH_FORMAT_4_MAX_BITS,
            num_prbs: 1,
            start_symbol: 0,
            num_symbols: 14,
        },
    }
}

// ─── Priority Multiplexing ───────────────────────────────────────────

/// Multiplex two codebooks of different priorities onto a single PUCCH.
///
/// Per TS 38.213 §9.2.5.2, when both HP and LP HARQ-ACK are to be
/// reported in the same slot, they are concatenated with HP first.
pub fn multiplex_priority_codebooks(
    high_priority: &AssembledCodebook,
    low_priority: &AssembledCodebook,
) -> AssembledCodebook {
    let mut combined_bits =
        Vec::with_capacity(high_priority.num_bits + low_priority.num_bits);
    combined_bits.extend_from_slice(&high_priority.bits);
    combined_bits.extend_from_slice(&low_priority.bits);

    let total_bits = combined_bits.len();
    let pucch_format = select_pucch_format(total_bits);

    AssembledCodebook {
        bits: combined_bits,
        num_bits: total_bits,
        codebook_type: high_priority.codebook_type,
        pucch_format,
        num_occasions: high_priority.num_occasions + low_priority.num_occasions,
        contains_dtx: high_priority.contains_dtx || low_priority.contains_dtx,
        priority: HarqPriority::High,
        trp_sub_codebooks: None,
    }
}

// ─── One-Shot HARQ-ACK Encoder (Rel-18) ─────────────────────────────

/// Encode a one-shot HARQ-ACK codebook for multi-cell scheduling.
///
/// In Rel-18 multi-cell scheduling, a single DCI can schedule PDSCH on
/// multiple cells. The HARQ-ACK for all co-scheduled cells is reported
/// in a single codebook transmission.
pub fn encode_one_shot_multi_cell(
    occasions_by_cell: &[Vec<PdschOccasion>],
    max_tb_per_pdsch: u8,
) -> Result<AssembledCodebook, HarqCodebookError> {
    if occasions_by_cell.is_empty() {
        return Err(HarqCodebookError::EmptyCodebook);
    }

    let tb_max = max_tb_per_pdsch as usize;
    let mut bits = Vec::new();
    let mut contains_dtx = false;
    let mut total_occasions = 0usize;
    let mut max_prio = HarqPriority::Low;

    for cell_occasions in occasions_by_cell {
        for occ in cell_occasions {
            for tb in 0..occ.num_tb.min(max_tb_per_pdsch) as usize {
                bits.push(occ.ack_bits[tb].to_bit());
                if occ.ack_bits[tb] == HarqAckBit::Dtx {
                    contains_dtx = true;
                }
            }
            if tb_max == 2 && occ.num_tb == 1 {
                bits.push(0);
            }
            total_occasions += 1;
            if occ.priority > max_prio {
                max_prio = occ.priority;
            }
        }
    }

    let num_bits = bits.len();
    let pucch_format = select_pucch_format(num_bits);

    Ok(AssembledCodebook {
        bits,
        num_bits,
        codebook_type: CodebookType::Type2Dynamic,
        pucch_format,
        num_occasions: total_occasions,
        contains_dtx,
        priority: max_prio,
        trp_sub_codebooks: None,
    })
}

// ─── Sub-slot HARQ-ACK grouping ─────────────────────────────────────

/// Group PDSCH occasions by sub-slot for URLLC sub-slot feedback.
///
/// Returns a vector of codebooks, one per sub-slot that has occasions.
pub fn assemble_sub_slot_codebooks(
    occasions: &[PdschOccasion],
    sub_slot_config: SubSlotConfig,
    max_tb: u8,
) -> Vec<AssembledCodebook> {
    let num_sub_slots = sub_slot_config.sub_slots_per_slot();
    let mut sub_slot_groups: Vec<Vec<&PdschOccasion>> =
        vec![Vec::new(); num_sub_slots];

    for occ in occasions {
        let idx = occ.sub_slot_index as usize;
        if idx < num_sub_slots {
            sub_slot_groups[idx].push(occ);
        }
    }

    let tb_max = max_tb as usize;
    let mut codebooks = Vec::new();

    for (_sub_slot_idx, group) in sub_slot_groups.iter().enumerate() {
        if group.is_empty() {
            continue;
        }

        let mut bits = Vec::new();
        let mut contains_dtx = false;

        for occ in group {
            for tb in 0..occ.num_tb.min(max_tb) as usize {
                bits.push(occ.ack_bits[tb].to_bit());
                if occ.ack_bits[tb] == HarqAckBit::Dtx {
                    contains_dtx = true;
                }
            }
            if tb_max == 2 && occ.num_tb == 1 {
                bits.push(0);
            }
        }

        let num_bits = bits.len();
        let pucch_format = select_pucch_format(num_bits);

        codebooks.push(AssembledCodebook {
            bits,
            num_bits,
            codebook_type: CodebookType::Type2Dynamic,
            pucch_format,
            num_occasions: group.len(),
            contains_dtx,
            priority: group
                .iter()
                .map(|o| o.priority)
                .max()
                .unwrap_or(HarqPriority::Low),
            trp_sub_codebooks: None,
        });
    }

    codebooks
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_harq_ack_bit_conversion() {
        assert_eq!(HarqAckBit::Ack.to_bit(), 1);
        assert_eq!(HarqAckBit::Nack.to_bit(), 0);
        assert_eq!(HarqAckBit::Dtx.to_bit(), 0);
    }

    #[test]
    fn test_sub_slot_config() {
        assert_eq!(SubSlotConfig::NoSubSlot.sub_slots_per_slot(), 1);
        assert_eq!(SubSlotConfig::TwoSubSlots.sub_slots_per_slot(), 2);
        assert_eq!(SubSlotConfig::SevenSubSlots.sub_slots_per_slot(), 7);
        assert_eq!(SubSlotConfig::TwoSubSlots.symbols_per_sub_slot(), 7);
        assert_eq!(SubSlotConfig::SevenSubSlots.symbols_per_sub_slot(), 2);
    }

    #[test]
    fn test_dai_tracker() {
        let mut tracker = DaiTracker::new(0);
        assert_eq!(tracker.counter_dai, 0);
        tracker.increment_counter();
        assert_eq!(tracker.counter_dai, 1);
        tracker.increment_counter();
        tracker.increment_counter();
        tracker.increment_counter();
        assert_eq!(tracker.counter_dai, 0); // wraps at 4
    }

    #[test]
    fn test_pucch_format_selection() {
        assert_eq!(select_pucch_format(1), PucchFormat::Format1);
        assert_eq!(select_pucch_format(2), PucchFormat::Format1);
        assert_eq!(select_pucch_format(3), PucchFormat::Format2);
        assert_eq!(select_pucch_format(100), PucchFormat::Format2);
    }

    #[test]
    fn test_mac_ce_roundtrip() {
        let codebook = AssembledCodebook {
            bits: vec![1, 0, 1, 1, 0, 0, 1, 0],
            num_bits: 8,
            codebook_type: CodebookType::Type2Dynamic,
            pucch_format: PucchFormat::Format2,
            num_occasions: 4,
            contains_dtx: false,
            priority: HarqPriority::Low,
            trp_sub_codebooks: None,
        };

        let mac_ce = HarqAckMacCe::from_codebook(&codebook);
        assert_eq!(mac_ce.lcid, HarqAckMacCe::LCID_HARQ_ACK);
        assert_eq!(mac_ce.payload.len(), 1);
        // Bits: 1,0,1,1,0,0,1,0 -> MSB first = 0b10110010 = 0xB2
        assert_eq!(mac_ce.payload[0], 0xB2);

        let wire = mac_ce.serialize();
        let (decoded, consumed) = HarqAckMacCe::deserialize(&wire).unwrap();
        assert_eq!(consumed, wire.len());
        assert_eq!(decoded.payload, mac_ce.payload);
    }
}
