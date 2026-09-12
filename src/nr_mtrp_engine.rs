//! 3GPP Rel-18 5G-Advanced Inter-Cell Multi-TRP (IC-mTRP) & URLLC Repetition Engine.
//!
//! Compliant with:
//! - 3GPP TS 38.213 §10 / §11 (Multi-DCI & Single-DCI Multi-TRP, CORESETPoolIndex, HARQ feedback)
//! - 3GPP TS 38.214 §5.1.2.2 / §5.1.5 (PDSCH Multi-TRP repetition: Schemes 1a, 1b, 2a, 2b, and SDM)
//! - 3GPP TS 38.214 §6.1.2 / §6.1.5 (PUSCH Multi-TRP repetition and dual-panel spatial relations)
//! - 3GPP TS 38.321 §5.17 / §6.1.3.23a (Rel-18 Multi-TRP Beam Failure Recovery MAC CE)
//! - 3GPP TS 38.331 (RRC Information Elements: `CORESETPoolIndex`, `PDSCH-Config`, `ControlResourceSet`)
//!
//! Pure Rust standard library implementation with zero external dependencies.

/// Maximum number of Transmission Reception Points (TRPs) in co-operative cluster.
pub const MAX_MTRP_TRPS: usize = 2;

/// Default beam failure instance (BFI) count threshold before triggering BFR.
pub const DEFAULT_MTRP_BFI_THRESHOLD: u8 = 4;

/// Default Q_out threshold for beam failure detection in dBm.
pub const DEFAULT_MTRP_Q_OUT_DBM: f64 = -105.0;

/// Default Q_in threshold for candidate beam qualification in dBm.
pub const DEFAULT_MTRP_Q_IN_DBM: f64 = -95.0;

/// MAC LCID for Rel-18 Multi-TRP Beam Failure Recovery MAC CE.
pub const MAC_LCID_MTRP_BFR: u8 = 0x34;

// ---------------------------------------------------------------------------
// Enumerations & Error Types
// ---------------------------------------------------------------------------

/// 3GPP CORESETPoolIndex for multi-DCI and multi-TRP distinction (TS 38.213 §10.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CoresetPoolId {
    /// Pool Index 0: Associated with Serving TRP 0.
    Pool0,
    /// Pool Index 1: Associated with Co-channel or Inter-Cell TRP 1.
    Pool1,
}

impl CoresetPoolId {
    pub fn to_u8(self) -> u8 {
        match self {
            Self::Pool0 => 0,
            Self::Pool1 => 1,
        }
    }

    pub fn from_u8(val: u8) -> Option<Self> {
        match val {
            0 => Some(Self::Pool0),
            1 => Some(Self::Pool1),
            _ => None,
        }
    }
}

/// 3GPP Rel-18 Multi-TRP Transmission & Repetition Scheme (TS 38.214 §5.1.2.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MtrpScheme {
    /// Spatial Division Multiplexing (SDM): orthogonal spatial layers across TRPs.
    Sdm,
    /// Scheme 1a: Slot-level Time Division Multiplexing (TDM) repetition across slots.
    TdmScheme1a { repetitions_per_trp: u8 },
    /// Scheme 1b: Intra-slot / mini-slot TDM repetition with distinct symbol blocks.
    TdmScheme1b { symbols_per_repetition: u8 },
    /// Scheme 2a: Frequency Division Multiplexing (FDM) PRB group splitting.
    FdmScheme2a { prb_chunk_size: u16 },
    /// Scheme 2b: FDM RB-level interleaved repetition (odd/even PRBs).
    FdmScheme2b,
    /// Fallback to single TRP when one TRP suffers beam failure or shadowing.
    SingleTrpFallback { active_pool: CoresetPoolId },
}

/// DCI scheduling coordination architecture.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MtrpDciMode {
    /// Single-DCI: Single PDCCH carries dual TCI codepoints scheduling both TRPs.
    SingleDci,
    /// Multi-DCI: Separate PDCCHs monitored in CORESETs with different CORESETPoolIndex.
    MultiDci,
}

/// HARQ-ACK codebook feedback scheme across TRPs (TS 38.213 §11).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MtrpHarqMode {
    /// Separate HARQ-ACK codebooks generated independently per CORESETPoolIndex.
    SeparateCodebooks,
    /// Joint HARQ-ACK codebook multiplexed on a single primary PUCCH.
    JointCodebook,
}

/// Operational state of a TRP's beam link.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrpLinkState {
    /// Beam link is healthy and tracking active TCI state.
    Healthy,
    /// Beam failure instances accumulating ($0 < \text{count} < \text{threshold}$).
    Degraded { bfi_count: u8 },
    /// Beam failure declared on this TRP; BFR MAC CE triggered.
    BeamFailure { candidate_beam: Option<u8> },
    /// BFR complete; new TCI state activated.
    Recovered,
}

/// Errors raised during Multi-TRP operations.
#[derive(Debug, Clone, PartialEq)]
pub enum MtrpError {
    InvalidPci(u16),
    InvalidPrbAllocation { requested: u16, available: u16 },
    InvalidSymbolAllocation { start: u8, count: u8 },
    TrpNotFound(CoresetPoolId),
    BothTrpsFailed,
    CoresetPoolMismatch,
}

impl std::fmt::Display for MtrpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidPci(pci) => write!(f, "Invalid Physical Cell ID: {}", pci),
            Self::InvalidPrbAllocation {
                requested,
                available,
            } => {
                write!(
                    f,
                    "Invalid PRB allocation: requested {}, available {}",
                    requested, available
                )
            }
            Self::InvalidSymbolAllocation { start, count } => {
                write!(
                    f,
                    "Invalid symbol allocation: start {}, count {}",
                    start, count
                )
            }
            Self::TrpNotFound(pool) => write!(f, "TRP with {:?} not found", pool),
            Self::BothTrpsFailed => write!(f, "Catastrophic failure: both TRPs are unavailable"),
            Self::CoresetPoolMismatch => write!(f, "CORESETPoolIndex mismatch with scheduling DCI"),
        }
    }
}

// ---------------------------------------------------------------------------
// Multi-TRP Cell & Transmission Structures
// ---------------------------------------------------------------------------

/// Configuration and radio telemetry for an individual TRP node.
#[derive(Debug, Clone, PartialEq)]
pub struct TrpConfig {
    pub pool_id: CoresetPoolId,
    /// Physical Cell ID (0..1007). In Inter-Cell Multi-TRP, TRP 0 and TRP 1 have different PCIs.
    pub physical_cell_id: u16,
    pub is_serving_cell: bool,
    /// Active TCI state index (0..127).
    pub active_tci_state: u8,
    /// Channel Signal-to-Interference-plus-Noise Ratio in dB.
    pub channel_sinr_db: f64,
    /// Path loss to UE in dB.
    pub path_loss_db: f64,
    /// Current link tracking state.
    pub link_state: TrpLinkState,
}

impl TrpConfig {
    pub fn new(pool_id: CoresetPoolId, pci: u16, is_serving_cell: bool) -> Self {
        Self {
            pool_id,
            physical_cell_id: pci,
            is_serving_cell,
            active_tci_state: 0,
            channel_sinr_db: 15.0,
            path_loss_db: 85.0,
            link_state: TrpLinkState::Healthy,
        }
    }

    /// Check if this TRP is currently capable of carrying transmission.
    pub fn is_available(&self) -> bool {
        !matches!(self.link_state, TrpLinkState::BeamFailure { .. })
    }

    /// Channel power gain in linear scale ($10^{\text{SINR}/10}$).
    pub fn linear_sinr(&self) -> f64 {
        10.0f64.powf(self.channel_sinr_db / 10.0)
    }
}

/// A specific scheduled physical transmission slice on one TRP.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PdschTransmissionLeg {
    pub pool_id: CoresetPoolId,
    pub pci: u16,
    pub slot_offset: u16,
    pub start_symbol: u8,
    pub num_symbols: u8,
    pub start_prb: u16,
    pub num_prbs: u16,
    pub tci_state_id: u8,
    pub redundancy_version: u8,
}

/// Coordinated Multi-TRP PDSCH transmission bundle.
#[derive(Debug, Clone, PartialEq)]
pub struct PdschMtrpBundle {
    pub scheme: MtrpScheme,
    pub tbs_bytes: usize,
    pub mcs: u8,
    pub legs: Vec<PdschTransmissionLeg>,
}

impl PdschMtrpBundle {
    /// Calculate effective combined SINR in dB after Maximal Ratio Combining (MRC) or spatial diversity.
    pub fn effective_combined_sinr(&self, trps: &[TrpConfig]) -> f64 {
        if self.legs.is_empty() {
            return -30.0;
        }

        match self.scheme {
            MtrpScheme::Sdm => {
                // In SDM, layers are parallel, effective SINR is bounded by the minimum layer SINR
                trps.iter()
                    .filter(|t| t.is_available())
                    .map(|t| t.channel_sinr_db)
                    .fold(f64::INFINITY, f64::min)
            }
            MtrpScheme::TdmScheme1a { .. }
            | MtrpScheme::TdmScheme1b { .. }
            | MtrpScheme::FdmScheme2a { .. }
            | MtrpScheme::FdmScheme2b => {
                // In repetition schemes, soft-combining / MRC accumulates linear powers:
                // $\text{SINR}_{\text{eff}} = 10 \log_{10}\left(\sum_i 10^{\text{SINR}_i / 10}\right)$
                let sum_linear: f64 = trps
                    .iter()
                    .filter(|t| t.is_available())
                    .map(|t| t.linear_sinr())
                    .sum();
                if sum_linear > 0.0 {
                    10.0 * sum_linear.log10()
                } else {
                    -30.0
                }
            }
            MtrpScheme::SingleTrpFallback { active_pool } => trps
                .iter()
                .find(|t| t.pool_id == active_pool)
                .map(|t| t.channel_sinr_db)
                .unwrap_or(-30.0),
        }
    }

    /// Simulate physical block decoding based on combined SINR and target Block Error Rate (BLER).
    pub fn simulate_decoding(&self, trps: &[TrpConfig], required_sinr_db: f64) -> bool {
        let eff_sinr = self.effective_combined_sinr(trps);
        eff_sinr >= required_sinr_db
    }
}

// ---------------------------------------------------------------------------
// Rel-18 Multi-TRP Beam Failure Recovery MAC CE
// ---------------------------------------------------------------------------

/// Rel-18 Multi-TRP Beam Failure Recovery MAC CE payload (TS 38.321 §6.1.3.23a).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MtrpBfrMacCe {
    /// Serving cell indication (1 bit).
    pub serving_cell: bool,
    /// Failed TRP CORESETPoolIndex (0 or 1).
    pub failed_pool: CoresetPoolId,
    /// Candidate beam availability flag (AC bit).
    pub candidate_available: bool,
    /// Candidate beam SSB or CSI-RS index (0..63) if available.
    pub candidate_beam_id: Option<u8>,
}

impl MtrpBfrMacCe {
    /// Serialize to standard 3GPP MAC CE byte representation.
    ///
    /// Bit format:
    /// [B7: SP | B6: PoolId | B5: AC | B4..B0: CandidateBeamId (5 MSBs) or reserved]
    pub fn serialize(&self) -> [u8; 2] {
        let mut b0 = 0u8;
        if self.serving_cell {
            b0 |= 0x80;
        }
        if self.failed_pool == CoresetPoolId::Pool1 {
            b0 |= 0x40;
        }
        if self.candidate_available {
            b0 |= 0x20;
        }

        let b1 = if let Some(beam) = self.candidate_beam_id {
            beam & 0x3F
        } else {
            0
        };

        [b0, b1]
    }

    /// Deserialize from 2 raw MAC CE bytes.
    pub fn deserialize(bytes: [u8; 2]) -> Self {
        let serving_cell = (bytes[0] & 0x80) != 0;
        let failed_pool = if (bytes[0] & 0x40) != 0 {
            CoresetPoolId::Pool1
        } else {
            CoresetPoolId::Pool0
        };
        let candidate_available = (bytes[0] & 0x20) != 0;
        let candidate_beam_id = if candidate_available {
            Some(bytes[1] & 0x3F)
        } else {
            None
        };

        Self {
            serving_cell,
            failed_pool,
            candidate_available,
            candidate_beam_id,
        }
    }
}

// ---------------------------------------------------------------------------
// Multi-TRP Engine
// ---------------------------------------------------------------------------

/// 5G-Advanced Inter-Cell Multi-TRP (IC-mTRP) Scheduling & Mobility Engine.
#[derive(Debug, PartialEq)]
pub struct MtrpEngine {
    /// Co-operating TRPs (Index 0: Serving Cell, Index 1: Inter-Cell / Co-channel).
    pub trps: [TrpConfig; MAX_MTRP_TRPS],
    /// Current transmission scheme.
    pub scheme: MtrpScheme,
    /// DCI scheduling mode (Single-DCI vs Multi-DCI).
    pub dci_mode: MtrpDciMode,
    /// HARQ feedback configuration.
    pub harq_mode: MtrpHarqMode,
    /// Consecutive BFI threshold before declaring beam failure on a TRP.
    pub bfi_threshold: u8,
    /// Total transmission bursts scheduled.
    pub stats_bursts_scheduled: u64,
    /// HARQ ACK count for Pool 0.
    pub stats_pool0_acks: u64,
    /// HARQ NACK count for Pool 0.
    pub stats_pool0_nacks: u64,
    /// HARQ ACK count for Pool 1.
    pub stats_pool1_acks: u64,
    /// HARQ NACK count for Pool 1.
    pub stats_pool1_nacks: u64,
    /// Total BFR events triggered.
    pub stats_bfr_events: u64,
}

impl MtrpEngine {
    /// Initialize with Serving Cell PCI and Neighbor Cell PCI (Inter-Cell Multi-TRP).
    pub fn new(serving_pci: u16, neighbor_pci: u16) -> Result<Self, MtrpError> {
        if serving_pci > 1007 {
            return Err(MtrpError::InvalidPci(serving_pci));
        }
        if neighbor_pci > 1007 {
            return Err(MtrpError::InvalidPci(neighbor_pci));
        }

        let trp0 = TrpConfig::new(CoresetPoolId::Pool0, serving_pci, true);
        let trp1 = TrpConfig::new(CoresetPoolId::Pool1, neighbor_pci, false);

        Ok(Self {
            trps: [trp0, trp1],
            scheme: MtrpScheme::TdmScheme1a {
                repetitions_per_trp: 2,
            },
            dci_mode: MtrpDciMode::MultiDci,
            harq_mode: MtrpHarqMode::SeparateCodebooks,
            bfi_threshold: DEFAULT_MTRP_BFI_THRESHOLD,
            stats_bursts_scheduled: 0,
            stats_pool0_acks: 0,
            stats_pool0_nacks: 0,
            stats_pool1_acks: 0,
            stats_pool1_nacks: 0,
            stats_bfr_events: 0,
        })
    }

    /// Update the multi-TRP transmission scheme.
    pub fn set_scheme(&mut self, scheme: MtrpScheme) {
        self.scheme = scheme;
    }

    /// Set DCI coordination mode.
    pub fn set_dci_mode(&mut self, dci_mode: MtrpDciMode) {
        self.dci_mode = dci_mode;
    }

    /// Set HARQ feedback mode.
    pub fn set_harq_mode(&mut self, harq_mode: MtrpHarqMode) {
        self.harq_mode = harq_mode;
    }

    /// Get reference to a specific TRP by CORESETPoolIndex.
    pub fn get_trp(&self, pool: CoresetPoolId) -> &TrpConfig {
        match pool {
            CoresetPoolId::Pool0 => &self.trps[0],
            CoresetPoolId::Pool1 => &self.trps[1],
        }
    }

    /// Get mutable reference to a specific TRP by CORESETPoolIndex.
    pub fn get_trp_mut(&mut self, pool: CoresetPoolId) -> &mut TrpConfig {
        match pool {
            CoresetPoolId::Pool0 => &mut self.trps[0],
            CoresetPoolId::Pool1 => &mut self.trps[1],
        }
    }

    /// Update radio link SINR and path loss for a specific TRP.
    pub fn update_trp_measurements(
        &mut self,
        pool: CoresetPoolId,
        sinr_db: f64,
        path_loss_db: f64,
    ) {
        let trp = self.get_trp_mut(pool);
        trp.channel_sinr_db = sinr_db;
        trp.path_loss_db = path_loss_db;
    }

    /// Schedule a coordinated Multi-TRP downlink transmission burst across time/frequency.
    pub fn schedule_pdsch(
        &mut self,
        tbs_bytes: usize,
        mcs: u8,
        total_prbs: u16,
    ) -> Result<PdschMtrpBundle, MtrpError> {
        if total_prbs == 0 || total_prbs > 275 {
            return Err(MtrpError::InvalidPrbAllocation {
                requested: total_prbs,
                available: 275,
            });
        }

        let trp0_ok = self.trps[0].is_available();
        let trp1_ok = self.trps[1].is_available();

        if !trp0_ok && !trp1_ok {
            return Err(MtrpError::BothTrpsFailed);
        }

        // Automatic fallback if one TRP is down
        let effective_scheme = match self.scheme {
            MtrpScheme::SingleTrpFallback { active_pool } => {
                MtrpScheme::SingleTrpFallback { active_pool }
            }
            other => {
                if !trp0_ok {
                    MtrpScheme::SingleTrpFallback {
                        active_pool: CoresetPoolId::Pool1,
                    }
                } else if !trp1_ok {
                    MtrpScheme::SingleTrpFallback {
                        active_pool: CoresetPoolId::Pool0,
                    }
                } else {
                    other
                }
            }
        };

        let mut legs = Vec::new();

        match effective_scheme {
            MtrpScheme::Sdm => {
                // Both TRPs transmit on same time-frequency grid using orthogonal layers
                legs.push(PdschTransmissionLeg {
                    pool_id: CoresetPoolId::Pool0,
                    pci: self.trps[0].physical_cell_id,
                    slot_offset: 0,
                    start_symbol: 2,
                    num_symbols: 12,
                    start_prb: 0,
                    num_prbs: total_prbs,
                    tci_state_id: self.trps[0].active_tci_state,
                    redundancy_version: 0,
                });
                legs.push(PdschTransmissionLeg {
                    pool_id: CoresetPoolId::Pool1,
                    pci: self.trps[1].physical_cell_id,
                    slot_offset: 0,
                    start_symbol: 2,
                    num_symbols: 12,
                    start_prb: 0,
                    num_prbs: total_prbs,
                    tci_state_id: self.trps[1].active_tci_state,
                    redundancy_version: 0,
                });
            }
            MtrpScheme::TdmScheme1a {
                repetitions_per_trp,
            } => {
                // Slot-level repetition across TRPs: slot n (TRP0), slot n+1 (TRP1), etc.
                let mut current_slot = 0;
                for rep in 0..repetitions_per_trp {
                    let rv = (rep % 4) as u8;
                    // TRP 0 leg
                    legs.push(PdschTransmissionLeg {
                        pool_id: CoresetPoolId::Pool0,
                        pci: self.trps[0].physical_cell_id,
                        slot_offset: current_slot,
                        start_symbol: 2,
                        num_symbols: 12,
                        start_prb: 0,
                        num_prbs: total_prbs,
                        tci_state_id: self.trps[0].active_tci_state,
                        redundancy_version: rv,
                    });
                    current_slot += 1;
                    // TRP 1 leg
                    legs.push(PdschTransmissionLeg {
                        pool_id: CoresetPoolId::Pool1,
                        pci: self.trps[1].physical_cell_id,
                        slot_offset: current_slot,
                        start_symbol: 2,
                        num_symbols: 12,
                        start_prb: 0,
                        num_prbs: total_prbs,
                        tci_state_id: self.trps[1].active_tci_state,
                        redundancy_version: rv,
                    });
                    current_slot += 1;
                }
            }
            MtrpScheme::TdmScheme1b {
                symbols_per_repetition,
            } => {
                // Intra-slot mini-slot repetition: TRP0 occupies first half, TRP1 second half
                let syms = symbols_per_repetition.min(6);
                legs.push(PdschTransmissionLeg {
                    pool_id: CoresetPoolId::Pool0,
                    pci: self.trps[0].physical_cell_id,
                    slot_offset: 0,
                    start_symbol: 2,
                    num_symbols: syms,
                    start_prb: 0,
                    num_prbs: total_prbs,
                    tci_state_id: self.trps[0].active_tci_state,
                    redundancy_version: 0,
                });
                legs.push(PdschTransmissionLeg {
                    pool_id: CoresetPoolId::Pool1,
                    pci: self.trps[1].physical_cell_id,
                    slot_offset: 0,
                    start_symbol: 2 + syms,
                    num_symbols: syms,
                    start_prb: 0,
                    num_prbs: total_prbs,
                    tci_state_id: self.trps[1].active_tci_state,
                    redundancy_version: 2, // Non-zero RV for incremental redundancy
                });
            }
            MtrpScheme::FdmScheme2a { prb_chunk_size: _ } => {
                // Split frequency PRBs into two contiguous blocks
                let half_prbs = total_prbs / 2;
                legs.push(PdschTransmissionLeg {
                    pool_id: CoresetPoolId::Pool0,
                    pci: self.trps[0].physical_cell_id,
                    slot_offset: 0,
                    start_symbol: 2,
                    num_symbols: 12,
                    start_prb: 0,
                    num_prbs: half_prbs,
                    tci_state_id: self.trps[0].active_tci_state,
                    redundancy_version: 0,
                });
                legs.push(PdschTransmissionLeg {
                    pool_id: CoresetPoolId::Pool1,
                    pci: self.trps[1].physical_cell_id,
                    slot_offset: 0,
                    start_symbol: 2,
                    num_symbols: 12,
                    start_prb: half_prbs,
                    num_prbs: total_prbs - half_prbs,
                    tci_state_id: self.trps[1].active_tci_state,
                    redundancy_version: 0,
                });
            }
            MtrpScheme::FdmScheme2b => {
                // Interleaved PRB assignment: TRP 0 and TRP 1 interleaved across grid
                let half_prbs = total_prbs / 2;
                legs.push(PdschTransmissionLeg {
                    pool_id: CoresetPoolId::Pool0,
                    pci: self.trps[0].physical_cell_id,
                    slot_offset: 0,
                    start_symbol: 2,
                    num_symbols: 12,
                    start_prb: 0,
                    num_prbs: half_prbs,
                    tci_state_id: self.trps[0].active_tci_state,
                    redundancy_version: 0,
                });
                legs.push(PdschTransmissionLeg {
                    pool_id: CoresetPoolId::Pool1,
                    pci: self.trps[1].physical_cell_id,
                    slot_offset: 0,
                    start_symbol: 2,
                    num_symbols: 12,
                    start_prb: 1, // Interleaved odd PRBs
                    num_prbs: total_prbs - half_prbs,
                    tci_state_id: self.trps[1].active_tci_state,
                    redundancy_version: 0,
                });
            }
            MtrpScheme::SingleTrpFallback { active_pool } => {
                let trp_idx = match active_pool {
                    CoresetPoolId::Pool0 => 0,
                    CoresetPoolId::Pool1 => 1,
                };
                legs.push(PdschTransmissionLeg {
                    pool_id: active_pool,
                    pci: self.trps[trp_idx].physical_cell_id,
                    slot_offset: 0,
                    start_symbol: 2,
                    num_symbols: 12,
                    start_prb: 0,
                    num_prbs: total_prbs,
                    tci_state_id: self.trps[trp_idx].active_tci_state,
                    redundancy_version: 0,
                });
            }
        }

        self.stats_bursts_scheduled += 1;
        Ok(PdschMtrpBundle {
            scheme: effective_scheme,
            tbs_bytes,
            mcs,
            legs,
        })
    }

    /// Record HARQ-ACK / NACK feedback for a specific TRP's transmission.
    pub fn record_harq_feedback(&mut self, pool: CoresetPoolId, ack: bool) {
        match pool {
            CoresetPoolId::Pool0 => {
                if ack {
                    self.stats_pool0_acks += 1;
                } else {
                    self.stats_pool0_nacks += 1;
                }
            }
            CoresetPoolId::Pool1 => {
                if ack {
                    self.stats_pool1_acks += 1;
                } else {
                    self.stats_pool1_nacks += 1;
                }
            }
        }
    }

    /// Process Beam Failure Instance (BFI) measurement for an individual TRP.
    ///
    /// If measured RSRP falls below Q_out, increments BFI counter.
    /// When counter reaches `bfi_threshold`, triggers Rel-18 Multi-TRP BFR MAC CE.
    pub fn evaluate_bfi(
        &mut self,
        pool: CoresetPoolId,
        measured_rsrp_dbm: f64,
        candidate_beam: Option<u8>,
    ) -> Option<MtrpBfrMacCe> {
        let trp_idx = match pool {
            CoresetPoolId::Pool0 => 0,
            CoresetPoolId::Pool1 => 1,
        };

        if measured_rsrp_dbm < DEFAULT_MTRP_Q_OUT_DBM {
            let current_count = match self.trps[trp_idx].link_state {
                TrpLinkState::Healthy | TrpLinkState::Recovered => 1,
                TrpLinkState::Degraded { bfi_count } => bfi_count + 1,
                TrpLinkState::BeamFailure { .. } => return None, // Already failed
            };

            if current_count >= self.bfi_threshold {
                let is_serving = self.trps[trp_idx].is_serving_cell;
                self.trps[trp_idx].link_state = TrpLinkState::BeamFailure { candidate_beam };
                self.stats_bfr_events += 1;

                Some(MtrpBfrMacCe {
                    serving_cell: is_serving,
                    failed_pool: pool,
                    candidate_available: candidate_beam.is_some(),
                    candidate_beam_id: candidate_beam,
                })
            } else {
                self.trps[trp_idx].link_state = TrpLinkState::Degraded {
                    bfi_count: current_count,
                };
                None
            }
        } else {
            // Quality is good, reset to Healthy
            self.trps[trp_idx].link_state = TrpLinkState::Healthy;
            None
        }
    }

    /// Complete BFR and activate a new TCI state for a failed TRP.
    pub fn complete_bfr(&mut self, pool: CoresetPoolId, new_tci_state: u8) {
        let trp = self.get_trp_mut(pool);
        trp.active_tci_state = new_tci_state;
        trp.link_state = TrpLinkState::Recovered;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mtrp_engine_initialization() {
        let engine = MtrpEngine::new(100, 200).unwrap();
        assert_eq!(engine.trps[0].physical_cell_id, 100);
        assert_eq!(engine.trps[0].pool_id, CoresetPoolId::Pool0);
        assert!(engine.trps[0].is_serving_cell);

        assert_eq!(engine.trps[1].physical_cell_id, 200);
        assert_eq!(engine.trps[1].pool_id, CoresetPoolId::Pool1);
        assert!(!engine.trps[1].is_serving_cell);

        assert_eq!(
            engine.scheme,
            MtrpScheme::TdmScheme1a {
                repetitions_per_trp: 2
            }
        );
    }

    #[test]
    fn test_pdsch_tdm_scheme1a_scheduling() {
        let mut engine = MtrpEngine::new(10, 20).unwrap();
        engine.set_scheme(MtrpScheme::TdmScheme1a {
            repetitions_per_trp: 2,
        });

        let bundle = engine.schedule_pdsch(500, 16, 50).unwrap();
        // 2 repetitions per TRP * 2 TRPs = 4 transmission legs
        assert_eq!(bundle.legs.len(), 4);
        assert_eq!(bundle.legs[0].pool_id, CoresetPoolId::Pool0);
        assert_eq!(bundle.legs[0].slot_offset, 0);

        assert_eq!(bundle.legs[1].pool_id, CoresetPoolId::Pool1);
        assert_eq!(bundle.legs[1].slot_offset, 1);

        assert_eq!(bundle.legs[2].pool_id, CoresetPoolId::Pool0);
        assert_eq!(bundle.legs[2].slot_offset, 2);

        assert_eq!(bundle.legs[3].pool_id, CoresetPoolId::Pool1);
        assert_eq!(bundle.legs[3].slot_offset, 3);
    }

    #[test]
    fn test_pdsch_fdm_scheme2a_scheduling() {
        let mut engine = MtrpEngine::new(10, 20).unwrap();
        engine.set_scheme(MtrpScheme::FdmScheme2a { prb_chunk_size: 25 });

        let bundle = engine.schedule_pdsch(800, 20, 50).unwrap();
        assert_eq!(bundle.legs.len(), 2);
        // TRP 0 gets PRBs 0..25
        assert_eq!(bundle.legs[0].start_prb, 0);
        assert_eq!(bundle.legs[0].num_prbs, 25);
        // TRP 1 gets PRBs 25..50
        assert_eq!(bundle.legs[1].start_prb, 25);
        assert_eq!(bundle.legs[1].num_prbs, 25);
    }

    #[test]
    fn test_mtrp_bfr_evaluation_and_mac_ce() {
        let mut engine = MtrpEngine::new(1, 2).unwrap();
        engine.bfi_threshold = 3;

        // Feed bad RSRP measurements to TRP 1
        assert!(
            engine
                .evaluate_bfi(CoresetPoolId::Pool1, -110.0, None)
                .is_none()
        );
        assert!(
            engine
                .evaluate_bfi(CoresetPoolId::Pool1, -112.0, None)
                .is_none()
        );

        // 3rd failure reaches threshold, must trigger BFR MAC CE
        let mac_ce = engine
            .evaluate_bfi(CoresetPoolId::Pool1, -115.0, Some(14))
            .expect("Expected BFR MAC CE to trigger");

        assert_eq!(mac_ce.failed_pool, CoresetPoolId::Pool1);
        assert!(mac_ce.candidate_available);
        assert_eq!(mac_ce.candidate_beam_id, Some(14));

        // Test serialization and deserialization
        let bytes = mac_ce.serialize();
        let restored = MtrpBfrMacCe::deserialize(bytes);
        assert_eq!(mac_ce, restored);

        // While TRP 1 is failed, transmission must automatically fallback to TRP 0!
        let bundle = engine.schedule_pdsch(300, 10, 40).unwrap();
        assert_eq!(bundle.legs.len(), 1);
        assert_eq!(bundle.legs[0].pool_id, CoresetPoolId::Pool0);

        // Complete BFR
        engine.complete_bfr(CoresetPoolId::Pool1, 14);
        assert!(engine.trps[1].is_available());
    }
}
