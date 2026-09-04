//! 3GPP Release 18 (5G-Advanced) Dynamic Spectrum Sharing (DSS) Phase 2 & Mixed Numerology Scheduling Engine.
//!
//! Standards Reference:
//! - 3GPP TS 38.211 §4.2, §4.3: Numerologies and frame structure
//! - 3GPP TS 38.213 §10: Cross-carrier scheduling, DCI processing with Carrier Indicator Field (CIF)
//! - 3GPP TS 38.214 §5.1.2.1, §5.1.4.3, §6.1.2.1: Mixed numerology DL/UL slot timing (K0, K1, K2), LTE CRS Rate Matching Patterns (RMP)
//! - 3GPP TS 38.300 §5.5, TS 38.331: Carrier Aggregation (CA) and LTE MBSFN subframe allocation.
//!
//! This module implements:
//! 1. 4G LTE Cell-Specific Reference Signal (CRS) Rate Matching Patterns (RMP) for 1-port, 2-port, and 4-port antennas.
//! 2. Cell-specific frequency shift $v_{shift} = N_{ID}^{cell} \pmod 6$ and Resource Element (RE) puncturing bitmap calculation.
//! 3. LTE MBSFN subframe reservation (Phase 2 DSS) providing clean full-slot 5G NR PDSCH transmissions.
//! 4. Cross-Carrier Scheduling (CCS) with 3-bit Carrier Indicator Field (CIF 0..=7).
//! 5. Mixed Numerology Slot Translation ($\mu_{sched} \neq \mu_{target}$) for DL scheduling ($K_0$), UL grant ($K_2$), and HARQ-ACK timing ($K_1$).
//! 6. Multi-carrier PDCCH blind decoding and CCE budget monitoring (TS 38.213 Table 10.1-1).

use std::collections::HashMap;
use std::fmt;

// ---------------------------------------------------------------------------
// Error Types
// ---------------------------------------------------------------------------

/// Errors encountered in DSS and Mixed Numerology Cross-Carrier Scheduling.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DssMixedError {
    InvalidCarrierId(u8),
    InvalidCif(u8),
    InvalidCellId(u16),
    InvalidNumerology(u8),
    InvalidAntennaPortCount(u8),
    CarrierNotFound(u8),
    SchedulingConflict {
        slot: u32,
        reason: String,
    },
    BlindDecodingBudgetExceeded {
        slot: u32,
        limit: u32,
        requested: u32,
    },
}

pub type DssError = DssMixedError;

impl fmt::Display for DssMixedError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DssError::InvalidCarrierId(c) => write!(f, "Invalid Carrier ID: {c} (must be 0..=7)"),
            DssError::InvalidCif(cif) => write!(
                f,
                "Invalid Carrier Indicator Field (CIF): {cif} (must be 0..=7)"
            ),
            DssError::InvalidCellId(id) => write!(f, "Invalid Cell ID: {id} (must be 0..=1007)"),
            DssError::InvalidNumerology(mu) => {
                write!(f, "Invalid numerology mu: {mu} (must be 0..=3)")
            }
            DssError::InvalidAntennaPortCount(p) => {
                write!(
                    f,
                    "Invalid LTE CRS antenna port count: {p} (must be 1, 2, or 4)"
                )
            }
            DssError::CarrierNotFound(c) => {
                write!(f, "Carrier with ID {c} not found in scheduling engine")
            }
            DssError::SchedulingConflict { slot, reason } => {
                write!(
                    f,
                    "Cross-carrier scheduling conflict at slot {slot}: {reason}"
                )
            }
            DssError::BlindDecodingBudgetExceeded {
                slot,
                limit,
                requested,
            } => {
                write!(
                    f,
                    "PDCCH blind decoding budget exceeded at slot {slot}: requested {requested} > limit {limit}"
                )
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Numerology & Carrier Definition (TS 38.211 §4.2)
// ---------------------------------------------------------------------------

/// 5G NR Subcarrier Spacing Numerology ($\mu \in \{0, 1, 2, 3\}$).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CarrierNumerology {
    /// $\mu = 0$: 15 kHz SCS (1 slot per 1 ms subframe, 14 symbols).
    Mu0_15Khz = 0,
    /// $\mu = 1$: 30 kHz SCS (2 slots per 1 ms subframe, 14 symbols).
    Mu1_30Khz = 1,
    /// $\mu = 2$: 60 kHz SCS (4 slots per 1 ms subframe, 14 symbols).
    Mu2_60Khz = 2,
    /// $\mu = 3$: 120 kHz SCS (8 slots per 1 ms subframe, 14 symbols).
    Mu3_120Khz = 3,
}

impl CarrierNumerology {
    pub fn from_u8(val: u8) -> Result<Self, DssError> {
        match val {
            0 => Ok(CarrierNumerology::Mu0_15Khz),
            1 => Ok(CarrierNumerology::Mu1_30Khz),
            2 => Ok(CarrierNumerology::Mu2_60Khz),
            3 => Ok(CarrierNumerology::Mu3_120Khz),
            other => Err(DssError::InvalidNumerology(other)),
        }
    }

    pub fn mu_value(&self) -> u8 {
        *self as u8
    }

    pub fn scs_khz(&self) -> u32 {
        15 * (1 << self.mu_value())
    }

    pub fn slots_per_subframe(&self) -> u32 {
        1 << self.mu_value()
    }

    pub fn slot_duration_us(&self) -> f64 {
        1000.0 / (self.slots_per_subframe() as f64)
    }

    /// Maximum blind decodes per slot for this numerology (TS 38.213 Table 10.1-1).
    pub fn max_blind_decodes_per_slot(&self) -> u32 {
        match self {
            CarrierNumerology::Mu0_15Khz => 44,
            CarrierNumerology::Mu1_30Khz => 36,
            CarrierNumerology::Mu2_60Khz => 22,
            CarrierNumerology::Mu3_120Khz => 20,
        }
    }
}

// ---------------------------------------------------------------------------
// LTE CRS Rate Matching Patterns (TS 38.214 §5.1.4.3)
// ---------------------------------------------------------------------------

/// Number of LTE CRS Antenna Ports (1, 2, or 4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LteCrsAntennaPorts {
    Port1 = 1,
    Port2 = 2,
    Port4 = 4,
}

pub type LteAntennaPorts = LteCrsAntennaPorts;

impl LteCrsAntennaPorts {
    pub fn from_u8(val: u8) -> Result<Self, DssError> {
        match val {
            1 => Ok(LteCrsAntennaPorts::Port1),
            2 => Ok(LteCrsAntennaPorts::Port2),
            4 => Ok(LteCrsAntennaPorts::Port4),
            other => Err(DssError::InvalidAntennaPortCount(other)),
        }
    }

    pub fn port_count(&self) -> u8 {
        *self as u8
    }
}

/// LTE MBSFN Subframe Configuration (TS 36.331 §6.3.2 / TS 38.214).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LteMbsfnConfig {
    pub is_fdd: bool,
    /// 6-bit allocation bitmap for 1 radio frame (bits represent subframes 1, 2, 3, 6, 7, 8 in FDD).
    pub subframe_bitmap: u32,
    /// Number of non-MBSFN control symbols at subframe beginning (typically 1 or 2).
    pub non_mbsfn_symbols: u8,
}

impl LteMbsfnConfig {
    pub fn new_fdd(subframe_bitmap: u32, non_mbsfn_symbols: u8) -> Self {
        LteMbsfnConfig {
            is_fdd: true,
            subframe_bitmap: subframe_bitmap & 0x3F, // 6 bits
            non_mbsfn_symbols: non_mbsfn_symbols.clamp(1, 2),
        }
    }

    /// Check if subframe index (0..9) is configured as MBSFN.
    pub fn is_mbsfn_subframe(&self, subframe: u8) -> bool {
        if self.is_fdd {
            // In FDD, mapping: bit 5->subframe 1, bit 4->2, bit 3->3, bit 2->6, bit 1->7, bit 0->8
            let bit_idx = match subframe {
                1 => Some(5),
                2 => Some(4),
                3 => Some(3),
                6 => Some(2),
                7 => Some(1),
                8 => Some(0),
                _ => None,
            };
            if let Some(shift) = bit_idx {
                ((self.subframe_bitmap >> shift) & 1) != 0
            } else {
                false
            }
        } else {
            // TDD mapping: subframes 3, 4, 7, 8, 9
            let bit_idx = match subframe {
                3 => Some(4),
                4 => Some(3),
                7 => Some(2),
                8 => Some(1),
                9 => Some(0),
                _ => None,
            };
            if let Some(shift) = bit_idx {
                ((self.subframe_bitmap >> shift) & 1) != 0
            } else {
                false
            }
        }
    }
}

/// Resource Element (RE) puncturing mask for 1 PRB (14 OFDM symbols x 12 subcarriers).
/// 0 = usable for 5G PDSCH, 1 = punctured by LTE CRS or PDCCH.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CrsPuncturingMask {
    pub prb_index: u32,
    /// 14 symbols, each with a 12-bit mask representing subcarriers 0..11 (1 = punctured).
    pub symbol_masks: [u16; 14],
    pub punctured_re_count: u32,
    pub usable_re_count: u32,
}

impl CrsPuncturingMask {
    pub fn is_re_usable(&self, symbol: usize, subcarrier: usize) -> bool {
        if symbol < 14 && subcarrier < 12 {
            ((self.symbol_masks[symbol] >> subcarrier) & 1) == 0
        } else {
            false
        }
    }
}

/// LTE CRS Rate Matching Pattern (TS 38.214 §5.1.4.3).
#[derive(Debug, Clone, PartialEq)]
pub struct LteCrsRateMatchingPattern {
    pub carrier_id: u8,
    pub cell_id: u16,
    pub antenna_ports: LteAntennaPorts,
    pub lte_carrier_prbs: u32,
    pub mbsfn_config: Option<LteMbsfnConfig>,
    /// Frequency shift v_shift = Cell_ID mod 6
    pub v_shift: u8,
}

impl LteCrsRateMatchingPattern {
    pub fn new(
        carrier_id: u8,
        cell_id: u16,
        antenna_ports: LteAntennaPorts,
        lte_carrier_prbs: u32,
        mbsfn_config: Option<LteMbsfnConfig>,
    ) -> Result<Self, DssError> {
        if cell_id > 1007 {
            return Err(DssError::InvalidCellId(cell_id));
        }

        let v_shift = (cell_id % 6) as u8;

        Ok(LteCrsRateMatchingPattern {
            carrier_id,
            cell_id,
            antenna_ports,
            lte_carrier_prbs,
            mbsfn_config,
            v_shift,
        })
    }

    /// Compute the RE puncturing mask for a given PRB in a given subframe (0..9).
    pub fn compute_puncturing_mask(&self, prb_index: u32, subframe: u8) -> CrsPuncturingMask {
        let mut symbol_masks = [0u16; 14];
        let mut punctured_count = 0u32;

        let is_mbsfn = self
            .mbsfn_config
            .as_ref()
            .map(|c| c.is_mbsfn_subframe(subframe))
            .unwrap_or(false);

        let non_mbsfn_syms = self
            .mbsfn_config
            .as_ref()
            .map(|c| c.non_mbsfn_symbols as usize)
            .unwrap_or(0);

        let v_shift = self.v_shift as usize;

        // Loop across all 14 OFDM symbols in the slot
        for sym in 0..14 {
            if is_mbsfn && sym >= non_mbsfn_syms {
                // In MBSFN region, LTE CRS is completely absent! Full slot usable.
                continue;
            }

            let mut mask = 0u16;

            // Check if symbol contains CRS (TS 36.211 §6.10.1.2)
            // Port 0/1 CRS on symbols 0, 4, 7, 11
            let is_crs_sym_p01 = sym == 0 || sym == 4 || sym == 7 || sym == 11;
            // Port 2/3 CRS on symbols 1, 8
            let is_crs_sym_p23 =
                (sym == 1 || sym == 8) && self.antenna_ports == LteAntennaPorts::Port4;

            if is_crs_sym_p01 {
                // Staggered by 3 subcarriers between symbol pairs:
                // symbols 0 and 7 have shift v_shift
                // symbols 4 and 11 have shift (v_shift + 3) mod 6
                let shift = if sym == 0 || sym == 7 {
                    v_shift
                } else {
                    (v_shift + 3) % 6
                };

                let k0 = shift % 6;
                let k1 = (shift + 3) % 6;

                // Mark subcarriers across the 12 subcarriers of the PRB
                mask |= 1 << k0;
                mask |= 1 << (k0 + 6);

                if self.antenna_ports != LteAntennaPorts::Port1 {
                    mask |= 1 << k1;
                    mask |= 1 << (k1 + 6);
                }
            } else if is_crs_sym_p23 {
                let shift = v_shift;
                let k0 = shift % 6;
                let k1 = (shift + 3) % 6;

                mask |= 1 << k0;
                mask |= 1 << (k0 + 6);
                mask |= 1 << k1;
                mask |= 1 << (k1 + 6);
            }

            symbol_masks[sym] = mask;
            punctured_count += mask.count_ones();
        }

        let total_res = 14 * 12; // 168
        let usable_count = total_res - punctured_count;

        CrsPuncturingMask {
            prb_index,
            symbol_masks,
            punctured_re_count: punctured_count,
            usable_re_count: usable_count,
        }
    }
}

// ---------------------------------------------------------------------------
// Cross-Carrier Scheduling with Mixed Numerology (TS 38.214)
// ---------------------------------------------------------------------------

/// Configuration for Cross-Carrier Scheduling between two aggregated component carriers.
#[derive(Debug, Clone, PartialEq)]
pub struct CrossCarrierSchedulingConfig {
    pub scheduling_carrier_id: u8,
    pub scheduled_carrier_id: u8,
    /// 3-bit Carrier Indicator Field (CIF 0..=7).
    pub cif: u8,
    pub mu_scheduling: CarrierNumerology,
    pub mu_scheduled: CarrierNumerology,
    /// Default DL slot delay offset K0 (in scheduled cell slot grid).
    pub default_k0: u32,
    /// Default UL grant slot delay offset K2 (in scheduled cell slot grid).
    pub default_k2: u32,
    /// Default HARQ-ACK feedback delay offset K1 (in scheduled cell slot grid).
    pub default_k1: u32,
}

impl CrossCarrierSchedulingConfig {
    pub fn new(
        scheduling_carrier_id: u8,
        scheduled_carrier_id: u8,
        cif: u8,
        mu_scheduling: CarrierNumerology,
        mu_scheduled: CarrierNumerology,
        default_k0: u32,
        default_k2: u32,
        default_k1: u32,
    ) -> Result<Self, DssError> {
        if cif > 7 {
            return Err(DssError::InvalidCif(cif));
        }

        Ok(CrossCarrierSchedulingConfig {
            scheduling_carrier_id,
            scheduled_carrier_id,
            cif,
            mu_scheduling,
            mu_scheduled,
            default_k0,
            default_k2,
            default_k1,
        })
    }
}

/// Result of cross-carrier slot translation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CrossCarrierScheduleResult {
    pub scheduled_carrier_id: u8,
    pub scheduling_slot: u32,
    pub scheduled_slot: u32,
    pub k_offset_applied: u32,
    pub harq_feedback_slot: u32,
}

/// Mixed Numerology Slot Mapper (TS 38.214 §5.1.2.1, §6.1.2.1).
pub struct CrossCarrierSlotMapper;

impl CrossCarrierSlotMapper {
    /// Calculate target DL slot from scheduling cell DCI slot:
    /// n_target = floor(n_sched * 2^(mu_target - mu_sched)) + K0.
    pub fn calculate_dl_target_slot(
        scheduling_slot: u32,
        mu_sched: CarrierNumerology,
        mu_target: CarrierNumerology,
        k0: u32,
    ) -> u32 {
        let mu_s = mu_sched.mu_value() as i32;
        let mu_t = mu_target.mu_value() as i32;

        let base_slot = if mu_t >= mu_s {
            let shift = (mu_t - mu_s) as u32;
            scheduling_slot << shift
        } else {
            let shift = (mu_s - mu_t) as u32;
            scheduling_slot >> shift
        };

        base_slot + k0
    }

    /// Calculate target UL grant slot from scheduling cell DCI slot:
    /// n_target = floor(n_sched * 2^(mu_target - mu_sched)) + K2.
    pub fn calculate_ul_target_slot(
        scheduling_slot: u32,
        mu_sched: CarrierNumerology,
        mu_target: CarrierNumerology,
        k2: u32,
    ) -> u32 {
        Self::calculate_dl_target_slot(scheduling_slot, mu_sched, mu_target, k2)
    }

    /// Calculate HARQ-ACK feedback slot on scheduling cell:
    /// n_sched_feedback = floor((n_target + K1) * 2^(mu_sched - mu_target)).
    pub fn calculate_harq_feedback_slot(
        scheduled_slot: u32,
        k1: u32,
        mu_target: CarrierNumerology,
        mu_sched: CarrierNumerology,
    ) -> u32 {
        let target_ack_slot = scheduled_slot + k1;
        let mu_s = mu_sched.mu_value() as i32;
        let mu_t = mu_target.mu_value() as i32;

        if mu_s >= mu_t {
            let shift = (mu_s - mu_t) as u32;
            target_ack_slot << shift
        } else {
            let shift = (mu_t - mu_s) as u32;
            target_ack_slot >> shift
        }
    }
}

// ---------------------------------------------------------------------------
// Top-Level DSS & Mixed Numerology Engine
// ---------------------------------------------------------------------------

/// Carrier profile within the DSS engine.
#[derive(Debug, Clone)]
pub struct CarrierProfile {
    pub carrier_id: u8,
    pub numerology: CarrierNumerology,
    pub prb_count: u32,
    pub is_dss_with_lte: bool,
    pub crs_pattern: Option<LteCrsRateMatchingPattern>,
}

/// Telemetry metrics for DSS and multi-carrier scheduling.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DssMetrics {
    pub total_dci_scheduled: u64,
    pub total_cross_carrier_schedules: u64,
    pub total_mbsfn_slots_utilized: u64,
    pub total_crs_punctured_res: u64,
    pub total_usable_pdsch_res: u64,
}

/// Top-Level 3GPP Release 18 DSS Phase 2 & Mixed Numerology Scheduling Engine.
pub struct DssMixedEngine {
    pub carriers: HashMap<u8, CarrierProfile>,
    pub cross_carrier_configs: HashMap<(u8, u8), CrossCarrierSchedulingConfig>,
    pub blind_decode_counts: HashMap<(u8, u32), u32>, // (carrier_id, slot) -> current_count
    pub metrics: DssMetrics,
}

impl Default for DssMixedEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl DssMixedEngine {
    pub fn new() -> Self {
        DssMixedEngine {
            carriers: HashMap::new(),
            cross_carrier_configs: HashMap::new(),
            blind_decode_counts: HashMap::new(),
            metrics: DssMetrics {
                total_dci_scheduled: 0,
                total_cross_carrier_schedules: 0,
                total_mbsfn_slots_utilized: 0,
                total_crs_punctured_res: 0,
                total_usable_pdsch_res: 0,
            },
        }
    }

    /// Register a component carrier.
    pub fn add_carrier(
        &mut self,
        carrier_id: u8,
        numerology: CarrierNumerology,
        prb_count: u32,
        crs_pattern: Option<LteCrsRateMatchingPattern>,
    ) -> Result<(), DssError> {
        if carrier_id > 7 {
            return Err(DssError::InvalidCarrierId(carrier_id));
        }

        let is_dss = crs_pattern.is_some();
        let profile = CarrierProfile {
            carrier_id,
            numerology,
            prb_count,
            is_dss_with_lte: is_dss,
            crs_pattern,
        };

        self.carriers.insert(carrier_id, profile);
        Ok(())
    }

    /// Configure cross-carrier scheduling relationship.
    pub fn configure_cross_carrier(&mut self, config: CrossCarrierSchedulingConfig) {
        let key = (config.scheduling_carrier_id, config.scheduled_carrier_id);
        self.cross_carrier_configs.insert(key, config);
    }

    /// Perform cross-carrier scheduling from scheduling cell to target cell.
    pub fn schedule_cross_carrier_dl(
        &mut self,
        scheduling_carrier_id: u8,
        scheduled_carrier_id: u8,
        scheduling_slot: u32,
        k0_override: Option<u32>,
        k1_override: Option<u32>,
        blind_decodes_needed: u32,
    ) -> Result<CrossCarrierScheduleResult, DssError> {
        let sched_carrier = self
            .carriers
            .get(&scheduling_carrier_id)
            .ok_or(DssError::CarrierNotFound(scheduling_carrier_id))?;
        let target_carrier = self
            .carriers
            .get(&scheduled_carrier_id)
            .ok_or(DssError::CarrierNotFound(scheduled_carrier_id))?;

        let key = (scheduling_carrier_id, scheduled_carrier_id);
        let config = self
            .cross_carrier_configs
            .get(&key)
            .ok_or(DssError::CarrierNotFound(scheduled_carrier_id))?;

        // Check blind decoding budget on scheduling carrier
        let bd_limit = sched_carrier.numerology.max_blind_decodes_per_slot();
        let bd_entry = self
            .blind_decode_counts
            .entry((scheduling_carrier_id, scheduling_slot))
            .or_insert(0);

        if *bd_entry + blind_decodes_needed > bd_limit {
            return Err(DssError::BlindDecodingBudgetExceeded {
                slot: scheduling_slot,
                limit: bd_limit,
                requested: *bd_entry + blind_decodes_needed,
            });
        }
        *bd_entry += blind_decodes_needed;

        let k0 = k0_override.unwrap_or(config.default_k0);
        let k1 = k1_override.unwrap_or(config.default_k1);

        let target_slot = CrossCarrierSlotMapper::calculate_dl_target_slot(
            scheduling_slot,
            sched_carrier.numerology,
            target_carrier.numerology,
            k0,
        );

        let harq_feedback_slot = CrossCarrierSlotMapper::calculate_harq_feedback_slot(
            target_slot,
            k1,
            target_carrier.numerology,
            sched_carrier.numerology,
        );

        // Update telemetry
        self.metrics.total_dci_scheduled += 1;
        if scheduling_carrier_id != scheduled_carrier_id {
            self.metrics.total_cross_carrier_schedules += 1;
        }

        // Account for DSS CRS puncturing on target carrier if applicable
        if let Some(pattern) = &target_carrier.crs_pattern {
            let subframe =
                (target_slot / target_carrier.numerology.slots_per_subframe() % 10) as u8;
            let mask = pattern.compute_puncturing_mask(0, subframe);
            let prbs = target_carrier.prb_count as u64;

            self.metrics.total_crs_punctured_res += (mask.punctured_re_count as u64) * prbs;
            self.metrics.total_usable_pdsch_res += (mask.usable_re_count as u64) * prbs;

            if mask.punctured_re_count == 0 {
                self.metrics.total_mbsfn_slots_utilized += 1;
            }
        }

        Ok(CrossCarrierScheduleResult {
            scheduled_carrier_id,
            scheduling_slot,
            scheduled_slot: target_slot,
            k_offset_applied: k0,
            harq_feedback_slot,
        })
    }

    /// Evaluate PRB net usable RE capacity on a given carrier and slot.
    pub fn evaluate_prb_capacity(&self, carrier_id: u8, slot: u32) -> Option<CrsPuncturingMask> {
        let carrier = self.carriers.get(&carrier_id)?;
        if let Some(pattern) = &carrier.crs_pattern {
            let subframe = (slot / carrier.numerology.slots_per_subframe() % 10) as u8;
            Some(pattern.compute_puncturing_mask(0, subframe))
        } else {
            // Pure 5G NR carrier without LTE CRS: 168 REs fully usable
            Some(CrsPuncturingMask {
                prb_index: 0,
                symbol_masks: [0; 14],
                punctured_re_count: 0,
                usable_re_count: 168,
            })
        }
    }
}
