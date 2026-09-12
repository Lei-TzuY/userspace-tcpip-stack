//! 3GPP Rel-18 5G-Advanced Sidelink Inter-UE Coordination (IUC) & Conflict Resolution Engine.
//!
//! Compliant with:
//! - **3GPP TS 38.214 Rel-18 §8.1.4.1**: "UE procedure for determining physical sidelink
//!   shared channel assignment - Inter-UE Coordination (IUC) Scheme 1 & Scheme 2".
//! - **3GPP TS 38.212 Rel-18 §8.4.2**: 2nd-stage Sidelink Control Information (SCI format 2-C).
//! - **3GPP TS 38.321 Rel-18 §5.22.1**: MAC procedures for resource re-evaluation and pre-emption.
//! - **3GPP TS 38.331 Rel-18**: RRC configuration `SL-InterUE-CoordinationConfig`.
//!
//! Solves:
//! 1. **Hidden Node Problem**: When UE-A cannot detect transmissions from a distant UE-C,
//!    intermediate UE-B informs UE-A of UE-C's reserved resources to prevent in-band collisions.
//! 2. **Half-Duplex Blindness**: UE-A cannot sense while transmitting; UE-B provides external sensing feedback.
//! 3. **Scheme 1 Coordination**: UE-B evaluates sensing history and transmits explicit Preferred Resource Sets
//!    ($S_{\text{pref}}$) and Non-Preferred Resource Sets ($S_{\text{non-pref}}$) to UE-A.
//! 4. **Scheme 2 Collision Notification**: Condition-triggered alert when UE-B detects an imminent
//!    reservation overlap between two transmitting UEs, triggering pre-emption and re-evaluation at UE-A.
//! 5. **SCI Format 2-C Codec**: Compact binary wire encoding and decoding for coordination feedback.

use std::collections::{HashMap, HashSet};

// ---------------------------------------------------------------------------
// Protocol Constants
// ---------------------------------------------------------------------------

/// Protocol identifier for SCI format 2-C.
pub const SCI_FORMAT_2C_IDENTIFIER: u8 = 0x2C;

/// Minimum percentage of candidates that must remain available in selection window (20%).
pub const DEFAULT_MIN_RETAINED_CANDIDATE_RATIO: f64 = 0.20;

/// Default RSRP exclusion threshold for Inter-UE Coordination in dBm.
pub const DEFAULT_IUC_RSRP_THRESHOLD_DBM: i16 = -105;

/// Maximum coordination window in slots.
pub const MAX_IUC_WINDOW_SLOTS: u16 = 128;

// ---------------------------------------------------------------------------
// Basic Resource & Signaling Types
// ---------------------------------------------------------------------------

/// Single time-frequency physical resource block on Sidelink.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SidelinkSlotResource {
    pub slot: u64,
    pub subchannel: u8,
}

/// Coordination Scheme Type (TS 38.214 §8.1.4.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IucSchemeType {
    /// Scheme 1: Preferred resources indicated to UE-A.
    Scheme1Preferred = 0x01,
    /// Scheme 1: Non-preferred resources indicated to UE-A.
    Scheme1NonPreferred = 0x02,
    /// Scheme 2: Imminent collision / conflict notification.
    Scheme2ConflictNotification = 0x03,
}

/// Sidelink reservation entry recorded by a sensing node (UE-B).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SidelinkReservationEntry {
    pub transmitting_ue_id: u32,
    pub target_ue_id: u32,
    pub slot_reserved: u64,
    pub subchannel: u8,
    pub priority: u8, // 0..7 (0 is highest priority)
    pub sl_rsrp_dbm: i16,
    pub reservation_period_slots: u16,
}

/// 2nd-stage Sidelink Control Information (SCI format 2-C) (TS 38.212 §8.4.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SciFormat2C {
    pub scheme_type: IucSchemeType,
    pub requesting_ue_id: u32,
    pub coordinating_ue_id: u32,
    pub priority: u8,
    pub starting_slot: u64,
    pub slot_count: u8,
    /// Bitmap of resources: 1 = included in scheme, 0 = not included.
    pub resource_bitmap: Vec<u8>,
}

impl SciFormat2C {
    /// Encode SCI format 2-C into compact binary wire representation.
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.push(SCI_FORMAT_2C_IDENTIFIER);
        buf.push(self.scheme_type as u8);
        buf.extend_from_slice(&self.requesting_ue_id.to_be_bytes());
        buf.extend_from_slice(&self.coordinating_ue_id.to_be_bytes());
        buf.push(self.priority);
        buf.extend_from_slice(&self.starting_slot.to_be_bytes());
        buf.push(self.slot_count);
        let len_u16 = self.resource_bitmap.len() as u16;
        buf.extend_from_slice(&len_u16.to_be_bytes());
        buf.extend_from_slice(&self.resource_bitmap);
        buf
    }

    /// Decode binary wire representation into SCI format 2-C.
    pub fn decode(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() < 22 {
            return Err("Buffer too short for SCI format 2-C".to_string());
        }
        if bytes[0] != SCI_FORMAT_2C_IDENTIFIER {
            return Err(format!(
                "Invalid SCI 2-C identifier: expected {:#04x}, got {:#04x}",
                SCI_FORMAT_2C_IDENTIFIER, bytes[0]
            ));
        }

        let scheme_type = match bytes[1] {
            0x01 => IucSchemeType::Scheme1Preferred,
            0x02 => IucSchemeType::Scheme1NonPreferred,
            0x03 => IucSchemeType::Scheme2ConflictNotification,
            other => return Err(format!("Invalid IUC scheme type: {other}")),
        };

        let requesting_ue_id = u32::from_be_bytes([bytes[2], bytes[3], bytes[4], bytes[5]]);
        let coordinating_ue_id = u32::from_be_bytes([bytes[6], bytes[7], bytes[8], bytes[9]]);
        let priority = bytes[10];
        let starting_slot = u64::from_be_bytes([
            bytes[11], bytes[12], bytes[13], bytes[14], bytes[15], bytes[16], bytes[17], bytes[18],
        ]);
        let slot_count = bytes[19];
        let bitmap_len = u16::from_be_bytes([bytes[20], bytes[21]]) as usize;

        if bytes.len() < 22 + bitmap_len {
            return Err("Truncated resource bitmap in SCI 2-C".to_string());
        }
        let resource_bitmap = bytes[22..22 + bitmap_len].to_vec();

        Ok(Self {
            scheme_type,
            requesting_ue_id,
            coordinating_ue_id,
            priority,
            starting_slot,
            slot_count,
            resource_bitmap,
        })
    }
}

/// Imminent conflict / collision report generated under Scheme 2.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IucConflictNotification {
    pub colliding_slot: u64,
    pub colliding_subchannel: u8,
    pub ue_a_id: u32,
    pub ue_a_priority: u8,
    pub colliding_peer_id: u32,
    pub colliding_peer_priority: u8,
    pub reason: &'static str,
}

// ---------------------------------------------------------------------------
// Sidelink Inter-UE Coordination Engine
// ---------------------------------------------------------------------------

/// Configuration for Inter-UE Coordination entity.
#[derive(Debug, Clone, PartialEq)]
pub struct IucConfig {
    pub local_ue_id: u32,
    pub total_subchannels: u8,
    pub rsrp_threshold_dbm: i16,
    pub min_candidate_ratio: f64,
}

impl Default for IucConfig {
    fn default() -> Self {
        Self {
            local_ue_id: 1,
            total_subchannels: 4,
            rsrp_threshold_dbm: DEFAULT_IUC_RSRP_THRESHOLD_DBM,
            min_candidate_ratio: DEFAULT_MIN_RETAINED_CANDIDATE_RATIO,
        }
    }
}

/// Complete 3GPP Rel-18 Sidelink Inter-UE Coordination (IUC) Engine.
#[derive(Debug, PartialEq)]
pub struct SidelinkIucEngine {
    pub config: IucConfig,
    /// Active sensing database of neighbor reservations: key = (slot, subchannel).
    pub reservations: HashMap<SidelinkSlotResource, SidelinkReservationEntry>,
    /// Own reservations scheduled for transmission.
    pub own_reservations: HashMap<u64, SidelinkSlotResource>,
    /// Statistics.
    pub stats_scheme1_reports_generated: u64,
    pub stats_scheme2_conflicts_detected: u64,
    pub stats_hidden_node_collisions_avoided: u64,
    pub stats_re_evaluations_triggered: u64,
}

impl SidelinkIucEngine {
    pub fn new(config: IucConfig) -> Self {
        Self {
            config,
            reservations: HashMap::new(),
            own_reservations: HashMap::new(),
            stats_scheme1_reports_generated: 0,
            stats_scheme2_conflicts_detected: 0,
            stats_hidden_node_collisions_avoided: 0,
            stats_re_evaluations_triggered: 0,
        }
    }

    /// Record an incoming SCI format 1-A reservation announced by a peer UE.
    pub fn record_peer_reservation(&mut self, entry: SidelinkReservationEntry) {
        let res = SidelinkSlotResource {
            slot: entry.slot_reserved,
            subchannel: entry.subchannel,
        };
        self.reservations.insert(res, entry);

        // Periodically purge entries older than 2000 slots
        let min_slot = if res.slot > 2000 { res.slot - 2000 } else { 0 };
        self.reservations.retain(|r, _| r.slot >= min_slot);
    }

    /// Schedule own transmission on a specific slot and subchannel.
    pub fn schedule_own_transmission(&mut self, slot: u64, subchannel: u8) {
        self.own_reservations
            .insert(slot, SidelinkSlotResource { slot, subchannel });
    }

    // -----------------------------------------------------------------------
    // Scheme 1: Preferred & Non-Preferred Resource Set Evaluation (UE-B side)
    // -----------------------------------------------------------------------

    /// Coordinating UE-B generates Scheme 1 Coordination Information for requesting UE-A (TS 38.214 §8.1.4.1).
    /// Partitions candidate resources in window [start_slot .. start_slot + slot_count - 1] into:
    /// - Non-preferred set: Resources where UE-B detects high interference (RSRP >= threshold)
    ///   or reservations by peer UEs with equal/higher priority.
    /// - Preferred set: Resources free of colliding reservations and below threshold.
    pub fn generate_scheme1_coordination(
        &mut self,
        requesting_ue_id: u32,
        requesting_priority: u8,
        start_slot: u64,
        slot_count: u8,
        indicate_preferred: bool,
    ) -> (SciFormat2C, HashSet<SidelinkSlotResource>) {
        let mut non_preferred_set = HashSet::new();
        let mut preferred_set = HashSet::new();

        let num_subch = self.config.total_subchannels;

        for s in start_slot..start_slot + slot_count as u64 {
            for subch in 0..num_subch {
                let res = SidelinkSlotResource {
                    slot: s,
                    subchannel: subch,
                };

                let mut is_non_pref = false;
                if let Some(entry) = self.reservations.get(&res) {
                    // Check if entry belongs to someone else and exceeds RSRP threshold
                    if entry.transmitting_ue_id != requesting_ue_id
                        && entry.sl_rsrp_dbm >= self.config.rsrp_threshold_dbm
                    {
                        // Stricter protection if peer has equal or higher priority (lower numerical value)
                        if entry.priority <= requesting_priority {
                            is_non_pref = true;
                        }
                    }
                }

                if is_non_pref {
                    non_preferred_set.insert(res);
                } else {
                    preferred_set.insert(res);
                }
            }
        }

        let total_candidates = (slot_count as usize) * (num_subch as usize);
        let reported_set = if indicate_preferred {
            preferred_set
        } else {
            non_preferred_set
        };

        // Pack reported resources into byte bitmap
        let num_bytes = (total_candidates + 7) / 8;
        let mut bitmap = vec![0u8; num_bytes];

        for s in 0..slot_count as usize {
            for subch in 0..num_subch as usize {
                let res = SidelinkSlotResource {
                    slot: start_slot + s as u64,
                    subchannel: subch as u8,
                };
                let bit_idx = s * (num_subch as usize) + subch;
                if reported_set.contains(&res) {
                    let byte_idx = bit_idx / 8;
                    let bit_offset = 7 - (bit_idx % 8);
                    bitmap[byte_idx] |= 1 << bit_offset;
                }
            }
        }

        let scheme_type = if indicate_preferred {
            IucSchemeType::Scheme1Preferred
        } else {
            IucSchemeType::Scheme1NonPreferred
        };

        self.stats_scheme1_reports_generated += 1;

        let sci = SciFormat2C {
            scheme_type,
            requesting_ue_id,
            coordinating_ue_id: self.config.local_ue_id,
            priority: requesting_priority,
            starting_slot: start_slot,
            slot_count,
            resource_bitmap: bitmap,
        };

        (sci, reported_set)
    }

    // -----------------------------------------------------------------------
    // Scheme 1: Application & Filtering (UE-A side)
    // -----------------------------------------------------------------------

    /// Requesting UE-A applies incoming Scheme 1 Coordination from UE-B to filter its selection candidates.
    pub fn apply_scheme1_filtering(
        &mut self,
        sci: &SciFormat2C,
        candidate_resources: &[SidelinkSlotResource],
    ) -> Vec<SidelinkSlotResource> {
        let num_subch = self.config.total_subchannels as usize;
        let mut filtered = Vec::new();

        for &cand in candidate_resources {
            if cand.slot < sci.starting_slot
                || cand.slot >= sci.starting_slot + sci.slot_count as u64
                || (cand.subchannel as usize) >= num_subch
            {
                // Outside coordination window; retain as is
                filtered.push(cand);
                continue;
            }

            let s_offset = (cand.slot - sci.starting_slot) as usize;
            let bit_idx = s_offset * num_subch + (cand.subchannel as usize);
            let byte_idx = bit_idx / 8;
            let bit_offset = 7 - (bit_idx % 8);

            let is_marked = if byte_idx < sci.resource_bitmap.len() {
                (sci.resource_bitmap[byte_idx] & (1 << bit_offset)) != 0
            } else {
                false
            };

            match sci.scheme_type {
                IucSchemeType::Scheme1Preferred => {
                    // Only retain if flagged as preferred
                    if is_marked {
                        filtered.push(cand);
                    }
                }
                IucSchemeType::Scheme1NonPreferred => {
                    // Exclude if flagged as non-preferred
                    if !is_marked {
                        filtered.push(cand);
                    } else {
                        self.stats_hidden_node_collisions_avoided += 1;
                    }
                }
                _ => filtered.push(cand),
            }
        }

        // 20% candidate fallback rule: if filtered candidates < 20% of original, revert to full set
        let min_required =
            (candidate_resources.len() as f64 * self.config.min_candidate_ratio).ceil() as usize;
        if filtered.len() < min_required && !candidate_resources.is_empty() {
            candidate_resources.to_vec()
        } else {
            filtered
        }
    }

    // -----------------------------------------------------------------------
    // Scheme 2: Condition-Triggered Collision Detection (UE-B side)
    // -----------------------------------------------------------------------

    /// Coordinating UE-B monitors spectrum and identifies imminent collisions between UE-A and hidden nodes.
    /// Triggers Scheme 2 Conflict Notification if two UEs reserve the same slot and subchannel (TS 38.214 §8.1.4.1).
    pub fn evaluate_scheme2_conflicts(
        &mut self,
        ue_a_id: u32,
        ue_a_slot: u64,
        ue_a_subchannel: u8,
        ue_a_priority: u8,
    ) -> Option<IucConflictNotification> {
        let res = SidelinkSlotResource {
            slot: ue_a_slot,
            subchannel: ue_a_subchannel,
        };

        if let Some(entry) = self.reservations.get(&res) {
            // Collision detected if a different UE has reserved the same slot & subchannel
            if entry.transmitting_ue_id != ue_a_id
                && entry.sl_rsrp_dbm >= self.config.rsrp_threshold_dbm
            {
                self.stats_scheme2_conflicts_detected += 1;
                return Some(IucConflictNotification {
                    colliding_slot: ue_a_slot,
                    colliding_subchannel: ue_a_subchannel,
                    ue_a_id,
                    ue_a_priority,
                    colliding_peer_id: entry.transmitting_ue_id,
                    colliding_peer_priority: entry.priority,
                    reason: "Imminent resource collision with hidden peer reservation",
                });
            }
        }

        None
    }

    // -----------------------------------------------------------------------
    // Scheme 2: Pre-emption & Re-evaluation (UE-A side)
    // -----------------------------------------------------------------------

    /// Transmitting UE-A processes incoming Conflict Notification:
    /// Cancels scheduled transmission and triggers pre-emption re-evaluation to an uncontested slot.
    pub fn handle_scheme2_conflict(
        &mut self,
        conflict: &IucConflictNotification,
        available_candidates: &[SidelinkSlotResource],
    ) -> Option<SidelinkSlotResource> {
        // Drop conflicting reservation
        self.own_reservations.remove(&conflict.colliding_slot);
        self.stats_re_evaluations_triggered += 1;
        self.stats_hidden_node_collisions_avoided += 1;

        // Pick alternative candidate that avoids the colliding slot/subchannel
        let alternative = available_candidates
            .iter()
            .find(|c| {
                !(c.slot == conflict.colliding_slot
                    && c.subchannel == conflict.colliding_subchannel)
            })
            .copied();

        if let Some(alt) = alternative {
            self.schedule_own_transmission(alt.slot, alt.subchannel);
        }

        alternative
    }
}
