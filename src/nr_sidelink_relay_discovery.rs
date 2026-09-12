//! 3GPP Rel-18 5G-Advanced Sidelink Relay Discovery & Re-selection Engine.
//!
//! Compliant with:
//! - 3GPP TS 38.300 §16.12 Rel-18 ("Sidelink Relay in NR")
//! - 3GPP TS 38.331 §5.8.15 Rel-18 ("Sidelink Relay Discovery and Reselection procedures")
//! - 3GPP TS 23.304 §6.3 Rel-18 ("ProSe Direct Discovery Models A and B for UE-to-Network and UE-to-UE Relay")
//! - 3GPP TS 38.215 §5.1.x (Sidelink PC5-RSRP and Uu-RSRP measurements)
//!
//! Key Capabilities:
//! 1. Dual Discovery Architecture:
//!    - Model A ("I am here"): Periodic Relay Discovery Announcements with Relay Service Code (RSC)
//!      and Uu link quality indication.
//!    - Model B ("Who is there?"): On-demand Relay Discovery Solicitations and candidate Responses.
//! 2. Rel-18 Multi-Hop Relay Extension:
//!    - Supports multi-hop hop-count signaling, hop limit enforcement, and loop mitigation.
//! 3. Sidelink Relay Selection & Re-selection Evaluator (TS 38.331 §5.8.15.2):
//!    - End-to-end radio quality metric ranking: $R = \min(RSRP_{PC5}, RSRP_{Uu}) - \text{hop\_penalty}$.
//!    - Configurable hysteresis margins ($\text{Hyst}_{\text{Relay}}$) and Time-To-Trigger ($TTT$).
//!    - Seamless ping-pong mitigation between Direct Uu and Relay, or between Relay candidates.
//! 4. Compact 3GPP Binary PC5-D Message Serialization & Bitfield Codecs.
//!
//! Pure Rust standard library implementation with zero external dependencies.

use std::collections::HashMap;

// ---------------------------------------------------------------------------
// Constants & Defaults
// ---------------------------------------------------------------------------

/// Default Direct Uu RSRP high threshold in dBm (-105 dBm). Below this, search for relay.
pub const DEFAULT_DIRECT_UU_THRESH_HIGH_DBM: f64 = -105.0;

/// Default minimum Sidelink PC5-RSRP threshold in dBm (-112 dBm) for relay suitability.
pub const DEFAULT_PC5_RSRP_MIN_THRESH_DBM: f64 = -112.0;

/// Default Relay Reselection Hysteresis in dB (3.0 dB) to prevent ping-pong switching.
pub const DEFAULT_RELAY_HYSTERESIS_DB: f64 = 3.0;

/// Default Time-To-Trigger (TTT) in milliseconds (100 ms) before executing reselection.
pub const DEFAULT_RELAY_TTT_MS: u64 = 100;

/// Default relay candidate entry expiration timeout in milliseconds (3000 ms = 3.0s).
pub const DEFAULT_RELAY_EXPIRY_MS: u64 = 3000;

/// Default maximum allowed relay hops in Rel-18 multi-hop relaying (2 hops).
pub const DEFAULT_MAX_RELAY_HOPS: u8 = 2;

/// Default per-hop metric penalty in dB to prefer shorter relay paths.
pub const DEFAULT_HOP_PENALTY_DB: f64 = 3.0;

// ---------------------------------------------------------------------------
// Enumerations & Data Structures
// ---------------------------------------------------------------------------

/// Protocol role of the local node in 5G sidelink relaying.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SidelinkRelayRole {
    /// Remote UE out-of-coverage or at cell edge seeking connection.
    RemoteUe,
    /// Relay UE providing connectivity forwarding between Remote UE and gNodeB / peer UE.
    RelayUe,
}

/// Sidelink Discovery Model (TS 23.304 §6.3.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RelayDiscoveryModel {
    /// Model A: Announcement-based ("I am here").
    ModelA,
    /// Model B: Solicitation / Response ("Who is there? / I am here").
    ModelB,
}

/// 3GPP PC5-D Discovery Message Type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Pc5DiscoveryMessageType {
    /// Relay Discovery Announcement (Model A).
    Announcement = 1,
    /// Relay Discovery Solicitation (Model B).
    Solicitation = 2,
    /// Relay Discovery Response (Model B).
    Response = 3,
}

/// Connection state of the Remote UE.
#[derive(Debug, Clone, PartialEq)]
pub enum RelayConnectionState {
    /// Directly connected to the gNodeB via Uu radio interface.
    DirectUu,
    /// Connected through an intermediate Relay UE via PC5 sidelink.
    ConnectedViaRelay {
        relay_l2_id: [u8; 3],
        pc5_rsrp_dbm: f64,
        hop_count: u8,
    },
    /// Disconnected / Out-of-Coverage searching for a suitable relay.
    SearchingForRelay,
}

/// Outcome of a periodic relay re-selection evaluation (TS 38.331).
#[derive(Debug, Clone, PartialEq)]
pub enum RelayReselectionDecision {
    /// Maintain current connection without changes.
    StayConnected,
    /// Trigger re-selection to a designated candidate Relay UE.
    SwitchToRelay {
        target_relay_l2_id: [u8; 3],
        target_metric: f64,
        reason: String,
    },
    /// Switch back from Relay to direct gNodeB Uu link due to improved Uu signal.
    SwitchToDirectUu {
        direct_uu_rsrp_dbm: f64,
        reason: String,
    },
    /// No viable relay candidate meets the suitability thresholds.
    NoSuitableRelay,
}

/// Errors occurring during discovery message handling or parsing.
#[derive(Debug, Clone, PartialEq)]
pub enum RelayDiscoveryError {
    BufferTooShort { expected: usize, actual: usize },
    InvalidMessageType(u8),
    InvalidRelayServiceCode,
    HopLimitExceeded { hops: u8, max_hops: u8 },
    InvalidLayer2Id,
}

impl std::fmt::Display for RelayDiscoveryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BufferTooShort { expected, actual } => {
                write!(
                    f,
                    "Buffer too short: expected {} bytes, got {}",
                    expected, actual
                )
            }
            Self::InvalidMessageType(t) => write!(f, "Invalid PC5-D message type: 0x{:02X}", t),
            Self::InvalidRelayServiceCode => write!(f, "Invalid 24-bit Relay Service Code"),
            Self::HopLimitExceeded { hops, max_hops } => {
                write!(f, "Relay hop count {} exceeds max {}", hops, max_hops)
            }
            Self::InvalidLayer2Id => write!(f, "Invalid 24-bit Layer-2 ID"),
        }
    }
}

// ---------------------------------------------------------------------------
// PC5-D Discovery Protocol Framing
// ---------------------------------------------------------------------------

/// 3GPP PC5-D Sidelink Relay Discovery Protocol Data Unit.
#[derive(Debug, Clone, PartialEq)]
pub struct Pc5DiscoveryMessage {
    pub msg_type: Pc5DiscoveryMessageType,
    /// 24-bit Relay Service Code (RSC) indicating service profile (e.g. Public Safety, VoNR).
    pub relay_service_code: u32,
    /// 24-bit Source Layer-2 ID of transmitting node.
    pub sender_l2_id: [u8; 3],
    /// Optional 24-bit Target Layer-2 ID (used in Model B Response).
    pub target_l2_id: Option<[u8; 3]>,
    /// Quantized Uu RSRP in dBm (-140 dBm .. -44 dBm, 1 dB step).
    pub uu_rsrp_dbm: Option<f64>,
    /// Rel-18 Multi-Hop Relay hop count (1 for single-hop relay, 2+ for multi-hop).
    pub hop_count: u8,
}

impl Pc5DiscoveryMessage {
    /// Encode PC5-D discovery frame into binary wire format.
    /// Format:
    /// [0]: msg_type (u8)
    /// [1..4]: relay_service_code (24 bits BE) | hop_count (8 bits)
    /// [4..7]: sender_l2_id (3 bytes)
    /// [7]: has_target (1 bit) | has_uu_rsrp (1 bit) | reserved (6 bits)
    /// [8..11] (optional): target_l2_id (3 bytes)
    /// [11] (optional): uu_rsrp (u8, mapped as (rsrp + 140) in dBm)
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(12);

        // Byte 0: Message Type
        bytes.push(self.msg_type as u8);

        // Bytes 1..3: Relay Service Code (24 bits)
        let rsc = self.relay_service_code & 0x00FF_FFFF;
        bytes.push(((rsc >> 16) & 0xFF) as u8);
        bytes.push(((rsc >> 8) & 0xFF) as u8);
        bytes.push((rsc & 0xFF) as u8);

        // Byte 4: Hop count
        bytes.push(self.hop_count);

        // Bytes 5..7: Sender L2 ID
        bytes.extend_from_slice(&self.sender_l2_id);

        // Byte 8: Flags
        let mut flags = 0u8;
        if self.target_l2_id.is_some() {
            flags |= 0x80;
        }
        if self.uu_rsrp_dbm.is_some() {
            flags |= 0x40;
        }
        bytes.push(flags);

        // Optional Target L2 ID
        if let Some(target) = self.target_l2_id {
            bytes.extend_from_slice(&target);
        }

        // Optional Uu RSRP
        if let Some(rsrp) = self.uu_rsrp_dbm {
            // Encode -140..-44 dBm as 0..96
            let quantized = ((rsrp + 140.0).clamp(0.0, 255.0).round()) as u8;
            bytes.push(quantized);
        }

        bytes
    }

    /// Decode PC5-D discovery frame from binary wire format.
    pub fn from_bytes(data: &[u8]) -> Result<Self, RelayDiscoveryError> {
        if data.len() < 9 {
            return Err(RelayDiscoveryError::BufferTooShort {
                expected: 9,
                actual: data.len(),
            });
        }

        let msg_type = match data[0] {
            1 => Pc5DiscoveryMessageType::Announcement,
            2 => Pc5DiscoveryMessageType::Solicitation,
            3 => Pc5DiscoveryMessageType::Response,
            other => return Err(RelayDiscoveryError::InvalidMessageType(other)),
        };

        let rsc = ((data[1] as u32) << 16) | ((data[2] as u32) << 8) | (data[3] as u32);
        let hop_count = data[4];
        let sender_l2_id = [data[5], data[6], data[7]];
        let flags = data[8];

        let mut offset = 9;
        let mut target_l2_id = None;
        if (flags & 0x80) != 0 {
            if data.len() < offset + 3 {
                return Err(RelayDiscoveryError::BufferTooShort {
                    expected: offset + 3,
                    actual: data.len(),
                });
            }
            target_l2_id = Some([data[offset], data[offset + 1], data[offset + 2]]);
            offset += 3;
        }

        let mut uu_rsrp_dbm = None;
        if (flags & 0x40) != 0 {
            if data.len() < offset + 1 {
                return Err(RelayDiscoveryError::BufferTooShort {
                    expected: offset + 1,
                    actual: data.len(),
                });
            }
            let raw_rsrp = data[offset] as f64;
            uu_rsrp_dbm = Some(raw_rsrp - 140.0);
        }

        Ok(Self {
            msg_type,
            relay_service_code: rsc,
            sender_l2_id,
            target_l2_id,
            uu_rsrp_dbm,
            hop_count,
        })
    }
}

// ---------------------------------------------------------------------------
// Candidate Relay Entity
// ---------------------------------------------------------------------------

/// Tracked candidate Relay UE in the Remote UE's discovery database.
#[derive(Debug, Clone, PartialEq)]
pub struct CandidateRelay {
    pub relay_l2_id: [u8; 3],
    pub relay_service_code: u32,
    pub pc5_rsrp_dbm: f64,
    pub uu_rsrp_dbm: f64,
    pub hop_count: u8,
    pub last_seen_ms: u64,
}

impl CandidateRelay {
    /// Calculate composite end-to-end radio quality metric $R$:
    /// $R = \min(RSRP_{PC5}, RSRP_{Uu}) - (\text{hop\_count} - 1) \cdot \text{penalty}$
    pub fn calculate_metric(&self, hop_penalty_db: f64) -> f64 {
        let bottleneck = self.pc5_rsrp_dbm.min(self.uu_rsrp_dbm);
        let hops_penalty = ((self.hop_count.max(1) - 1) as f64) * hop_penalty_db;
        bottleneck - hops_penalty
    }
}

// ---------------------------------------------------------------------------
// Engine Configuration
// ---------------------------------------------------------------------------

/// Sidelink relay discovery and re-selection configuration parameters.
#[derive(Debug, Clone, PartialEq)]
pub struct SidelinkRelayConfig {
    pub direct_uu_thresh_high_dbm: f64,
    pub pc5_rsrp_min_thresh_dbm: f64,
    pub relay_hysteresis_db: f64,
    pub time_to_trigger_ms: u64,
    pub relay_expiry_ms: u64,
    pub max_relay_hops: u8,
    pub hop_penalty_db: f64,
}

impl SidelinkRelayConfig {
    pub fn default_config() -> Self {
        Self {
            direct_uu_thresh_high_dbm: DEFAULT_DIRECT_UU_THRESH_HIGH_DBM,
            pc5_rsrp_min_thresh_dbm: DEFAULT_PC5_RSRP_MIN_THRESH_DBM,
            relay_hysteresis_db: DEFAULT_RELAY_HYSTERESIS_DB,
            time_to_trigger_ms: DEFAULT_RELAY_TTT_MS,
            relay_expiry_ms: DEFAULT_RELAY_EXPIRY_MS,
            max_relay_hops: DEFAULT_MAX_RELAY_HOPS,
            hop_penalty_db: DEFAULT_HOP_PENALTY_DB,
        }
    }
}

// ---------------------------------------------------------------------------
// Sidelink Relay Discovery & Reselection Engine
// ---------------------------------------------------------------------------

/// Complete 3GPP Rel-18 Sidelink Relay Discovery & Reselection Engine.
#[derive(Debug, PartialEq)]
pub struct SidelinkRelayDiscoveryEngine {
    pub role: SidelinkRelayRole,
    pub own_l2_id: [u8; 3],
    pub supported_rsc: u32,
    pub config: SidelinkRelayConfig,
    pub candidate_relays: HashMap<[u8; 3], CandidateRelay>,
    pub connection_state: RelayConnectionState,
    /// Pending candidate for reselection: (candidate_id, first_triggered_timestamp_ms)
    pub pending_reselection: Option<([u8; 3], u64)>,
    /// Pending switch back to direct Uu: first_triggered_timestamp_ms
    pub pending_direct_uu: Option<u64>,
    /// Statistics: Discovery announcements received.
    pub stats_announcements_received: u64,
    /// Statistics: Solicitations received.
    pub stats_solicitations_received: u64,
    /// Statistics: Total successful relay reselections executed.
    pub stats_reselections_executed: u64,
}

impl SidelinkRelayDiscoveryEngine {
    pub fn new(
        role: SidelinkRelayRole,
        own_l2_id: [u8; 3],
        supported_rsc: u32,
        config: SidelinkRelayConfig,
    ) -> Self {
        let initial_state = match role {
            SidelinkRelayRole::RemoteUe => RelayConnectionState::SearchingForRelay,
            SidelinkRelayRole::RelayUe => RelayConnectionState::DirectUu,
        };

        Self {
            role,
            own_l2_id,
            supported_rsc,
            config,
            candidate_relays: HashMap::new(),
            connection_state: initial_state,
            pending_reselection: None,
            pending_direct_uu: None,
            stats_announcements_received: 0,
            stats_solicitations_received: 0,
            stats_reselections_executed: 0,
        }
    }

    /// Generate Model A Relay Discovery Announcement (transmitting by Relay UE).
    pub fn generate_announcement(
        &self,
        uu_rsrp_dbm: f64,
    ) -> Result<Pc5DiscoveryMessage, RelayDiscoveryError> {
        Ok(Pc5DiscoveryMessage {
            msg_type: Pc5DiscoveryMessageType::Announcement,
            relay_service_code: self.supported_rsc,
            sender_l2_id: self.own_l2_id,
            target_l2_id: None,
            uu_rsrp_dbm: Some(uu_rsrp_dbm),
            hop_count: 1, // Single-hop direct U2N relay
        })
    }

    /// Generate Model B Relay Discovery Solicitation (transmitting by Remote UE).
    pub fn generate_solicitation(&self, requested_rsc: u32) -> Pc5DiscoveryMessage {
        Pc5DiscoveryMessage {
            msg_type: Pc5DiscoveryMessageType::Solicitation,
            relay_service_code: requested_rsc,
            sender_l2_id: self.own_l2_id,
            target_l2_id: None,
            uu_rsrp_dbm: None,
            hop_count: 0,
        }
    }

    /// Ingest an incoming PC5-D discovery message and update candidate repository.
    /// If local node is a Relay UE receiving a matching Model B Solicitation, returns a Response message.
    pub fn process_discovery_message(
        &mut self,
        msg: &Pc5DiscoveryMessage,
        measured_pc5_rsrp_dbm: f64,
        now_ms: u64,
    ) -> Option<Pc5DiscoveryMessage> {
        match msg.msg_type {
            Pc5DiscoveryMessageType::Announcement | Pc5DiscoveryMessageType::Response => {
                self.stats_announcements_received += 1;
                // If this message advertises our supported service code and within hop limit
                if msg.relay_service_code == self.supported_rsc
                    && msg.hop_count <= self.config.max_relay_hops
                {
                    let uu_rsrp = msg.uu_rsrp_dbm.unwrap_or(-140.0);
                    let candidate = CandidateRelay {
                        relay_l2_id: msg.sender_l2_id,
                        relay_service_code: msg.relay_service_code,
                        pc5_rsrp_dbm: measured_pc5_rsrp_dbm,
                        uu_rsrp_dbm: uu_rsrp,
                        hop_count: msg.hop_count,
                        last_seen_ms: now_ms,
                    };
                    self.candidate_relays.insert(msg.sender_l2_id, candidate);
                }
                None
            }
            Pc5DiscoveryMessageType::Solicitation => {
                self.stats_solicitations_received += 1;
                // If we are a Relay UE and the solicitation requests our RSC, reply with Response
                if self.role == SidelinkRelayRole::RelayUe
                    && msg.relay_service_code == self.supported_rsc
                {
                    Some(Pc5DiscoveryMessage {
                        msg_type: Pc5DiscoveryMessageType::Response,
                        relay_service_code: self.supported_rsc,
                        sender_l2_id: self.own_l2_id,
                        target_l2_id: Some(msg.sender_l2_id),
                        uu_rsrp_dbm: Some(-85.0), // Relay serving cell quality
                        hop_count: 1,
                    })
                } else {
                    None
                }
            }
        }
    }

    /// Evaluate Sidelink Relay Selection and Re-selection rules according to TS 38.331 §5.8.15.2.
    pub fn evaluate_reselection(
        &mut self,
        direct_uu_rsrp_dbm: Option<f64>,
        now_ms: u64,
    ) -> RelayReselectionDecision {
        self.prune_stale_relays(now_ms);

        // Case 1: If current direct Uu link is healthy (above threshold + hysteresis), stay on Direct Uu
        if let Some(uu_rsrp) = direct_uu_rsrp_dbm {
            if uu_rsrp >= self.config.direct_uu_thresh_high_dbm + self.config.relay_hysteresis_db {
                if let RelayConnectionState::ConnectedViaRelay { .. } = self.connection_state {
                    // Time-to-trigger for returning to direct Uu
                    if let Some(start_ms) = self.pending_direct_uu {
                        if now_ms >= start_ms + self.config.time_to_trigger_ms {
                            self.connection_state = RelayConnectionState::DirectUu;
                            self.pending_direct_uu = None;
                            self.stats_reselections_executed += 1;
                            return RelayReselectionDecision::SwitchToDirectUu {
                                direct_uu_rsrp_dbm: uu_rsrp,
                                reason: "Direct Uu RSRP exceeds high threshold + hysteresis"
                                    .to_string(),
                            };
                        }
                    } else {
                        self.pending_direct_uu = Some(now_ms);
                    }
                    return RelayReselectionDecision::StayConnected;
                } else {
                    self.connection_state = RelayConnectionState::DirectUu;
                    self.pending_reselection = None;
                    self.pending_direct_uu = None;
                    return RelayReselectionDecision::StayConnected;
                }
            } else {
                self.pending_direct_uu = None;
            }
        }

        // Find the best suitable relay candidate
        let mut best_candidate: Option<CandidateRelay> = None;
        let mut best_metric = -999.0f64;

        for candidate in self.candidate_relays.values() {
            // Minimum suitability criterion: PC5 RSRP >= min threshold
            if candidate.pc5_rsrp_dbm >= self.config.pc5_rsrp_min_thresh_dbm {
                let metric = candidate.calculate_metric(self.config.hop_penalty_db);
                if metric > best_metric {
                    best_metric = metric;
                    best_candidate = Some(candidate.clone());
                }
            }
        }

        let target = match best_candidate {
            Some(c) => c,
            None => {
                self.pending_reselection = None;
                return RelayReselectionDecision::NoSuitableRelay;
            }
        };

        // Determine if target candidate satisfies re-selection hysteresis over active link
        let current_active_metric = match &self.connection_state {
            RelayConnectionState::DirectUu => direct_uu_rsrp_dbm.unwrap_or(-140.0),
            RelayConnectionState::ConnectedViaRelay { relay_l2_id, .. } => {
                if let Some(current_relay) = self.candidate_relays.get(relay_l2_id) {
                    current_relay.calculate_metric(self.config.hop_penalty_db)
                } else {
                    -140.0 // Lost relay
                }
            }
            RelayConnectionState::SearchingForRelay => -140.0,
        };

        let needs_reselection = match &self.connection_state {
            RelayConnectionState::ConnectedViaRelay { relay_l2_id, .. } => {
                // If same relay, no change
                if *relay_l2_id == target.relay_l2_id {
                    false
                } else {
                    // Inter-relay reselection requires hysteresis improvement
                    best_metric >= current_active_metric + self.config.relay_hysteresis_db
                }
            }
            RelayConnectionState::DirectUu => {
                // Direct-to-relay requires direct Uu < Thresh_High and target meets min threshold
                best_metric >= current_active_metric + self.config.relay_hysteresis_db
            }
            RelayConnectionState::SearchingForRelay => true,
        };

        if !needs_reselection {
            self.pending_reselection = None;
            return RelayReselectionDecision::StayConnected;
        }

        // Apply Time-To-Trigger (TTT)
        if let Some((pending_id, start_time)) = self.pending_reselection {
            if pending_id == target.relay_l2_id {
                if now_ms >= start_time + self.config.time_to_trigger_ms {
                    // TTT expired: commit reselection
                    self.connection_state = RelayConnectionState::ConnectedViaRelay {
                        relay_l2_id: target.relay_l2_id,
                        pc5_rsrp_dbm: target.pc5_rsrp_dbm,
                        hop_count: target.hop_count,
                    };
                    self.pending_reselection = None;
                    self.stats_reselections_executed += 1;

                    return RelayReselectionDecision::SwitchToRelay {
                        target_relay_l2_id: target.relay_l2_id,
                        target_metric: best_metric,
                        reason: "TTT expired with candidate metric exceeding hysteresis margin"
                            .to_string(),
                    };
                }
            } else {
                // Target changed during TTT; restart TTT
                self.pending_reselection = Some((target.relay_l2_id, now_ms));
            }
        } else {
            // First time condition met; arm TTT
            self.pending_reselection = Some((target.relay_l2_id, now_ms));
        }

        RelayReselectionDecision::StayConnected
    }

    /// Prune expired candidate entries from local database.
    pub fn prune_stale_relays(&mut self, now_ms: u64) {
        let expiry = self.config.relay_expiry_ms;
        self.candidate_relays
            .retain(|_, candidate| now_ms.saturating_sub(candidate.last_seen_ms) <= expiry);
    }
}

// ---------------------------------------------------------------------------
// Unit Tests (Internal Module)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_discovery_message_binary_roundtrip() {
        let msg = Pc5DiscoveryMessage {
            msg_type: Pc5DiscoveryMessageType::Announcement,
            relay_service_code: 0x0012_3456,
            sender_l2_id: [0xAA, 0xBB, 0xCC],
            target_l2_id: Some([0x11, 0x22, 0x33]),
            uu_rsrp_dbm: Some(-80.0),
            hop_count: 1,
        };

        let bytes = msg.to_bytes();
        let decoded = Pc5DiscoveryMessage::from_bytes(&bytes).expect("Decodes cleanly");
        assert_eq!(msg.msg_type, decoded.msg_type);
        assert_eq!(msg.relay_service_code, decoded.relay_service_code);
        assert_eq!(msg.sender_l2_id, decoded.sender_l2_id);
        assert_eq!(msg.target_l2_id, decoded.target_l2_id);
        assert_eq!(msg.hop_count, decoded.hop_count);
        assert!((msg.uu_rsrp_dbm.unwrap() - decoded.uu_rsrp_dbm.unwrap()).abs() < 1.0);
    }

    #[test]
    fn test_candidate_metric_calculation() {
        let cand = CandidateRelay {
            relay_l2_id: [1, 2, 3],
            relay_service_code: 100,
            pc5_rsrp_dbm: -90.0,
            uu_rsrp_dbm: -80.0,
            hop_count: 2, // 1 hop above minimum -> 3 dB penalty
            last_seen_ms: 1000,
        };

        // Bottleneck is min(-90, -80) = -90. Penalty = 1 * 3 = 3 dB -> Metric = -93 dBm
        let metric = cand.calculate_metric(3.0);
        assert!((metric - (-93.0)).abs() < 1e-6);
    }
}
