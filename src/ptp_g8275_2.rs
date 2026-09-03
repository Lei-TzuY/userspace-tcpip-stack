//! ITU-T G.8275.2 / IEEE 1588-2019 Telecom Profile for Phase/Time Synchronization with Partial Timing Support (PTS).
//!
//! Implements G.8275.2 unicast negotiation, Alternate Best Master Clock Algorithm (BMCA),
//! asymmetry calibration, and T-TSC slave synchronization lifecycle:
//! - Dynamic Unicast Service Negotiation (IEEE 1588 Section 16.1 & G.8275.2 Section 6.5):
//!   - Lease request (`REQUEST_UNICAST_TRANSMISSION`) for Announce, Sync, and Delay_Resp
//!   - Lease grant (`GRANT_UNICAST_TRANSMISSION`) with rate policing and renewal timers
//!   - Graceful cancellation (`CANCEL_UNICAST_TRANSMISSION`) and lease expiration
//! - G.8275.2 Alternate BMCA (Section 6.7):
//!   - Clock comparison based on ClockClass, ClockAccuracy, OffsetScaledLogVariance, Priority2,
//!     LocalPriority, and StepsRemoved across multi-hop routed L3 paths
//! - Forward / Reverse Path Asymmetry Calibration:
//!   - Compensates for static L3 routing delay asymmetry (positive / negative offset correction)
//! - Telecom Time Slave Clock (T-TSC) State Machine (Section 6.4):
//!   - `FreeRun`, `Negotiating`, `Tracking`, `Locked`, `HoldoverInSpec`, `HoldoverOutOfSpec`
//!   - Compliant with ITU-T G.8271.2 5G TDD maximum phase error limit (1.5 microseconds)

use std::collections::HashMap;

use crate::ipv4::Ipv4Address;

// ---------------------------------------------------------------------------
// G.8275.2 Enums & Data Structures
// ---------------------------------------------------------------------------

/// PTP message types supported in G.8275.2 unicast transmission.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum G8275_2MessageType {
    Announce,
    Sync,
    DelayResp,
}

/// Unicast lease grant status.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnicastLease {
    pub message_type: G8275_2MessageType,
    pub log_inter_message_period: i8, // -7 (128 pps) to 1 (1 pkt per 2s)
    pub duration_s: u32,
    pub granted_at_epoch_s: u64,
    pub expires_at_epoch_s: u64,
}

/// Unicast service request from a slave (REQUEST_UNICAST_TRANSMISSION TLV).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnicastRequest {
    pub client_ip: Ipv4Address,
    pub message_type: G8275_2MessageType,
    pub requested_rate_log2: i8,
    pub requested_duration_s: u32,
}

/// Unicast service grant returned by master (GRANT_UNICAST_TRANSMISSION TLV).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnicastGrant {
    pub message_type: G8275_2MessageType,
    pub granted_rate_log2: i8,
    pub granted_duration_s: u32,
    pub renewal_invited: bool,
}

/// Candidate Grandmaster recorded in T-TSC slave dataset.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct G8275_2MasterCandidate {
    pub master_ip: Ipv4Address,
    pub clock_class: u8,
    pub clock_accuracy: u8,
    pub offset_scaled_log_variance: u16,
    pub priority2: u8,
    pub local_priority: u8, // 1..255 (lower = preferred in G.8275.2)
    pub steps_removed: u16,
    pub static_asymmetry_ns: i64, // Path delay asymmetry correction (+/- ns)
    pub active_leases: HashMap<G8275_2MessageType, UnicastLease>,
}

/// T-TSC Operational Synchronization State (ITU-T G.8275.2 Section 6.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum G8275_2SlaveState {
    FreeRun,
    Negotiating,
    Tracking,
    Locked,
    HoldoverInSpec,
    HoldoverOutOfSpec,
}

// ---------------------------------------------------------------------------
// G.8275.2 Unicast Master Engine (T-GM / Boundary Clock Port)
// ---------------------------------------------------------------------------

/// Unicast PTP Master Server negotiating leases with remote slaves over L3.
pub struct G8275_2MasterEngine {
    pub master_ip: Ipv4Address,
    pub min_log_rate: i8, // e.g. -7 (128 pps)
    pub max_log_rate: i8, // e.g. 1 (0.5 pps)
    pub max_duration_s: u32,
    /// Active leases: client_ip -> (message_type -> UnicastLease)
    pub client_leases: HashMap<Ipv4Address, HashMap<G8275_2MessageType, UnicastLease>>,
}

impl G8275_2MasterEngine {
    pub fn new(master_ip: Ipv4Address) -> Self {
        G8275_2MasterEngine {
            master_ip,
            min_log_rate: -7, // Up to 128 packets/second
            max_log_rate: 1,
            max_duration_s: 3600, // Maximum 1 hour lease
            client_leases: HashMap::new(),
        }
    }

    /// Process incoming unicast service request from remote slave.
    pub fn handle_unicast_request(
        &mut self,
        req: &UnicastRequest,
        now_s: u64,
    ) -> Result<UnicastGrant, &'static str> {
        // Enforce rate bounds
        let granted_rate = req
            .requested_rate_log2
            .clamp(self.min_log_rate, self.max_log_rate);

        // Enforce duration bounds
        let granted_duration = req.requested_duration_s.min(self.max_duration_s);
        if granted_duration == 0 {
            return Err("Requested duration must be non-zero");
        }

        let lease = UnicastLease {
            message_type: req.message_type,
            log_inter_message_period: granted_rate,
            duration_s: granted_duration,
            granted_at_epoch_s: now_s,
            expires_at_epoch_s: now_s + granted_duration as u64,
        };

        self.client_leases
            .entry(req.client_ip)
            .or_insert_with(HashMap::new)
            .insert(req.message_type, lease);

        Ok(UnicastGrant {
            message_type: req.message_type,
            granted_rate_log2: granted_rate,
            granted_duration_s: granted_duration,
            renewal_invited: true,
        })
    }

    /// Cancel active unicast transmission for a specific message type.
    pub fn cancel_unicast(&mut self, client_ip: Ipv4Address, msg_type: G8275_2MessageType) -> bool {
        if let Some(leases) = self.client_leases.get_mut(&client_ip) {
            let removed = leases.remove(&msg_type).is_some();
            if leases.is_empty() {
                self.client_leases.remove(&client_ip);
            }
            removed
        } else {
            false
        }
    }

    /// Purge expired leases.
    pub fn expire_leases(&mut self, now_s: u64) -> usize {
        let mut expired_count = 0;
        let mut empty_clients = Vec::new();

        for (client_ip, leases) in self.client_leases.iter_mut() {
            let before = leases.len();
            leases.retain(|_, lease| lease.expires_at_epoch_s > now_s);
            expired_count += before - leases.len();
            if leases.is_empty() {
                empty_clients.push(*client_ip);
            }
        }

        for ip in empty_clients {
            self.client_leases.remove(&ip);
        }

        expired_count
    }

    /// Count of currently active client IP endpoints.
    pub fn active_client_count(&self) -> usize {
        self.client_leases.len()
    }
}

// ---------------------------------------------------------------------------
// G.8275.2 Telecom Time Slave Clock (T-TSC) Engine
// ---------------------------------------------------------------------------

/// ITU-T G.8275.2 Telecom Time Slave Clock (T-TSC) Engine.
pub struct G8275_2SlaveEngine {
    pub slave_ip: Ipv4Address,
    pub candidates: HashMap<Ipv4Address, G8275_2MasterCandidate>,
    pub selected_master: Option<Ipv4Address>,
    pub state: G8275_2SlaveState,
    pub holdover_started_s: Option<u64>,
    pub max_holdover_in_spec_s: u64, // e.g. 7200s (2 hours)
}

impl G8275_2SlaveEngine {
    pub fn new(slave_ip: Ipv4Address) -> Self {
        G8275_2SlaveEngine {
            slave_ip,
            candidates: HashMap::new(),
            selected_master: None,
            state: G8275_2SlaveState::FreeRun,
            holdover_started_s: None,
            max_holdover_in_spec_s: 7200, // 2h holdover within 1.5us spec
        }
    }

    /// Add or update a candidate Grandmaster.
    pub fn add_or_update_candidate(&mut self, candidate: G8275_2MasterCandidate) {
        self.candidates.insert(candidate.master_ip, candidate);
    }

    /// Run ITU-T G.8275.2 Alternate BMCA across all active master candidates.
    ///
    /// Comparison order (Section 6.7):
    /// 1. ClockClass (lower = superior)
    /// 2. ClockAccuracy (lower = superior)
    /// 3. OffsetScaledLogVariance (lower = superior)
    /// 4. Priority2 (lower = superior)
    /// 5. LocalPriority (lower = superior)
    /// 6. StepsRemoved (lower = superior)
    /// 7. IP Address (tie-breaker)
    pub fn run_alternate_bmca(&mut self) -> Option<Ipv4Address> {
        let mut sorted: Vec<&G8275_2MasterCandidate> = self.candidates.values().collect();
        if sorted.is_empty() {
            self.selected_master = None;
            return None;
        }

        sorted.sort_by(|a, b| {
            a.clock_class
                .cmp(&b.clock_class)
                .then(a.clock_accuracy.cmp(&b.clock_accuracy))
                .then(
                    a.offset_scaled_log_variance
                        .cmp(&b.offset_scaled_log_variance),
                )
                .then(a.priority2.cmp(&b.priority2))
                .then(a.local_priority.cmp(&b.local_priority))
                .then(a.steps_removed.cmp(&b.steps_removed))
                .then(a.master_ip.to_u32().cmp(&b.master_ip.to_u32()))
        });

        let best_ip = sorted[0].master_ip;
        self.selected_master = Some(best_ip);

        // Advance state from FreeRun if not already tracking/locked
        if self.state == G8275_2SlaveState::FreeRun {
            self.state = G8275_2SlaveState::Negotiating;
        }

        Some(best_ip)
    }

    /// Apply static path delay asymmetry correction for the selected master.
    ///
    /// Corrected Offset = Measured Offset - Asymmetry / 2
    pub fn apply_asymmetry_correction(
        &self,
        measured_offset_ns: i64,
        master_ip: Ipv4Address,
    ) -> i64 {
        if let Some(candidate) = self.candidates.get(&master_ip) {
            measured_offset_ns - (candidate.static_asymmetry_ns / 2)
        } else {
            measured_offset_ns
        }
    }

    /// Update slave servo state based on current absolute time error (TE).
    ///
    /// 3GPP TS 38.104 / ITU-T G.8271.2: 5G TDD cell boundary limit = 1500 ns.
    pub fn update_servo_lock(&mut self, abs_te_ns: i64, is_signal_present: bool, now_s: u64) {
        if !is_signal_present {
            // Signal lost: transition to Holdover
            match self.state {
                G8275_2SlaveState::Locked | G8275_2SlaveState::Tracking => {
                    self.state = G8275_2SlaveState::HoldoverInSpec;
                    self.holdover_started_s = Some(now_s);
                }
                G8275_2SlaveState::HoldoverInSpec => {
                    if let Some(start) = self.holdover_started_s {
                        if now_s - start > self.max_holdover_in_spec_s {
                            self.state = G8275_2SlaveState::HoldoverOutOfSpec;
                        }
                    }
                }
                _ => {}
            }
            return;
        }

        // Signal present
        self.holdover_started_s = None;
        if abs_te_ns <= 1500 {
            self.state = G8275_2SlaveState::Locked;
        } else {
            self.state = G8275_2SlaveState::Tracking;
        }
    }
}
