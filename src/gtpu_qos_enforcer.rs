//! 3GPP TS 38.415 / TS 23.501 — 5G GTP-U QoS Flow Identifier (QFI) Enforcement & Session-AMBR Rate Limiter.
//!
//! In 5G Service-Based Architecture, user plane traffic is categorized into
//! QoS Flows identified by a 6-bit QoS Flow Identifier (QFI, 1..64).
//!
//! The UPF enforces:
//! 1. **5QI QoS Characteristics**: Priority Level, Packet Delay Budget (PDB), Packet Error Rate (PER).
//! 2. **Session-AMBR (Aggregate Maximum Bit Rate)**: Token bucket policing across all Non-GBR flows within a PDU session.
//! 3. **Dynamic QFI Remapping**: Adjusts outer GTP-U PDU Session Container extension headers
//!    during network congestion or dynamic policy updates from SMF/PCF.
//!
//! This module implements:
//! * 6-bit QFI classification and 5QI profile table.
//! * Session-AMBR token bucket rate enforcement.
//! * Dynamic QFI remapping pipeline.

use std::collections::HashMap;

/// 5G QoS Resource Type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FiveQiResourceType {
    NonGbr,
    Gbr,
    DelayCriticalGbr,
}

/// 5G QoS Profile parameters (5QI 1..9, 65..86).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FiveQiProfile {
    pub five_qi: u8,
    pub resource_type: FiveQiResourceType,
    pub priority_level: u8,
    pub packet_delay_budget_ms: u32,
}

/// QoS Enforcer Action Verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QosVerdict {
    Pass { qfi: u8 },
    Remapped { old_qfi: u8, new_qfi: u8 },
    DropAmbrExceeded,
}

/// 5G GTP-U PDU Session QoS & AMBR Enforcer.
#[derive(Debug, Clone)]
pub struct GtpuQosEnforcer {
    pub session_id: u32,
    /// Session-AMBR in bytes per second.
    pub session_ambr_bps: u64,
    pub burst_capacity_bytes: u64,
    pub current_tokens: u64,
    pub last_refill_ns: u64,
    /// QFI mapping rules: incoming QFI -> target QFI
    pub qfi_remap_rules: HashMap<u8, u8>,
    /// Configured 5QI profiles: QFI -> FiveQiProfile
    pub qfi_profiles: HashMap<u8, FiveQiProfile>,
    pub total_conformed_bytes: u64,
    pub total_ambr_dropped_bytes: u64,
    pub total_remapped_packets: u64,
}

impl GtpuQosEnforcer {
    pub fn new(session_id: u32, session_ambr_bps: u64, burst_bytes: u64) -> Self {
        GtpuQosEnforcer {
            session_id,
            session_ambr_bps,
            burst_capacity_bytes: burst_bytes,
            current_tokens: burst_bytes,
            last_refill_ns: 0,
            qfi_remap_rules: HashMap::new(),
            qfi_profiles: HashMap::new(),
            total_conformed_bytes: 0,
            total_ambr_dropped_bytes: 0,
            total_remapped_packets: 0,
        }
    }

    pub fn register_qfi(&mut self, qfi: u8, five_qi: u8, resource_type: FiveQiResourceType, priority: u8, pdb_ms: u32) {
        self.qfi_profiles.insert(qfi, FiveQiProfile {
            five_qi,
            resource_type,
            priority_level: priority,
            packet_delay_budget_ms: pdb_ms,
        });
    }

    pub fn set_qfi_remap(&mut self, from_qfi: u8, to_qfi: u8) {
        self.qfi_remap_rules.insert(from_qfi, to_qfi);
    }

    /// Evaluates an outgoing GTP-U PDU session packet against QoS profiles and Session-AMBR.
    pub fn enforce_packet(&mut self, qfi: u8, packet_bytes: usize, now_ns: u64) -> QosVerdict {
        let is_non_gbr = self.qfi_profiles.get(&qfi)
            .map(|p| p.resource_type == FiveQiResourceType::NonGbr)
            .unwrap_or(true);

        // 1. Enforce Session-AMBR for Non-GBR flows
        if is_non_gbr {
            if self.last_refill_ns == 0 {
                self.last_refill_ns = now_ns;
            }

            let elapsed_ns = now_ns.saturating_sub(self.last_refill_ns);
            let refill_tokens = (elapsed_ns * self.session_ambr_bps) / 1_000_000_000;
            if refill_tokens > 0 {
                self.current_tokens = (self.current_tokens + refill_tokens).min(self.burst_capacity_bytes);
                self.last_refill_ns = now_ns;
            }

            let needed = packet_bytes as u64;
            if self.current_tokens < needed {
                self.total_ambr_dropped_bytes += needed;
                return QosVerdict::DropAmbrExceeded;
            }
            self.current_tokens -= needed;
        }

        self.total_conformed_bytes += packet_bytes as u64;

        // 2. Check dynamic QFI remapping
        if let Some(&new_qfi) = self.qfi_remap_rules.get(&qfi) {
            self.total_remapped_packets += 1;
            QosVerdict::Remapped { old_qfi: qfi, new_qfi }
        } else {
            QosVerdict::Pass { qfi }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gtpu_qos_ambr_and_remapping() {
        let mut enforcer = GtpuQosEnforcer::new(100, 10_000_000, 2000); // 10 MB/s, 2000B burst

        // QFI 1: Non-GBR (5QI 9 - Default Internet)
        enforcer.register_qfi(1, 9, FiveQiResourceType::NonGbr, 9, 300);
        // QFI 2: DelayCriticalGBR (5QI 82 - Mission Critical Video)
        enforcer.register_qfi(2, 82, FiveQiResourceType::DelayCriticalGbr, 2, 10);

        // Frame 1 on QFI 1 (1500B at t=0) -> Pass (2000 - 1500 = 500B tokens left)
        assert_eq!(enforcer.enforce_packet(1, 1500, 0), QosVerdict::Pass { qfi: 1 });

        // Frame 2 on QFI 1 (1000B at t=0) -> Exceeds 500B -> DropAmbrExceeded
        assert_eq!(enforcer.enforce_packet(1, 1000, 0), QosVerdict::DropAmbrExceeded);

        // Frame 3 on QFI 2 (GBR bypasses Session-AMBR!) -> Pass
        assert_eq!(enforcer.enforce_packet(2, 1500, 0), QosVerdict::Pass { qfi: 2 });

        // Set Remapping rule: QFI 1 -> QFI 3
        enforcer.set_qfi_remap(1, 3);
        // Advance time by 1 second to replenish tokens
        assert_eq!(
            enforcer.enforce_packet(1, 500, 1_000_000_000),
            QosVerdict::Remapped { old_qfi: 1, new_qfi: 3 }
        );
    }
}
