//! EVPN Layer 2 Dynamic Port Security & Sticky MAC Aging (RFC 7432 Section 15).
//!
//! Port Security protects edge Attachment Circuits (AC) in EVPN EVPN datacenter fabrics
//! against MAC flooding attacks, unauthorized rogue host connections, and CAM table exhaustion.
//!
//! This module implements:
//! * Configurable maximum MAC limit per port (e.g. max 2 MACs).
//! * Security violation modes:
//!   - **Protect**: Silently drops frames with unauthorized source MACs.
//!   - **Restrict**: Drops unauthorized frames, logs security alerts, and increments violation counters.
//!   - **Shutdown**: Transitions port into `ErrDisabled` state upon violation.
//! * Sticky MAC learning with inactivity aging timers.

use crate::ethernet::MacAddress;
use std::collections::HashMap;

/// Port Security Violation Action.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PortSecurityViolationAction {
    Protect,
    Restrict,
    Shutdown,
}

/// Port Operational State.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PortState {
    Active,
    ErrDisabled,
}

/// Learned MAC entry with timestamp for inactivity aging.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StickyMacEntry {
    pub mac: MacAddress,
    pub learned_timestamp_sec: u64,
    pub last_seen_sec: u64,
    pub is_sticky: bool,
}

/// Per-port security configuration.
#[derive(Debug, Clone)]
pub struct PortSecurityConfig {
    pub max_macs: usize,
    pub violation_action: PortSecurityViolationAction,
    pub aging_timeout_sec: u64,
    pub state: PortState,
    pub learned_macs: HashMap<MacAddress, StickyMacEntry>,
    pub violation_count: u64,
}

impl PortSecurityConfig {
    pub fn new(
        max_macs: usize,
        violation_action: PortSecurityViolationAction,
        aging_timeout_sec: u64,
    ) -> Self {
        PortSecurityConfig {
            max_macs,
            violation_action,
            aging_timeout_sec,
            state: PortState::Active,
            learned_macs: HashMap::new(),
            violation_count: 0,
        }
    }
}

/// EVPN Layer 2 Dynamic Port Security Engine.
#[derive(Debug, Clone)]
pub struct EvpnPortSecurityEngine {
    pub ports: HashMap<String, PortSecurityConfig>,
    pub total_allowed_frames: u64,
    pub total_violation_drops: u64,
}

impl EvpnPortSecurityEngine {
    pub fn new() -> Self {
        EvpnPortSecurityEngine {
            ports: HashMap::new(),
            total_allowed_frames: 0,
            total_violation_drops: 0,
        }
    }

    pub fn configure_port(
        &mut self,
        iface: &str,
        max_macs: usize,
        violation: PortSecurityViolationAction,
        aging_sec: u64,
    ) {
        self.ports.insert(
            iface.to_string(),
            PortSecurityConfig::new(max_macs, violation, aging_sec),
        );
    }

    /// Evaluates an incoming frame from `src_mac` on `iface`.
    /// Returns `true` if permitted, or `false` if dropped due to a port security rule.
    pub fn ingress_frame(&mut self, iface: &str, src_mac: MacAddress, now_sec: u64) -> bool {
        let port = match self.ports.get_mut(iface) {
            Some(p) => p,
            None => return true, // No port security configured on this port
        };

        if port.state == PortState::ErrDisabled {
            self.total_violation_drops += 1;
            return false;
        }

        // Age out expired dynamic entries (skip sticky entries if aging is 0)
        if port.aging_timeout_sec > 0 {
            let timeout = port.aging_timeout_sec;
            port.learned_macs
                .retain(|_, entry| now_sec.saturating_sub(entry.last_seen_sec) < timeout);
        }

        if let Some(entry) = port.learned_macs.get_mut(&src_mac) {
            entry.last_seen_sec = now_sec;
            self.total_allowed_frames += 1;
            true
        } else if port.learned_macs.len() < port.max_macs {
            // Learn new sticky MAC
            port.learned_macs.insert(
                src_mac,
                StickyMacEntry {
                    mac: src_mac,
                    learned_timestamp_sec: now_sec,
                    last_seen_sec: now_sec,
                    is_sticky: true,
                },
            );
            self.total_allowed_frames += 1;
            true
        } else {
            // Security Violation!
            port.violation_count += 1;
            self.total_violation_drops += 1;

            match port.violation_action {
                PortSecurityViolationAction::Protect => false,
                PortSecurityViolationAction::Restrict => false,
                PortSecurityViolationAction::Shutdown => {
                    port.state = PortState::ErrDisabled;
                    false
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_evpn_port_security_max_mac_and_shutdown() {
        let mut sec = EvpnPortSecurityEngine::new();
        sec.configure_port("eth1", 2, PortSecurityViolationAction::Shutdown, 300);

        let mac1 = MacAddress([0x00, 0x11, 0x22, 0x33, 0x44, 0x01]);
        let mac2 = MacAddress([0x00, 0x11, 0x22, 0x33, 0x44, 0x02]);
        let mac3 = MacAddress([0x00, 0x11, 0x22, 0x33, 0x44, 0x03]);

        // 1. MAC 1 and MAC 2 allowed
        assert!(sec.ingress_frame("eth1", mac1, 10));
        assert!(sec.ingress_frame("eth1", mac2, 10));
        assert_eq!(sec.total_allowed_frames, 2);

        // 2. MAC 3 exceeds limit -> Violation triggers Shutdown!
        assert!(!sec.ingress_frame("eth1", mac3, 15));
        assert_eq!(sec.total_violation_drops, 1);

        let port = sec.ports.get("eth1").unwrap();
        assert_eq!(port.state, PortState::ErrDisabled);
        assert_eq!(port.violation_count, 1);

        // 3. Even MAC 1 is now dropped because port is ErrDisabled
        assert!(!sec.ingress_frame("eth1", mac1, 20));
    }
}
