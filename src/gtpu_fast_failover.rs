//! 3GPP TS 23.501 — 5G GTP-U Path Loss Detection & Sub-Millisecond Fast Failover Route Selection.
//!
//! In Ultra-Reliable Low-Latency Communication (URLLC) and industrial 5G,
//! user plane packet forwarding cannot tolerate control plane signaling delays
//! when an N3 or N9 GTP-U path degrades or fails.
//!
//! This module implements:
//! * Primary and Secondary (Backup) GTP-U path pre-provisioning per PDU Session.
//! * Autonomous fast path health monitoring with configurable consecutive loss thresholds.
//! * Sub-millisecond data plane switchover to secondary UPF upon path loss.
//! * Auto-reversion to primary path upon validated heartbeat restoration.

use crate::ipv4::Ipv4Address;
use std::collections::HashMap;

/// Active Forwarding Path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActivePath {
    Primary,
    Secondary,
}

/// A GTP-U Endpoint Path descriptor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GtpuPathEndpoint {
    pub upf_ip: Ipv4Address,
    pub teid: u32,
    pub is_alive: bool,
    pub consecutive_failures: u32,
}

/// Fast Failover Session Configuration.
#[derive(Debug, Clone)]
pub struct FastFailoverSession {
    pub session_id: u32,
    pub primary_path: GtpuPathEndpoint,
    pub secondary_path: GtpuPathEndpoint,
    pub active_path: ActivePath,
    pub failure_threshold: u32,
    pub total_failovers: u64,
    pub total_reversions: u64,
}

impl FastFailoverSession {
    pub fn new(
        session_id: u32,
        primary_ip: Ipv4Address,
        primary_teid: u32,
        secondary_ip: Ipv4Address,
        secondary_teid: u32,
        failure_threshold: u32,
    ) -> Self {
        FastFailoverSession {
            session_id,
            primary_path: GtpuPathEndpoint {
                upf_ip: primary_ip,
                teid: primary_teid,
                is_alive: true,
                consecutive_failures: 0,
            },
            secondary_path: GtpuPathEndpoint {
                upf_ip: secondary_ip,
                teid: secondary_teid,
                is_alive: true,
                consecutive_failures: 0,
            },
            active_path: ActivePath::Primary,
            failure_threshold,
            total_failovers: 0,
            total_reversions: 0,
        }
    }

    /// Reports a heartbeat result for the primary path.
    pub fn report_primary_heartbeat(&mut self, success: bool) -> ActivePath {
        if success {
            self.primary_path.consecutive_failures = 0;
            self.primary_path.is_alive = true;
            if self.active_path == ActivePath::Secondary {
                // Auto-revert to primary path!
                self.active_path = ActivePath::Primary;
                self.total_reversions += 1;
            }
        } else {
            self.primary_path.consecutive_failures += 1;
            if self.primary_path.consecutive_failures >= self.failure_threshold {
                self.primary_path.is_alive = false;
                if self.active_path == ActivePath::Primary && self.secondary_path.is_alive {
                    // Autonomous fast failover to secondary path!
                    self.active_path = ActivePath::Secondary;
                    self.total_failovers += 1;
                }
            }
        }

        self.active_path
    }

    /// Gets the current active GTP-U forwarding target (IP and TEID).
    pub fn get_active_target(&self) -> (Ipv4Address, u32) {
        match self.active_path {
            ActivePath::Primary => (self.primary_path.upf_ip, self.primary_path.teid),
            ActivePath::Secondary => (self.secondary_path.upf_ip, self.secondary_path.teid),
        }
    }
}

/// 5G GTP-U User Plane Fast Failover Engine.
#[derive(Debug, Clone)]
pub struct GtpuFastFailoverEngine {
    pub sessions: HashMap<u32, FastFailoverSession>,
    pub total_forwarded_packets: u64,
}

impl GtpuFastFailoverEngine {
    pub fn new() -> Self {
        GtpuFastFailoverEngine {
            sessions: HashMap::new(),
            total_forwarded_packets: 0,
        }
    }

    pub fn add_session(&mut self, session: FastFailoverSession) {
        self.sessions.insert(session.session_id, session);
    }

    /// Selects the current active GTP-U forwarding target for an outgoing user plane packet.
    pub fn forward_user_plane(
        &mut self,
        session_id: u32,
    ) -> Option<(Ipv4Address, u32, ActivePath)> {
        let sess = self.sessions.get_mut(&session_id)?;
        let (ip, teid) = sess.get_active_target();
        let path = sess.active_path;
        self.total_forwarded_packets += 1;
        Some((ip, teid, path))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gtpu_fast_failover_and_reversion() {
        let mut engine = GtpuFastFailoverEngine::new();
        let session = FastFailoverSession::new(
            101,
            Ipv4Address::new(10, 1, 1, 10), // Primary UPF
            0x1111AAAA,
            Ipv4Address::new(10, 2, 2, 20), // Secondary Backup UPF
            0x2222BBBB,
            2, // 2 heartbeat losses -> switch
        );
        engine.add_session(session);

        // Initial forwarding -> Primary UPF
        let (ip1, teid1, path1) = engine.forward_user_plane(101).unwrap();
        assert_eq!(ip1, Ipv4Address::new(10, 1, 1, 10));
        assert_eq!(teid1, 0x1111AAAA);
        assert_eq!(path1, ActivePath::Primary);

        // Heartbeat failure 1 on primary
        let sess = engine.sessions.get_mut(&101).unwrap();
        sess.report_primary_heartbeat(false);
        assert_eq!(sess.active_path, ActivePath::Primary);

        // Heartbeat failure 2 on primary -> threshold reached -> Autonomous Failover to Secondary!
        sess.report_primary_heartbeat(false);
        assert_eq!(sess.active_path, ActivePath::Secondary);
        assert_eq!(sess.total_failovers, 1);

        // Next forwarded packet goes to Secondary UPF immediately!
        let (ip2, teid2, path2) = engine.forward_user_plane(101).unwrap();
        assert_eq!(ip2, Ipv4Address::new(10, 2, 2, 20));
        assert_eq!(teid2, 0x2222BBBB);
        assert_eq!(path2, ActivePath::Secondary);

        // Primary path recovers
        let sess = engine.sessions.get_mut(&101).unwrap();
        sess.report_primary_heartbeat(true);
        assert_eq!(sess.active_path, ActivePath::Primary);
        assert_eq!(sess.total_reversions, 1);
    }
}
