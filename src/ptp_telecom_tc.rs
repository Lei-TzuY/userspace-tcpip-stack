//! PTP Telecom Profile Peer-to-Peer & End-to-End Transparent Clock (T-TC) Engine (ITU-T G.8275.1 / G.8275.2 / IEEE 1588).
//!
//! Implements P2P Peer Delay calculation (Pdelay_Req/Pdelay_Resp timestamps t1, t2, t3, t4),
//! ingress-to-egress residence time computation, sub-nanosecond 16-bit fractional correctionField
//! representation (units of 2^-16 ns), link latency asymmetry compensation, and direct in-place
//! PtpHeader correction for telecom fronthaul and packet networks.

use crate::ptp::PtpHeader;
use std::collections::HashMap;

/// Scale factor for PTP correctionField in units of 2^-16 nanoseconds (IEEE 1588-2008 Section 13.3.2.7).
pub const PTP_SUB_NS_SCALE: i64 = 65536; // 2^16

/// Transparent Clock Operating Mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TelecomTcMode {
    #[default]
    PeerToPeer, // P2P TC: includes residence time + ingress peer link delay
    EndToEnd, // E2E TC: includes residence time only
}

/// PTP Telecom Transparent Clock (T-TC) Engine.
#[derive(Debug, Clone)]
pub struct TelecomPeerTransparentClockEngine {
    pub mode: TelecomTcMode,
    pub peer_delays_ns: HashMap<u32, i64>, // Port ID -> Link Peer Mean Delay in nanoseconds
    pub port_asymmetry_ns: HashMap<u32, i64>, // Port ID -> Path delay asymmetry (+/- ns)
    pub neighbor_rate_ratios: HashMap<u32, f64>, // Port ID -> Frequency ratio of neighbor to local
    pub corrections_performed: usize,
    pub accumulated_correction_ns: i64,
}

impl Default for TelecomPeerTransparentClockEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl TelecomPeerTransparentClockEngine {
    pub fn new() -> Self {
        TelecomPeerTransparentClockEngine {
            mode: TelecomTcMode::PeerToPeer,
            peer_delays_ns: HashMap::new(),
            port_asymmetry_ns: HashMap::new(),
            neighbor_rate_ratios: HashMap::new(),
            corrections_performed: 0,
            accumulated_correction_ns: 0,
        }
    }

    pub fn with_mode(mut self, mode: TelecomTcMode) -> Self {
        self.mode = mode;
        self
    }

    /// Sets the operating mode (P2P vs E2E).
    pub fn set_mode(&mut self, mode: TelecomTcMode) {
        self.mode = mode;
    }

    /// Sets the physical link delay asymmetry for a port.
    pub fn set_port_asymmetry(&mut self, port_id: u32, asymmetry_ns: i64) {
        self.port_asymmetry_ns.insert(port_id, asymmetry_ns);
    }

    /// Sets the neighbor frequency rate ratio (neighborRateRatio) for a port.
    pub fn set_neighbor_rate_ratio(&mut self, port_id: u32, ratio: f64) {
        self.neighbor_rate_ratios.insert(port_id, ratio);
    }

    /// Converts fractional nanoseconds to standard IEEE 1588 scaled correctionField units (2^-16 ns).
    pub fn to_scaled_nanoseconds(ns: f64) -> i64 {
        (ns * PTP_SUB_NS_SCALE as f64).round() as i64
    }

    /// Converts IEEE 1588 scaled correctionField units (2^-16 ns) back to nanoseconds.
    pub fn from_scaled_nanoseconds(scaled: i64) -> f64 {
        scaled as f64 / PTP_SUB_NS_SCALE as f64
    }

    /// Computes the peer mean path delay using IEEE 1588 P2P formula:
    /// Delay = ((t4 - t1) - (t3 - t2)) / 2
    pub fn compute_peer_delay(&self, t1_ns: i64, t2_ns: i64, t3_ns: i64, t4_ns: i64) -> i64 {
        let round_trip = t4_ns - t1_ns;
        let peer_turnaround = t3_ns - t2_ns;
        (round_trip - peer_turnaround) / 2
    }

    /// Computes peer delay adjusted by the measured neighbor rate ratio:
    /// Delay = ((t4 - t1) - (t3 - t2) * neighborRateRatio) / 2
    pub fn compute_peer_delay_with_ratio(
        &self,
        t1_ns: i64,
        t2_ns: i64,
        t3_ns: i64,
        t4_ns: i64,
        rate_ratio: f64,
    ) -> i64 {
        let round_trip = (t4_ns - t1_ns) as f64;
        let peer_turnaround = (t3_ns - t2_ns) as f64 * rate_ratio;
        ((round_trip - peer_turnaround) / 2.0).round() as i64
    }

    /// Updates the measured peer delay for a specific port.
    pub fn set_port_peer_delay(&mut self, port_id: u32, delay_ns: i64) {
        self.peer_delays_ns.insert(port_id, delay_ns);
    }

    /// Computes and applies residence time + ingress link peer delay correction in integer nanoseconds.
    pub fn correct_event_packet(
        &mut self,
        ingress_port: u32,
        ingress_time_ns: i64,
        egress_time_ns: i64,
        initial_correction_ns: i64,
    ) -> i64 {
        let residence_time = egress_time_ns.saturating_sub(ingress_time_ns);
        let peer_delay = if self.mode == TelecomTcMode::PeerToPeer {
            self.peer_delays_ns.get(&ingress_port).copied().unwrap_or(0)
        } else {
            0
        };
        let asym = self
            .port_asymmetry_ns
            .get(&ingress_port)
            .copied()
            .unwrap_or(0);

        let delta = residence_time + peer_delay + asym;
        self.corrections_performed += 1;
        self.accumulated_correction_ns += delta;
        initial_correction_ns + delta
    }

    /// Computes and applies residence time + link delay in sub-nanosecond scaled units (units of 2^-16 ns).
    pub fn correct_event_packet_scaled(
        &mut self,
        ingress_port: u32,
        ingress_time_ns: i64,
        egress_time_ns: i64,
        initial_correction_scaled: i64,
    ) -> i64 {
        let residence_time = egress_time_ns.saturating_sub(ingress_time_ns);
        let peer_delay = if self.mode == TelecomTcMode::PeerToPeer {
            self.peer_delays_ns.get(&ingress_port).copied().unwrap_or(0)
        } else {
            0
        };
        let asym = self
            .port_asymmetry_ns
            .get(&ingress_port)
            .copied()
            .unwrap_or(0);

        let delta_ns = residence_time + peer_delay + asym;
        let delta_scaled = delta_ns.saturating_mul(PTP_SUB_NS_SCALE);

        self.corrections_performed += 1;
        self.accumulated_correction_ns += delta_ns;
        initial_correction_scaled.saturating_add(delta_scaled)
    }

    /// Corrects a PTP message header in place using sub-nanosecond IEEE 1588 units.
    pub fn correct_ptp_header(
        &mut self,
        header: &mut PtpHeader,
        ingress_port: u32,
        ingress_time_ns: i64,
        egress_time_ns: i64,
    ) {
        header.correction_field = self.correct_event_packet_scaled(
            ingress_port,
            ingress_time_ns,
            egress_time_ns,
            header.correction_field,
        );
    }
}
