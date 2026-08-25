//! EVPN Layer 2 Unknown Unicast (UU) Flood Suppression & Storm Reduction (RFC 7432 Section 13.2 / RFC 8317).
//!
//! Implements Unknown Unicast (UU) frame suppression on EVPN bridge domains / VNIs to prevent
//! network-wide broadcast/multicast storms. Gated against local MAC learning and remote
//! BGP EVPN Route Type 2 MAC/IP Advertisement tables.

use crate::ethernet::MacAddress;
use std::collections::{HashMap, HashSet};

/// EVPN Unknown Unicast Suppression Decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UuSuppressionDecision {
    ForwardKnownUnicast,
    SuppressedUnknownUnicast,
    ForwardFloodingAllowed,
}

/// EVPN Unknown Unicast Suppression Engine.
#[derive(Debug, Clone, Default)]
pub struct EvpnUuSuppressionEngine {
    pub known_mac_table: HashSet<(u32, MacAddress)>, // (VNI, MAC)
    pub vni_suppression_enabled: HashMap<u32, bool>, // VNI -> Suppression Active
    pub allowed_packets_count: usize,
    pub suppressed_packets_count: usize,
}

impl EvpnUuSuppressionEngine {
    pub fn new() -> Self {
        EvpnUuSuppressionEngine {
            known_mac_table: HashSet::new(),
            vni_suppression_enabled: HashMap::new(),
            allowed_packets_count: 0,
            suppressed_packets_count: 0,
        }
    }

    /// Configures Unknown Unicast Suppression policy for a specific VNI.
    pub fn set_vni_suppression(&mut self, vni: u32, enabled: bool) {
        self.vni_suppression_enabled.insert(vni, enabled);
    }

    /// Learns or syncs a known MAC in a VNI (from local learning or remote EVPN Route Type 2).
    pub fn add_known_mac(&mut self, vni: u32, mac: MacAddress) {
        self.known_mac_table.insert((vni, mac));
    }

    /// Withdraws a MAC from the known table.
    pub fn remove_known_mac(&mut self, vni: u32, mac: MacAddress) {
        self.known_mac_table.remove(&(vni, mac));
    }

    /// Evaluates an incoming unicast frame against the UU suppression policy.
    pub fn evaluate_frame(&mut self, vni: u32, dst_mac: MacAddress) -> UuSuppressionDecision {
        let is_suppression_active = self
            .vni_suppression_enabled
            .get(&vni)
            .copied()
            .unwrap_or(true);

        if self.known_mac_table.contains(&(vni, dst_mac)) {
            self.allowed_packets_count += 1;
            UuSuppressionDecision::ForwardKnownUnicast
        } else if is_suppression_active {
            self.suppressed_packets_count += 1;
            UuSuppressionDecision::SuppressedUnknownUnicast
        } else {
            self.allowed_packets_count += 1;
            UuSuppressionDecision::ForwardFloodingAllowed
        }
    }
}
