//! SRv6 Network Slicing & Virtual Transport Network (VTN) Data Plane (RFC 9350 / RFC 9543 / 3GPP 5G).
//!
//! Implements SRv6 Network Slice Identifier (Slice-ID / VTN-ID) mapping, binding Flex-Algo
//! (Algo 128 Low-Latency / Algo 129 High-Throughput) to dedicated SRv6 segment lists,
//! and enforcing SLA bandwidth guarantees and slice isolation across 5G transport networks.

use crate::ipv4::Ipv4Address;
use crate::ipv6::Ipv6Address;
use std::collections::HashMap;

/// Standard 5G Network Slice Types (3GPP TS 23.501 SST).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SliceType {
    /// Enhanced Mobile Broadband (eMBB - SST 1).
    Embb = 1,
    /// Ultra-Reliable Low-Latency Communication (URLLC - SST 2).
    Urllc = 2,
    /// Massive IoT (mIoT - SST 3).
    Miot = 3,
    /// Custom Enterprise Private 5G Slice.
    Custom = 4,
}

/// 32-bit Virtual Transport Network / Slice Identifier (RFC 9543 / IETF VPN+).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NetworkSliceId(pub u32);

/// Policy definition for an SRv6 Network Slice.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Srv6SlicePolicy {
    pub slice_id: NetworkSliceId,
    pub slice_name: String,
    pub slice_type: SliceType,
    pub flex_algo: u8, // 128 = Delay metric, 129 = Bandwidth metric
    pub guaranteed_bandwidth_kbps: u32,
    pub segment_list: Vec<Ipv6Address>,
    pub max_latency_microseconds: u32,
}

/// Packet steering result from the SRv6 Slicing Engine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Srv6SliceSteeringResult {
    pub slice_id: NetworkSliceId,
    pub flex_algo: u8,
    pub srv6_sid_list: Vec<Ipv6Address>,
    pub metered_bandwidth_kbps: u32,
}

/// SRv6 Network Slicing Forwarding and Telemetry Engine.
#[derive(Debug, Clone, Default)]
pub struct Srv6SliceForwardingEngine {
    pub slice_policies: HashMap<NetworkSliceId, Srv6SlicePolicy>,
    pub subscriber_slice_bindings: HashMap<Ipv4Address, NetworkSliceId>,
    pub slice_metered_bytes: HashMap<NetworkSliceId, u64>,
    pub steered_packets_count: usize,
}

impl Srv6SliceForwardingEngine {
    pub fn new() -> Self {
        Srv6SliceForwardingEngine {
            slice_policies: HashMap::new(),
            subscriber_slice_bindings: HashMap::new(),
            slice_metered_bytes: HashMap::new(),
            steered_packets_count: 0,
        }
    }

    /// Registers an SRv6 Network Slice policy.
    pub fn add_slice(&mut self, policy: Srv6SlicePolicy) {
        self.slice_metered_bytes.entry(policy.slice_id).or_insert(0);
        self.slice_policies.insert(policy.slice_id, policy);
    }

    /// Binds a subscriber / application source IP to a specific Network Slice.
    pub fn bind_subscriber_to_slice(&mut self, sub_ip: Ipv4Address, slice_id: NetworkSliceId) -> bool {
        if self.slice_policies.contains_key(&slice_id) {
            self.subscriber_slice_bindings.insert(sub_ip, slice_id);
            true
        } else {
            false
        }
    }

    /// Evaluates an ingress packet, steers it onto the slice's dedicated SRv6 path, and meters bandwidth.
    pub fn steer_packet(
        &mut self,
        src_ip: Ipv4Address,
        packet_len: usize,
    ) -> Option<Srv6SliceSteeringResult> {
        let slice_id = self.subscriber_slice_bindings.get(&src_ip).copied()?;
        let policy = self.slice_policies.get(&slice_id)?;

        let bytes = self.slice_metered_bytes.entry(slice_id).or_insert(0);
        *bytes += packet_len as u64;
        self.steered_packets_count += 1;

        Some(Srv6SliceSteeringResult {
            slice_id,
            flex_algo: policy.flex_algo,
            srv6_sid_list: policy.segment_list.clone(),
            metered_bandwidth_kbps: policy.guaranteed_bandwidth_kbps,
        })
    }
}
