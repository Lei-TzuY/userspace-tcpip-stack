// =============================================================================
// 3GPP TS 29.281 / RFC 8684 5G GTP-U Multi-Link Flow Distribution & Aggregation
// =============================================================================
//
// In multi-connectivity 5G deployments (Dual Connectivity, ATSSS, and Multi-Path
// transport), the UPF distributes flows across multiple underlying transport
// tunnels (e.g. 3GPP 5G-NR leg, Wi-Fi leg, Satellite NTN leg).
//
// Features:
//   1. 5-Tuple Flow Hashing: Computes deterministic hash from (src_ip, dst_ip,
//      src_port, dst_port, proto) to pin micro-flows to a specific transport link,
//      preventing TCP packet reordering.
//   2. Link Health & Weight Management: Supports link states (Active, Degraded,
//      Down) and weighted load allocation.
//   3. Dynamic Resilient Failover: Re-hashes flows away from failed links onto
//      surviving healthy links.
//
// Pure safe Rust, zero external crates.

use crate::ipv4::Ipv4Address;

/// Health status of a physical transport link.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkHealthState {
    Active,
    Degraded,
    Down,
}

/// Profile for a transport link in the aggregation group.
#[derive(Debug, Clone)]
pub struct AggregatedLink {
    pub link_id: u32,
    pub name: String,
    pub weight: u32,
    pub status: LinkHealthState,
    pub local_teid: u32,
    pub peer_ip: Ipv4Address,
    pub total_packets_forwarded: u64,
    pub total_bytes_forwarded: u64,
}

impl AggregatedLink {
    pub fn new(
        link_id: u32,
        name: &str,
        weight: u32,
        local_teid: u32,
        peer_ip: Ipv4Address,
    ) -> Self {
        Self {
            link_id,
            name: name.to_string(),
            weight: weight.max(1),
            status: LinkHealthState::Active,
            local_teid,
            peer_ip,
            total_packets_forwarded: 0,
            total_bytes_forwarded: 0,
        }
    }
}

/// 5-Tuple flow identifier for hashing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FiveTuple {
    pub src_ip: Ipv4Address,
    pub dst_ip: Ipv4Address,
    pub src_port: u16,
    pub dst_port: u16,
    pub proto: u8,
}

impl FiveTuple {
    /// Compute a fast 32-bit hash using FNV-1a.
    pub fn hash_fnv1a(&self) -> u32 {
        let mut hash: u32 = 0x811c9dc5;
        let prime: u32 = 0x01000193;

        for b in &self.src_ip.0 {
            hash ^= *b as u32;
            hash = hash.wrapping_mul(prime);
        }
        for b in &self.dst_ip.0 {
            hash ^= *b as u32;
            hash = hash.wrapping_mul(prime);
        }
        hash ^= (self.src_port >> 8) as u32;
        hash = hash.wrapping_mul(prime);
        hash ^= (self.src_port & 0xFF) as u32;
        hash = hash.wrapping_mul(prime);
        hash ^= (self.dst_port >> 8) as u32;
        hash = hash.wrapping_mul(prime);
        hash ^= (self.dst_port & 0xFF) as u32;
        hash = hash.wrapping_mul(prime);
        hash ^= self.proto as u32;
        hash = hash.wrapping_mul(prime);

        hash
    }
}

/// Result of flow forwarding lookup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FlowDistributionResult {
    Forward {
        link_id: u32,
        local_teid: u32,
        peer_ip: Ipv4Address,
    },
    AllLinksDown,
}

/// 5G GTP-U Multi-Link Flow Aggregation & Distribution Engine.
pub struct GtpuLinkAggEngine {
    pub group_id: u32,
    pub links: Vec<AggregatedLink>,
    pub total_dispatched: u64,
    pub total_dropped: u64,
}

impl GtpuLinkAggEngine {
    pub fn new(group_id: u32) -> Self {
        Self {
            group_id,
            links: Vec::new(),
            total_dispatched: 0,
            total_dropped: 0,
        }
    }

    /// Add or update a link.
    pub fn add_link(&mut self, link: AggregatedLink) {
        if let Some(pos) = self.links.iter().position(|l| l.link_id == link.link_id) {
            self.links[pos] = link;
        } else {
            self.links.push(link);
        }
    }

    /// Set health state for a link.
    pub fn set_link_status(&mut self, link_id: u32, status: LinkHealthState) {
        if let Some(l) = self.links.iter_mut().find(|l| l.link_id == link_id) {
            l.status = status;
        }
    }

    /// Dispatch a packet based on 5-tuple hash.
    pub fn dispatch_packet(
        &mut self,
        tuple: &FiveTuple,
        payload_bytes: usize,
    ) -> FlowDistributionResult {
        // Collect healthy (Active or Degraded) links
        let healthy_indices: Vec<usize> = self
            .links
            .iter()
            .enumerate()
            .filter(|(_, l)| l.status != LinkHealthState::Down)
            .map(|(idx, _)| idx)
            .collect();

        if healthy_indices.is_empty() {
            self.total_dropped += 1;
            return FlowDistributionResult::AllLinksDown;
        }

        let total_weight: u32 = healthy_indices
            .iter()
            .map(|&idx| self.links[idx].weight)
            .sum();
        if total_weight == 0 {
            self.total_dropped += 1;
            return FlowDistributionResult::AllLinksDown;
        }

        let hash = tuple.hash_fnv1a();
        let target_slot = hash % total_weight;

        let mut cumulative = 0;
        let mut chosen_idx = healthy_indices[0];
        for &idx in &healthy_indices {
            cumulative += self.links[idx].weight;
            if target_slot < cumulative {
                chosen_idx = idx;
                break;
            }
        }

        let link = &mut self.links[chosen_idx];
        link.total_packets_forwarded += 1;
        link.total_bytes_forwarded += payload_bytes as u64;
        self.total_dispatched += 1;

        FlowDistributionResult::Forward {
            link_id: link.link_id,
            local_teid: link.local_teid,
            peer_ip: link.peer_ip,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gtpu_multi_link_flow_aggregation() {
        let mut agg = GtpuLinkAggEngine::new(1);

        let link1 = AggregatedLink::new(
            1,
            "5G-NR-Primary",
            3,
            0x1001,
            Ipv4Address::new(192, 168, 1, 10),
        );
        let link2 = AggregatedLink::new(
            2,
            "Wi-Fi-6-Secondary",
            1,
            0x2002,
            Ipv4Address::new(192, 168, 2, 20),
        );
        agg.add_link(link1);
        agg.add_link(link2);

        let flow_a = FiveTuple {
            src_ip: Ipv4Address::new(10, 1, 1, 5),
            dst_ip: Ipv4Address::new(93, 184, 216, 34),
            src_port: 54321,
            dst_port: 443,
            proto: 6, // TCP
        };

        // 1. Same flow always hashes to the same link (flow pinning)
        let res1 = agg.dispatch_packet(&flow_a, 1400);
        let res2 = agg.dispatch_packet(&flow_a, 1400);
        assert_eq!(res1, res2);

        // 2. Mark primary link Down -> automatic failover to Wi-Fi link
        if let FlowDistributionResult::Forward { link_id, .. } = res1 {
            agg.set_link_status(link_id, LinkHealthState::Down);
            let res3 = agg.dispatch_packet(&flow_a, 1400);
            match res3 {
                FlowDistributionResult::Forward {
                    link_id: new_link, ..
                } => {
                    assert_ne!(link_id, new_link);
                }
                _ => panic!("Expected failover link"),
            }
        }
    }
}
