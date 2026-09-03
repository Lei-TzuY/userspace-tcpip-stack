//! BGP Color-Aware Extended Community for Segment Routing Traffic Engineering (SR-TE) Steering (RFC 9012 / RFC 9256).
//!
//! Provides automated steering of BGP IPv4/IPv6 destination prefixes into Segment Routing
//! Policies (SR-MPLS / SRv6) identified by (Color, Endpoint) tuples.

use crate::ipv4::Ipv4Address;
use crate::ipv6::Ipv6Address;
use std::collections::HashMap;

/// BGP Color Extended Community Type and Sub-type (RFC 9012 Section 4.3).
pub const BGP_EXT_COMM_TYPE_OPAQUE: u8 = 0x03;
pub const BGP_EXT_COMM_SUBTYPE_COLOR: u8 = 0x0B;

/// Color Fallback and Resolution Mode (CO-Bits / Color-Only Flags).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoBitsMode {
    /// Fallback to native Best-Effort IP routing if no matching SR Policy is available.
    FallbackBestEffort = 0,
    /// Fallback to colored IGP shortest path.
    FallbackIgpColor = 1,
    /// Drop traffic if no matching SR Policy is available (Strict TE).
    StrictDrop = 2,
}

/// BGP Color Extended Community (8 bytes).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct BgpColorCommunity {
    pub flags: u16,
    pub color: u32,
}

impl BgpColorCommunity {
    pub fn new(color: u32, mode: CoBitsMode) -> Self {
        let flags = (mode as u16) & 0x03;
        BgpColorCommunity { flags, color }
    }

    pub fn co_mode(&self) -> CoBitsMode {
        match self.flags & 0x03 {
            0 => CoBitsMode::FallbackBestEffort,
            1 => CoBitsMode::FallbackIgpColor,
            2 => CoBitsMode::StrictDrop,
            _ => CoBitsMode::FallbackBestEffort,
        }
    }

    pub fn serialize(&self) -> [u8; 8] {
        let mut buf = [0u8; 8];
        buf[0] = BGP_EXT_COMM_TYPE_OPAQUE;
        buf[1] = BGP_EXT_COMM_SUBTYPE_COLOR;
        buf[2..4].copy_from_slice(&self.flags.to_be_bytes());
        buf[4..8].copy_from_slice(&self.color.to_be_bytes());
        buf
    }

    pub fn parse(buf: &[u8]) -> Option<Self> {
        if buf.len() < 8 {
            return None;
        }
        if buf[0] != BGP_EXT_COMM_TYPE_OPAQUE || buf[1] != BGP_EXT_COMM_SUBTYPE_COLOR {
            return None;
        }
        let flags = u16::from_be_bytes([buf[2], buf[3]]);
        let color = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
        Some(BgpColorCommunity { flags, color })
    }
}

/// Segment List variant for an SR-TE Policy Candidate Path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ColorSrSegmentList {
    /// SR-MPLS Label Stack (e.g. Node-SID, Adjacency-SID labels)
    MplsLabels(Vec<u32>),
    /// SRv6 Segment List (IPv6 SIDs)
    Srv6Sids(Vec<Ipv6Address>),
}

/// Active SR-TE Policy Path with preference and segment stack.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ColorSrPolicy {
    pub color: u32,
    pub endpoint: Ipv4Address,
    pub preference: u32,
    pub is_active: bool,
    pub segment_list: ColorSrSegmentList,
}

/// Steering verdict from Color-Aware SR Engine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SrSteeringVerdict {
    /// Steered over active SR-TE Policy
    SteeredOverPolicy {
        color: u32,
        endpoint: Ipv4Address,
        segments: ColorSrSegmentList,
    },
    /// Fell back to native best effort next-hop routing
    FallbackBestEffort { endpoint: Ipv4Address },
    /// Dropped due to strict policy requirement (CO-bits StrictDrop)
    StrictDropNoPolicyMatch,
}

/// Color-Aware BGP SR-TE Steering Engine (RFC 9256).
#[derive(Debug, Clone, Default)]
pub struct ColorAwareSrEngine {
    /// Key: (Color, Endpoint) -> List of candidate policies
    pub policies: HashMap<(u32, Ipv4Address), Vec<ColorSrPolicy>>,
}

impl ColorAwareSrEngine {
    pub fn new() -> Self {
        ColorAwareSrEngine {
            policies: HashMap::new(),
        }
    }

    pub fn add_policy(&mut self, policy: ColorSrPolicy) {
        let entry = self
            .policies
            .entry((policy.color, policy.endpoint))
            .or_default();
        entry.push(policy);
        // Sort descending by preference so highest preference candidate path is chosen
        entry.sort_by(|a, b| b.preference.cmp(&a.preference));
    }

    pub fn set_policy_status(&mut self, color: u32, endpoint: Ipv4Address, active: bool) {
        if let Some(list) = self.policies.get_mut(&(color, endpoint)) {
            for pol in list.iter_mut() {
                pol.is_active = active;
            }
        }
    }

    /// Steer packet/prefix destined to a BGP Next-Hop (Endpoint) with a given Color Community.
    pub fn steer_route(
        &self,
        endpoint: Ipv4Address,
        color_comm: Option<&BgpColorCommunity>,
    ) -> SrSteeringVerdict {
        let color_comm = match color_comm {
            Some(c) => c,
            None => return SrSteeringVerdict::FallbackBestEffort { endpoint },
        };

        // Look for matching active policy with highest preference
        if let Some(candidate_paths) = self.policies.get(&(color_comm.color, endpoint)) {
            if let Some(active_path) = candidate_paths.iter().find(|p| p.is_active) {
                return SrSteeringVerdict::SteeredOverPolicy {
                    color: color_comm.color,
                    endpoint,
                    segments: active_path.segment_list.clone(),
                };
            }
        }

        // No active policy found: consult CO-bits mode
        match color_comm.co_mode() {
            CoBitsMode::FallbackBestEffort | CoBitsMode::FallbackIgpColor => {
                SrSteeringVerdict::FallbackBestEffort { endpoint }
            }
            CoBitsMode::StrictDrop => SrSteeringVerdict::StrictDropNoPolicyMatch,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bgp_color_community_codec() {
        let comm = BgpColorCommunity::new(100, CoBitsMode::StrictDrop);
        let ser = comm.serialize();
        assert_eq!(ser[0], 0x03);
        assert_eq!(ser[1], 0x0B);
        assert_eq!(ser[3], 0x02); // StrictDrop flag
        assert_eq!(u32::from_be_bytes([ser[4], ser[5], ser[6], ser[7]]), 100);

        let parsed = BgpColorCommunity::parse(&ser).unwrap();
        assert_eq!(parsed.color, 100);
        assert_eq!(parsed.co_mode(), CoBitsMode::StrictDrop);
    }

    #[test]
    fn test_color_aware_sr_steering_and_failover() {
        let mut engine = ColorAwareSrEngine::new();
        let endpoint = Ipv4Address::new(192, 0, 2, 1);
        let color = 200; // Low-latency policy color

        let policy_primary = ColorSrPolicy {
            color,
            endpoint,
            preference: 200,
            is_active: true,
            segment_list: ColorSrSegmentList::MplsLabels(vec![16001, 16002, 16003]),
        };

        engine.add_policy(policy_primary);

        let comm_fallback = BgpColorCommunity::new(color, CoBitsMode::FallbackBestEffort);
        let comm_strict = BgpColorCommunity::new(color, CoBitsMode::StrictDrop);

        // 1. Steering while policy is active
        let res1 = engine.steer_route(endpoint, Some(&comm_fallback));
        match res1 {
            SrSteeringVerdict::SteeredOverPolicy { segments, .. } => {
                assert_eq!(
                    segments,
                    ColorSrSegmentList::MplsLabels(vec![16001, 16002, 16003])
                );
            }
            other => panic!("Expected SteeredOverPolicy, got {:?}", other),
        }

        // 2. Disable policy (simulating path failure)
        engine.set_policy_status(color, endpoint, false);

        // 3. Fallback mode -> Best Effort
        let res2 = engine.steer_route(endpoint, Some(&comm_fallback));
        assert_eq!(res2, SrSteeringVerdict::FallbackBestEffort { endpoint });

        // 4. Strict mode -> Drop
        let res3 = engine.steer_route(endpoint, Some(&comm_strict));
        assert_eq!(res3, SrSteeringVerdict::StrictDropNoPolicyMatch);
    }
}
