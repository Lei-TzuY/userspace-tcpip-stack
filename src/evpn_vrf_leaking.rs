//! EVPN Layer 3 Multi-VRF Route Leaking & Cross-Connect (RFC 9136 / RFC 4364 Section 10).
//!
//! Implements multi-tenant VRF Route Target (RT) import/export policy matching,
//! automatic cross-VRF prefix leaking for shared services (Internet, DNS, Security Appliances),
//! and per-VRF Longest Prefix Match (LPM) forwarding resolution.

use crate::ipv4::Ipv4Address;
use std::collections::{HashMap, HashSet};

/// VRF Route Entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeakedRouteEntry {
    pub prefix: Ipv4Address,
    pub prefix_len: u8,
    pub next_hop: Ipv4Address,
    pub source_vrf_id: u32,
    pub route_targets: HashSet<String>,
}

/// VRF Instance Definition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VrfInstance {
    pub vrf_id: u32,
    pub name: String,
    pub export_rts: HashSet<String>,
    pub import_rts: HashSet<String>,
    pub routes: Vec<LeakedRouteEntry>,
}

impl VrfInstance {
    pub fn new(vrf_id: u32, name: &str, export_rts: &[&str], import_rts: &[&str]) -> Self {
        VrfInstance {
            vrf_id,
            name: name.to_string(),
            export_rts: export_rts.iter().map(|s| s.to_string()).collect(),
            import_rts: import_rts.iter().map(|s| s.to_string()).collect(),
            routes: Vec::new(),
        }
    }
}

/// EVPN Layer 3 Multi-VRF Route Leaking Engine.
#[derive(Debug, Clone, Default)]
pub struct EvpnVrfLeakingEngine {
    pub vrfs: HashMap<u32, VrfInstance>,
    pub leaked_routes_count: usize,
}

impl EvpnVrfLeakingEngine {
    pub fn new() -> Self {
        EvpnVrfLeakingEngine {
            vrfs: HashMap::new(),
            leaked_routes_count: 0,
        }
    }

    /// Registers a new VRF instance.
    pub fn add_vrf(&mut self, vrf_id: u32, name: &str, export_rts: &[&str], import_rts: &[&str]) {
        let vrf = VrfInstance::new(vrf_id, name, export_rts, import_rts);
        self.vrfs.insert(vrf_id, vrf);
    }

    /// Adds a direct route to a source VRF.
    pub fn add_direct_route(
        &mut self,
        vrf_id: u32,
        prefix: Ipv4Address,
        prefix_len: u8,
        next_hop: Ipv4Address,
    ) {
        if let Some(vrf) = self.vrfs.get_mut(&vrf_id) {
            let entry = LeakedRouteEntry {
                prefix,
                prefix_len,
                next_hop,
                source_vrf_id: vrf_id,
                route_targets: vrf.export_rts.clone(),
            };
            vrf.routes.push(entry);
        }
    }

    /// Runs cross-VRF Route Leaking synchronization based on Route Target intersection.
    pub fn sync_route_leaking(&mut self) {
        let all_routes: Vec<LeakedRouteEntry> = self
            .vrfs
            .values()
            .flat_map(|v| v.routes.clone())
            .collect();

        for entry in all_routes {
            for vrf in self.vrfs.values_mut() {
                if vrf.vrf_id == entry.source_vrf_id {
                    continue; // Skip source VRF
                }

                // Check if any export RT from the route intersects with this VRF's import RTs
                let intersects = entry.route_targets.iter().any(|rt| vrf.import_rts.contains(rt));
                if intersects {
                    // Check if already present
                    if !vrf.routes.iter().any(|r| r.prefix == entry.prefix && r.prefix_len == entry.prefix_len) {
                        vrf.routes.push(entry.clone());
                        self.leaked_routes_count += 1;
                    }
                }
            }
        }
    }

    /// Performs a Longest Prefix Match (LPM) lookup within a specific VRF.
    pub fn lookup_vrf_lpm(&self, vrf_id: u32, dst_ip: Ipv4Address) -> Option<Ipv4Address> {
        let vrf = self.vrfs.get(&vrf_id)?;
        let mut best_match: Option<(&LeakedRouteEntry, u8)> = None;

        for r in &vrf.routes {
            let mask = if r.prefix_len == 0 {
                0u32
            } else {
                !((1u32 << (32 - r.prefix_len)) - 1)
            };

            let dst_num = u32::from_be_bytes(dst_ip.0);
            let prefix_num = u32::from_be_bytes(r.prefix.0);

            if (dst_num & mask) == (prefix_num & mask) {
                if best_match.is_none() || r.prefix_len > best_match.unwrap().1 {
                    best_match = Some((r, r.prefix_len));
                }
            }
        }

        best_match.map(|(r, _)| r.next_hop)
    }
}
