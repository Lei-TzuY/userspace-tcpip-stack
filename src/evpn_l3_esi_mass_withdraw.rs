//! EVPN Layer 3 ESI Fast Mass-Withdrawal for Type 5 IP Prefix Routes (RFC 9136 §4.4 / RFC 7432).
//!
//! When EVPN Route Type 5 (IP Prefix) routes are advertised with an Ethernet Segment Identifier (ESI),
//! remote PEs associate the prefix reachability with the corresponding Route Type 1 (Auto-Discovery per-ES).
//! Upon link failure, an EAD-per-ES withdrawal triggers instant hierarchical fast failover for all
//! associated Type 5 IP prefixes to surviving multi-homing backup PEs without waiting for per-prefix withdrawals.

use crate::evpn::RouteDistinguisher;
use crate::evpn_mass_withdraw::EvpnPerEsAdRoute;
use crate::evpn_synch::EthernetSegmentId;
use crate::ipv4::Ipv4Address;
use std::collections::{HashMap, HashSet};

/// EVPN Layer 3 Prefix Key (VRF + IPv4 Prefix / Prefix-Len).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct EvpnL3PrefixKey {
    pub vrf_id: u32,
    pub prefix: Ipv4Address,
    pub prefix_len: u8,
}

/// A Type 5 IP Prefix route bound to an ESI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvpnType5EsiRoute {
    pub rd: RouteDistinguisher,
    pub key: EvpnL3PrefixKey,
    pub esi: EthernetSegmentId,
    pub vni: u32,
    pub primary_pe: Ipv4Address,
    pub backup_pe: Option<Ipv4Address>,
}

/// Status of an ESI-backed L3 forwarding entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EvpnL3ForwardingState {
    ActivePrimary(Ipv4Address),
    FailedOverBackup(Ipv4Address),
    Unreachable,
}

/// Layer 3 ESI Fast Failover Engine.
#[derive(Debug, Clone, Default)]
pub struct EvpnL3EsiFastWithdrawEngine {
    /// ESI -> Set of active PEs that have advertised an active EAD-per-ES (Type 1) route
    pub active_esi_pes: HashMap<EthernetSegmentId, HashSet<Ipv4Address>>,
    /// ESI -> List of Type 5 Prefix keys associated with this segment
    pub esi_to_prefixes: HashMap<EthernetSegmentId, Vec<EvpnType5EsiRoute>>,
}

impl EvpnL3EsiFastWithdrawEngine {
    pub fn new() -> Self {
        Self {
            active_esi_pes: HashMap::new(),
            esi_to_prefixes: HashMap::new(),
        }
    }

    /// Registers or updates an active EAD-per-ES (Route Type 1) from a specific PE.
    pub fn handle_ad_route_advertisement(&mut self, ad_route: &EvpnPerEsAdRoute) {
        self.active_esi_pes
            .entry(ad_route.esi)
            .or_default()
            .insert(ad_route.next_hop);
    }

    /// Registers a Type 5 IP Prefix route bound to an ESI.
    pub fn add_type5_esi_route(&mut self, route: EvpnType5EsiRoute) {
        let list = self.esi_to_prefixes.entry(route.esi).or_default();
        list.push(route);
    }

    /// Resolves the current forwarding state and active next-hop for a given prefix.
    pub fn resolve_prefix_forwarding(&self, key: &EvpnL3PrefixKey) -> EvpnL3ForwardingState {
        for (esi, routes) in &self.esi_to_prefixes {
            for route in routes {
                if &route.key == key {
                    let active_pes = self.active_esi_pes.get(esi);
                    let primary_up =
                        active_pes.map_or(false, |pes| pes.contains(&route.primary_pe));

                    if primary_up {
                        return EvpnL3ForwardingState::ActivePrimary(route.primary_pe);
                    }

                    if let Some(backup) = route.backup_pe {
                        let backup_up = active_pes.map_or(false, |pes| pes.contains(&backup));
                        if backup_up {
                            return EvpnL3ForwardingState::FailedOverBackup(backup);
                        }
                    }

                    return EvpnL3ForwardingState::Unreachable;
                }
            }
        }
        EvpnL3ForwardingState::Unreachable
    }

    /// Handles a Route Type 1 (EAD-per-ES) withdrawal from a PE, immediately mass-invalidating
    /// or failing over all associated Type 5 IP prefixes.
    /// Returns the number of prefix routes impacted and failed over.
    pub fn handle_ad_route_withdrawal(
        &mut self,
        esi: &EthernetSegmentId,
        withdrawn_pe: &Ipv4Address,
    ) -> usize {
        if let Some(pes) = self.active_esi_pes.get_mut(esi) {
            pes.remove(withdrawn_pe);
        }

        self.esi_to_prefixes
            .get(esi)
            .map_or(0, |routes| routes.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_evpn_l3_esi_mass_withdrawal_failover() {
        let mut engine = EvpnL3EsiFastWithdrawEngine::new();

        let esi = EthernetSegmentId([1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
        let pe1 = Ipv4Address::new(192, 0, 2, 1); // Primary Multi-homing PE
        let pe2 = Ipv4Address::new(192, 0, 2, 2); // Backup Multi-homing PE
        let rd = RouteDistinguisher::new(pe1, 100);

        // 1. Both PEs advertise EAD-per-ES Route Type 1 for this ESI
        let ad1 = EvpnPerEsAdRoute::new(rd.clone(), esi, pe1);
        let ad2 = EvpnPerEsAdRoute::new(rd.clone(), esi, pe2);
        engine.handle_ad_route_advertisement(&ad1);
        engine.handle_ad_route_advertisement(&ad2);

        // 2. Add multiple Type 5 IP Prefix routes (e.g. customer subnets on this multi-homed CE)
        let prefix1 = EvpnL3PrefixKey {
            vrf_id: 10,
            prefix: Ipv4Address::new(10, 100, 1, 0),
            prefix_len: 24,
        };
        let prefix2 = EvpnL3PrefixKey {
            vrf_id: 10,
            prefix: Ipv4Address::new(10, 100, 2, 0),
            prefix_len: 24,
        };

        engine.add_type5_esi_route(EvpnType5EsiRoute {
            rd: rd.clone(),
            key: prefix1.clone(),
            esi,
            vni: 50000,
            primary_pe: pe1,
            backup_pe: Some(pe2),
        });
        engine.add_type5_esi_route(EvpnType5EsiRoute {
            rd,
            key: prefix2.clone(),
            esi,
            vni: 50000,
            primary_pe: pe1,
            backup_pe: Some(pe2),
        });

        // Initially both prefixes resolve to Primary PE1
        assert_eq!(
            engine.resolve_prefix_forwarding(&prefix1),
            EvpnL3ForwardingState::ActivePrimary(pe1)
        );
        assert_eq!(
            engine.resolve_prefix_forwarding(&prefix2),
            EvpnL3ForwardingState::ActivePrimary(pe1)
        );

        // 3. PE1 suffers link failure and withdraws Type 1 EAD-per-ES
        let count = engine.handle_ad_route_withdrawal(&esi, &pe1);
        assert_eq!(count, 2); // 2 Type-5 prefixes instantaneously affected

        // 4. Remote PE immediately routes via backup PE2 without waiting for Type-5 withdrawals!
        assert_eq!(
            engine.resolve_prefix_forwarding(&prefix1),
            EvpnL3ForwardingState::FailedOverBackup(pe2)
        );
        assert_eq!(
            engine.resolve_prefix_forwarding(&prefix2),
            EvpnL3ForwardingState::FailedOverBackup(pe2)
        );
    }
}
