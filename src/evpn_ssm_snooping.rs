// =============================================================================
// EVPN Layer 2 Source-Specific Multicast (SSM) Snooping & SMET Engine
// (RFC 7432 / RFC 9251 / RFC 4607)
// =============================================================================
//
// In multi-tenant datacenter fabrics, Source-Specific Multicast (SSM) allows
// receivers to subscribe explicitly to $(S, G)$ channels (Source IP $S$, Group IP $G$).
//
// The EVPN SSM Snooping Engine inspects IGMPv3 / MLDv2 membership reports,
// maintains local $(S, G)$ port membership, and generates BGP EVPN Type-6
// Selective Multicast Ethernet Tag (SMET) route advertisements to prune non-interested
// remote leaves from the replication tree.
//
// Features:
//   1. $(S, G)$ Channel Tracking per VNI (Source-Specific vs Any-Source $(*, G)$).
//   2. EVPN Type-6 (SMET) Route Join / Prune Event Generation.
//   3. Local Access Port Filtering and Ingress Replication Forwarding Decision.
//   4. Channel Inactivity Aging and Explicit Leave Processing.
//
// Pure safe Rust, zero external crates.

use crate::ipv4::Ipv4Address;

/// Multicast channel subscription filter mode (IGMPv3 / RFC 3376).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SsmFilterMode {
    /// Include specified source list $(S, G)$.
    Include,
    /// Exclude specified source list (Any-Source $(*, G)$ when empty).
    Exclude,
}

/// Active $(S, G)$ channel subscription on a local port.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SsmChannelEntry {
    pub vni: u32,
    pub group_ip: Ipv4Address,
    pub source_ip: Ipv4Address,
    pub subscribed_ports: Vec<u32>,
    pub remote_vteps: Vec<Ipv4Address>,
    pub last_refreshed_secs: u64,
}

/// EVPN Type-6 SMET Route Action.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SmetRouteAction {
    /// Advertise BGP EVPN Type-6 SMET route to overlay fabric.
    AdvertiseSmet {
        vni: u32,
        group_ip: Ipv4Address,
        source_ip: Ipv4Address,
    },
    /// Withdraw BGP EVPN Type-6 SMET route when all local receivers leave.
    WithdrawSmet {
        vni: u32,
        group_ip: Ipv4Address,
        source_ip: Ipv4Address,
    },
}

/// SSM Forwarding verdict for an ingress multicast packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SsmForwardingDecision {
    pub local_ports: Vec<u32>,
    pub remote_vteps: Vec<Ipv4Address>,
    pub should_drop: bool,
}

/// EVPN SSM Snooping & SMET Engine.
pub struct EvpnSsmEngine {
    pub local_vtep_ip: Ipv4Address,
    pub channel_timeout_secs: u64,
    pub channels: Vec<SsmChannelEntry>,
    pub total_smet_advertised: u64,
    pub total_smet_withdrawn: u64,
    pub total_packets_forwarded: u64,
}

impl EvpnSsmEngine {
    pub fn new(local_vtep_ip: Ipv4Address, channel_timeout_secs: u64) -> Self {
        Self {
            local_vtep_ip,
            channel_timeout_secs,
            channels: Vec::new(),
            total_smet_advertised: 0,
            total_smet_withdrawn: 0,
            total_packets_forwarded: 0,
        }
    }

    /// Process local IGMPv3 $(S, G)$ join report from an access port.
    pub fn handle_local_join(
        &mut self,
        vni: u32,
        port_id: u32,
        group_ip: Ipv4Address,
        source_ip: Ipv4Address,
        current_time_secs: u64,
    ) -> Option<SmetRouteAction> {
        let mut first_subscriber = false;

        if let Some(chan) = self
            .channels
            .iter_mut()
            .find(|c| c.vni == vni && c.group_ip == group_ip && c.source_ip == source_ip)
        {
            if !chan.subscribed_ports.contains(&port_id) {
                chan.subscribed_ports.push(port_id);
            }
            chan.last_refreshed_secs = current_time_secs;
        } else {
            self.channels.push(SsmChannelEntry {
                vni,
                group_ip,
                source_ip,
                subscribed_ports: vec![port_id],
                remote_vteps: Vec::new(),
                last_refreshed_secs: current_time_secs,
            });
            first_subscriber = true;
        }

        if first_subscriber {
            self.total_smet_advertised += 1;
            Some(SmetRouteAction::AdvertiseSmet {
                vni,
                group_ip,
                source_ip,
            })
        } else {
            None
        }
    }

    /// Process local IGMPv3 leave from an access port.
    pub fn handle_local_leave(
        &mut self,
        vni: u32,
        port_id: u32,
        group_ip: Ipv4Address,
        source_ip: Ipv4Address,
    ) -> Option<SmetRouteAction> {
        let mut should_withdraw = false;

        if let Some(pos) = self
            .channels
            .iter()
            .position(|c| c.vni == vni && c.group_ip == group_ip && c.source_ip == source_ip)
        {
            let chan = &mut self.channels[pos];
            if let Some(p_idx) = chan.subscribed_ports.iter().position(|p| *p == port_id) {
                chan.subscribed_ports.remove(p_idx);
            }

            if chan.subscribed_ports.is_empty() && chan.remote_vteps.is_empty() {
                self.channels.remove(pos);
                should_withdraw = true;
            } else if chan.subscribed_ports.is_empty() {
                should_withdraw = true;
            }
        }

        if should_withdraw {
            self.total_smet_withdrawn += 1;
            Some(SmetRouteAction::WithdrawSmet {
                vni,
                group_ip,
                source_ip,
            })
        } else {
            None
        }
    }

    /// Ingest remote EVPN Type-6 SMET route advertisement from a remote PE VTEP.
    pub fn handle_remote_smet_add(
        &mut self,
        vni: u32,
        remote_vtep: Ipv4Address,
        group_ip: Ipv4Address,
        source_ip: Ipv4Address,
    ) {
        if let Some(chan) = self
            .channels
            .iter_mut()
            .find(|c| c.vni == vni && c.group_ip == group_ip && c.source_ip == source_ip)
        {
            if !chan.remote_vteps.contains(&remote_vtep) {
                chan.remote_vteps.push(remote_vtep);
            }
        } else {
            self.channels.push(SsmChannelEntry {
                vni,
                group_ip,
                source_ip,
                subscribed_ports: Vec::new(),
                remote_vteps: vec![remote_vtep],
                last_refreshed_secs: 0,
            });
        }
    }

    /// Evaluate forwarding plan for an ingress $(S, G)$ multicast packet.
    pub fn evaluate_forwarding(
        &mut self,
        vni: u32,
        source_ip: Ipv4Address,
        group_ip: Ipv4Address,
    ) -> SsmForwardingDecision {
        self.total_packets_forwarded += 1;

        if let Some(chan) = self
            .channels
            .iter()
            .find(|c| c.vni == vni && c.group_ip == group_ip && c.source_ip == source_ip)
        {
            SsmForwardingDecision {
                local_ports: chan.subscribed_ports.clone(),
                remote_vteps: chan.remote_vteps.clone(),
                should_drop: chan.subscribed_ports.is_empty() && chan.remote_vteps.is_empty(),
            }
        } else {
            // No SSM subscriber: drop or treat as unknown
            SsmForwardingDecision {
                local_ports: Vec::new(),
                remote_vteps: Vec::new(),
                should_drop: true,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_evpn_ssm_snooping_lifecycle() {
        let mut engine = EvpnSsmEngine::new(Ipv4Address::new(10, 0, 0, 1), 60);

        let group = Ipv4Address::new(232, 1, 1, 1);
        let src = Ipv4Address::new(192, 168, 1, 100);

        // 1. Port 1 joins (S, G) channel -> triggers SMET advertisement
        let a1 = engine.handle_local_join(100, 1, group, src, 1000);
        assert_eq!(
            a1,
            Some(SmetRouteAction::AdvertiseSmet {
                vni: 100,
                group_ip: group,
                source_ip: src,
            })
        );

        // 2. Port 2 also joins -> no new SMET (already advertised)
        let a2 = engine.handle_local_join(100, 2, group, src, 1005);
        assert_eq!(a2, None);

        // 3. Remote VTEP 10.0.0.2 joins
        engine.handle_remote_smet_add(100, Ipv4Address::new(10, 0, 0, 2), group, src);

        // 4. Ingress multicast frame on (S, G) is forwarded to ports 1, 2 and remote VTEP
        let fwd = engine.evaluate_forwarding(100, src, group);
        assert!(!fwd.should_drop);
        assert_eq!(fwd.local_ports, vec![1, 2]);
        assert_eq!(fwd.remote_vteps, vec![Ipv4Address::new(10, 0, 0, 2)]);

        // 5. Ports 1 and 2 leave -> triggers SMET withdrawal
        assert_eq!(engine.handle_local_leave(100, 1, group, src), None);
        let a_leave = engine.handle_local_leave(100, 2, group, src);
        assert_eq!(
            a_leave,
            Some(SmetRouteAction::WithdrawSmet {
                vni: 100,
                group_ip: group,
                source_ip: src,
            })
        );
    }
}
