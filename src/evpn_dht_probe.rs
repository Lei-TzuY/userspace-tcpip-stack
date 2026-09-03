// =============================================================================
// EVPN Layer 2 Dynamic Host Tracking (DHT) & Silent Host Probing Engine
// (RFC 7432)
// =============================================================================
//
// In EVPN datacenter fabrics, hosts that do not generate frequent traffic
// ("silent hosts") risk having their local MAC/IP bindings prematurely aged out,
// causing unnecessary BGP EVPN Type-2 route flap and unneeded flood re-learning.
//
// The DHT Engine monitors host inactivity and dispatches targeted unicast ARP
// Request probes prior to aging out the host.
//
// Features:
//   1. Host Activity Lifecycle: Active -> Probing -> Dead (Withdrawn).
//   2. Targeted Unicast ARP Keep-Alive Generation.
//   3. Configurable Inactivity Threshold & Probe Retry Count.
//   4. Type-2 EVPN Route Preservation or Accelerated Withdrawal.
//
// Pure safe Rust, zero external crates.

use crate::ethernet::MacAddress;
use crate::ipv4::Ipv4Address;

/// Host liveness state in EVPN bridge.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostTrackingState {
    Active,
    Probing { retries_left: u32 },
    Dead,
}

/// Tracked host entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrackedHost {
    pub vni: u32,
    pub port_id: u32,
    pub mac: MacAddress,
    pub ip: Ipv4Address,
    pub last_seen_secs: u64,
    pub state: HostTrackingState,
    pub total_probes_sent: u32,
}

/// DHT periodic tick verdict.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DhtTickAction {
    /// No action required.
    None,
    /// Send unicast ARP probe to verify host presence.
    SendUnicastProbe {
        vni: u32,
        port_id: u32,
        target_mac: MacAddress,
        target_ip: Ipv4Address,
    },
    /// Host failed all probes; EVPN Type-2 route must be withdrawn.
    WithdrawHost {
        vni: u32,
        port_id: u32,
        mac: MacAddress,
        ip: Ipv4Address,
    },
}

/// EVPN Layer 2 Dynamic Host Tracking Engine.
pub struct EvpnDhtEngine {
    pub inactivity_timeout_secs: u64,
    pub probe_interval_secs: u64,
    pub max_probe_retries: u32,
    pub hosts: Vec<TrackedHost>,
    pub total_probes_dispatched: u64,
    pub total_withdrawals: u64,
}

impl EvpnDhtEngine {
    pub fn new(inactivity_timeout_secs: u64, max_probe_retries: u32) -> Self {
        Self {
            inactivity_timeout_secs,
            probe_interval_secs: 5,
            max_probe_retries,
            hosts: Vec::new(),
            total_probes_dispatched: 0,
            total_withdrawals: 0,
        }
    }

    /// Register or refresh host activity (e.g. upon seeing an ingress frame).
    pub fn touch_host(
        &mut self,
        vni: u32,
        port_id: u32,
        mac: MacAddress,
        ip: Ipv4Address,
        current_time_secs: u64,
    ) {
        if let Some(h) = self.hosts.iter_mut().find(|h| h.vni == vni && h.mac == mac) {
            h.port_id = port_id;
            h.ip = ip;
            h.last_seen_secs = current_time_secs;
            h.state = HostTrackingState::Active;
        } else {
            self.hosts.push(TrackedHost {
                vni,
                port_id,
                mac,
                ip,
                last_seen_secs: current_time_secs,
                state: HostTrackingState::Active,
                total_probes_sent: 0,
            });
        }
    }

    /// Periodic background tick to evaluate silence and dispatch probes.
    pub fn tick(&mut self, current_time_secs: u64) -> Vec<DhtTickAction> {
        let mut actions = Vec::new();

        for host in &mut self.hosts {
            let elapsed = current_time_secs.saturating_sub(host.last_seen_secs);

            match host.state {
                HostTrackingState::Active => {
                    if elapsed >= self.inactivity_timeout_secs {
                        host.state = HostTrackingState::Probing {
                            retries_left: self.max_probe_retries.saturating_sub(1),
                        };
                        host.total_probes_sent += 1;
                        self.total_probes_dispatched += 1;
                        actions.push(DhtTickAction::SendUnicastProbe {
                            vni: host.vni,
                            port_id: host.port_id,
                            target_mac: host.mac,
                            target_ip: host.ip,
                        });
                    }
                }
                HostTrackingState::Probing {
                    ref mut retries_left,
                } => {
                    if *retries_left > 0 {
                        *retries_left -= 1;
                        host.total_probes_sent += 1;
                        self.total_probes_dispatched += 1;
                        actions.push(DhtTickAction::SendUnicastProbe {
                            vni: host.vni,
                            port_id: host.port_id,
                            target_mac: host.mac,
                            target_ip: host.ip,
                        });
                    } else {
                        host.state = HostTrackingState::Dead;
                        self.total_withdrawals += 1;
                        actions.push(DhtTickAction::WithdrawHost {
                            vni: host.vni,
                            port_id: host.port_id,
                            mac: host.mac,
                            ip: host.ip,
                        });
                    }
                }
                HostTrackingState::Dead => {}
            }
        }

        // Clean up dead hosts
        self.hosts.retain(|h| h.state != HostTrackingState::Dead);

        actions
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_evpn_dht_probe_lifecycle() {
        let mut dht = EvpnDhtEngine::new(30, 2); // 30s inactivity, 2 retries

        let mac = MacAddress([0x00, 0x50, 0x56, 0x11, 0x22, 0x33]);
        let ip = Ipv4Address::new(192, 168, 10, 50);

        // 1. Host seen at t=1000
        dht.touch_host(100, 1, mac, ip, 1000);
        assert_eq!(dht.hosts.len(), 1);

        // 2. Tick at t=1020 (elapsed 20s < 30s) -> No action
        let a1 = dht.tick(1020);
        assert!(a1.is_empty());

        // 3. Tick at t=1035 (elapsed 35s >= 30s) -> Enters Probing, sends 1st probe
        let a2 = dht.tick(1035);
        assert_eq!(a2.len(), 1);
        assert_eq!(
            a2[0],
            DhtTickAction::SendUnicastProbe {
                vni: 100,
                port_id: 1,
                target_mac: mac,
                target_ip: ip,
            }
        );

        // 4. Host responds to probe at t=1036 -> Returns to Active
        dht.touch_host(100, 1, mac, ip, 1036);
        assert_eq!(dht.hosts[0].state, HostTrackingState::Active);

        // 5. Inactive again at t=1070 -> Probing 1st retry
        let a3 = dht.tick(1070);
        assert_eq!(a3.len(), 1);

        // Probing 2nd retry
        let a4 = dht.tick(1075);
        assert_eq!(a4.len(), 1);

        // Exhausted retries -> Withdraw host
        let a5 = dht.tick(1080);
        assert_eq!(a5.len(), 1);
        assert_eq!(
            a5[0],
            DhtTickAction::WithdrawHost {
                vni: 100,
                port_id: 1,
                mac,
                ip,
            }
        );
        assert!(dht.hosts.is_empty());
    }
}
