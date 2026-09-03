//! EVPN Layer 2 Multicast IGMPv3/MLDv2 Join Suppression & Proxy Reporting Engine.
//!
//! Implements RFC 9251 / RFC 4541 join suppression on multi-access EVPN L2 broadcast domains,
//! preventing upstream IGMP/MLD report storms by consolidating multiple local subscriber joins
//! into a single proxy report towards EVPN designated routers and the core fabric.

use crate::ipv4::Ipv4Address;

/// Action triggered when evaluating a local host membership report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JoinSuppressVerdict {
    /// First local subscriber joined: triggers upstream EVPN SMET / Proxy Join advertisement.
    FirstSubscriberProxyJoin {
        vni: u32,
        port_id: u16,
        source_ip: Ipv4Address,
        group_ip: Ipv4Address,
        joining_host: Ipv4Address,
    },
    /// Subsequent subscriber joined: report is suppressed locally to conserve fabric bandwidth.
    DuplicateJoinSuppressed {
        vni: u32,
        port_id: u16,
        source_ip: Ipv4Address,
        group_ip: Ipv4Address,
        joining_host: Ipv4Address,
        active_subscriber_count: usize,
    },
    /// Host refreshed existing membership: internal timer refreshed, upstream message suppressed.
    MembershipRefreshedSuppressed {
        vni: u32,
        port_id: u16,
        source_ip: Ipv4Address,
        group_ip: Ipv4Address,
        host_ip: Ipv4Address,
    },
    /// Intermediate subscriber left: channel remains active, upstream leave suppressed.
    SubscriberLeftChannelRemainsActive {
        vni: u32,
        port_id: u16,
        source_ip: Ipv4Address,
        group_ip: Ipv4Address,
        leaving_host: Ipv4Address,
        remaining_subscribers: usize,
    },
    /// Last local subscriber left: triggers upstream EVPN SMET withdrawal / Proxy Leave.
    LastSubscriberProxyLeave {
        vni: u32,
        port_id: u16,
        source_ip: Ipv4Address,
        group_ip: Ipv4Address,
        leaving_host: Ipv4Address,
    },
    /// Leave received for an un-subscribed channel.
    ChannelNotFound {
        vni: u32,
        port_id: u16,
        source_ip: Ipv4Address,
        group_ip: Ipv4Address,
    },
}

/// Tracked multicast channel state under join suppression.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JoinSuppressChannel {
    pub vni: u32,
    pub port_id: u16,
    pub source_ip: Ipv4Address,
    pub group_ip: Ipv4Address,
    pub subscribers: Vec<Ipv4Address>,
    pub is_proxy_advertised: bool,
}

/// EVPN IGMP/MLD Join Suppression Engine.
#[derive(Debug, Clone)]
pub struct EvpnIgmpJoinSuppressEngine {
    pub channels: Vec<JoinSuppressChannel>,
    pub total_joins_received: u64,
    pub total_joins_suppressed: u64,
    pub total_leaves_received: u64,
    pub total_proxy_joins_sent: u64,
    pub total_proxy_leaves_sent: u64,
}

impl Default for EvpnIgmpJoinSuppressEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl EvpnIgmpJoinSuppressEngine {
    /// Creates a new Join Suppression Engine.
    pub fn new() -> Self {
        Self {
            channels: Vec::new(),
            total_joins_received: 0,
            total_joins_suppressed: 0,
            total_leaves_received: 0,
            total_proxy_joins_sent: 0,
            total_proxy_leaves_sent: 0,
        }
    }

    /// Evaluates a host Join / Membership Report for a given (S, G) multicast channel.
    pub fn process_join(
        &mut self,
        vni: u32,
        port_id: u16,
        source_ip: Ipv4Address,
        group_ip: Ipv4Address,
        host_ip: Ipv4Address,
    ) -> JoinSuppressVerdict {
        self.total_joins_received += 1;

        if let Some(ch) = self.channels.iter_mut().find(|c| {
            c.vni == vni
                && c.port_id == port_id
                && c.source_ip == source_ip
                && c.group_ip == group_ip
        }) {
            if ch.subscribers.contains(&host_ip) {
                self.total_joins_suppressed += 1;
                JoinSuppressVerdict::MembershipRefreshedSuppressed {
                    vni,
                    port_id,
                    source_ip,
                    group_ip,
                    host_ip,
                }
            } else {
                ch.subscribers.push(host_ip);
                self.total_joins_suppressed += 1;
                JoinSuppressVerdict::DuplicateJoinSuppressed {
                    vni,
                    port_id,
                    source_ip,
                    group_ip,
                    joining_host: host_ip,
                    active_subscriber_count: ch.subscribers.len(),
                }
            }
        } else {
            // First subscriber on this segment
            let ch = JoinSuppressChannel {
                vni,
                port_id,
                source_ip,
                group_ip,
                subscribers: vec![host_ip],
                is_proxy_advertised: true,
            };
            self.channels.push(ch);
            self.total_proxy_joins_sent += 1;

            JoinSuppressVerdict::FirstSubscriberProxyJoin {
                vni,
                port_id,
                source_ip,
                group_ip,
                joining_host: host_ip,
            }
        }
    }

    /// Evaluates a host Leave / Group Record for a given (S, G) multicast channel.
    pub fn process_leave(
        &mut self,
        vni: u32,
        port_id: u16,
        source_ip: Ipv4Address,
        group_ip: Ipv4Address,
        host_ip: Ipv4Address,
    ) -> JoinSuppressVerdict {
        self.total_leaves_received += 1;

        let channel_idx = self.channels.iter().position(|c| {
            c.vni == vni
                && c.port_id == port_id
                && c.source_ip == source_ip
                && c.group_ip == group_ip
        });

        if let Some(idx) = channel_idx {
            let ch = &mut self.channels[idx];
            ch.subscribers.retain(|&h| h != host_ip);

            if ch.subscribers.is_empty() {
                self.channels.swap_remove(idx);
                self.total_proxy_leaves_sent += 1;

                JoinSuppressVerdict::LastSubscriberProxyLeave {
                    vni,
                    port_id,
                    source_ip,
                    group_ip,
                    leaving_host: host_ip,
                }
            } else {
                let remaining = ch.subscribers.len();
                JoinSuppressVerdict::SubscriberLeftChannelRemainsActive {
                    vni,
                    port_id,
                    source_ip,
                    group_ip,
                    leaving_host: host_ip,
                    remaining_subscribers: remaining,
                }
            }
        } else {
            JoinSuppressVerdict::ChannelNotFound {
                vni,
                port_id,
                source_ip,
                group_ip,
            }
        }
    }

    /// Checks if a channel currently has an active upstream proxy join.
    pub fn is_proxy_joined(
        &self,
        vni: u32,
        port_id: u16,
        source_ip: Ipv4Address,
        group_ip: Ipv4Address,
    ) -> bool {
        self.channels.iter().any(|c| {
            c.vni == vni
                && c.port_id == port_id
                && c.source_ip == source_ip
                && c.group_ip == group_ip
                && c.is_proxy_advertised
        })
    }

    /// Clears all channels.
    pub fn clear(&mut self) {
        self.channels.clear();
        self.total_joins_received = 0;
        self.total_joins_suppressed = 0;
        self.total_leaves_received = 0;
        self.total_proxy_joins_sent = 0;
        self.total_proxy_leaves_sent = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_evpn_join_suppress_lifecycle() {
        let mut engine = EvpnIgmpJoinSuppressEngine::new();
        let src = Ipv4Address::new(192, 168, 1, 100);
        let grp = Ipv4Address::new(232, 1, 1, 1);
        let host1 = Ipv4Address::new(10, 0, 0, 1);
        let host2 = Ipv4Address::new(10, 0, 0, 2);

        // 1. Host 1 joins -> Triggers FirstSubscriberProxyJoin
        let v1 = engine.process_join(100, 1, src, grp, host1);
        assert_eq!(
            v1,
            JoinSuppressVerdict::FirstSubscriberProxyJoin {
                vni: 100,
                port_id: 1,
                source_ip: src,
                group_ip: grp,
                joining_host: host1,
            }
        );
        assert_eq!(engine.total_proxy_joins_sent, 1);

        // 2. Host 2 joins same channel -> Suppressed
        let v2 = engine.process_join(100, 1, src, grp, host2);
        assert_eq!(
            v2,
            JoinSuppressVerdict::DuplicateJoinSuppressed {
                vni: 100,
                port_id: 1,
                source_ip: src,
                group_ip: grp,
                joining_host: host2,
                active_subscriber_count: 2,
            }
        );
        assert_eq!(engine.total_joins_suppressed, 1);

        // 3. Host 1 leaves -> Channel remains active with Host 2
        let v3 = engine.process_leave(100, 1, src, grp, host1);
        assert_eq!(
            v3,
            JoinSuppressVerdict::SubscriberLeftChannelRemainsActive {
                vni: 100,
                port_id: 1,
                source_ip: src,
                group_ip: grp,
                leaving_host: host1,
                remaining_subscribers: 1,
            }
        );
        assert_eq!(engine.total_proxy_leaves_sent, 0);

        // 4. Host 2 leaves -> LastSubscriberProxyLeave
        let v4 = engine.process_leave(100, 1, src, grp, host2);
        assert_eq!(
            v4,
            JoinSuppressVerdict::LastSubscriberProxyLeave {
                vni: 100,
                port_id: 1,
                source_ip: src,
                group_ip: grp,
                leaving_host: host2,
            }
        );
        assert_eq!(engine.total_proxy_leaves_sent, 1);
        assert_eq!(engine.channels.len(), 0);
    }
}
