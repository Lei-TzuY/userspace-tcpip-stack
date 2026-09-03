// src/evpn_igmp_explicit_tracking.rs
//
// RFC 9251 / RFC 3376 EVPN Layer 2 Multicast IGMPv3/MLDv2 Explicit Tracking & Fast Leave Engine.
//
// Maintains per-host membership state on shared Ethernet access ports to enable
// instant port pruning and EVPN SMET Route Type 6 withdrawal upon receiving Leave
// messages without waiting for Last Member Query Timer (LMQT) timeouts.

use crate::ipv4::Ipv4Address;

pub const DEFAULT_EXPLICIT_TRACKING_TIMEOUT_SECS: u64 = 260;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostSubscriber {
    pub host_ip: Ipv4Address,
    pub last_report_secs: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelPortState {
    pub vni: u32,
    pub port_id: u16,
    pub source_ip: Ipv4Address,
    pub group_ip: Ipv4Address,
    pub subscribers: Vec<HostSubscriber>,
    pub is_forwarding: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExplicitTrackingVerdict {
    SubscriberAdded {
        vni: u32,
        port_id: u16,
        source_ip: Ipv4Address,
        group_ip: Ipv4Address,
        host_ip: Ipv4Address,
        total_subscribers: usize,
        smet_advertise: bool,
    },
    SubscriberRefreshed {
        vni: u32,
        port_id: u16,
        source_ip: Ipv4Address,
        group_ip: Ipv4Address,
        host_ip: Ipv4Address,
    },
    FastLeavePruned {
        vni: u32,
        port_id: u16,
        source_ip: Ipv4Address,
        group_ip: Ipv4Address,
        leaving_host: Ipv4Address,
        smet_withdraw: bool,
    },
    SubscriberRemovedRemainingActive {
        vni: u32,
        port_id: u16,
        source_ip: Ipv4Address,
        group_ip: Ipv4Address,
        leaving_host: Ipv4Address,
        remaining_subscribers: usize,
    },
    ChannelNotFound {
        vni: u32,
        port_id: u16,
        source_ip: Ipv4Address,
        group_ip: Ipv4Address,
    },
}

#[derive(Debug, Clone)]
pub struct EvpnIgmpExplicitTrackingEngine {
    pub channels: Vec<ChannelPortState>,
    pub subscriber_timeout_secs: u64,
    pub total_reports_processed: u64,
    pub total_leaves_processed: u64,
    pub total_fast_leaves: u64,
    pub total_smet_advertisements: u64,
    pub total_smet_withdrawals: u64,
}

impl EvpnIgmpExplicitTrackingEngine {
    pub fn new(subscriber_timeout_secs: u64) -> Self {
        Self {
            channels: Vec::new(),
            subscriber_timeout_secs: if subscriber_timeout_secs == 0 {
                DEFAULT_EXPLICIT_TRACKING_TIMEOUT_SECS
            } else {
                subscriber_timeout_secs
            },
            total_reports_processed: 0,
            total_leaves_processed: 0,
            total_fast_leaves: 0,
            total_smet_advertisements: 0,
            total_smet_withdrawals: 0,
        }
    }

    pub fn process_membership_report(
        &mut self,
        vni: u32,
        port_id: u16,
        source_ip: Ipv4Address,
        group_ip: Ipv4Address,
        host_ip: Ipv4Address,
        current_time_secs: u64,
    ) -> ExplicitTrackingVerdict {
        self.total_reports_processed += 1;

        let channel_idx = self.channels.iter().position(|c| {
            c.vni == vni
                && c.port_id == port_id
                && c.source_ip == source_ip
                && c.group_ip == group_ip
        });

        if let Some(idx) = channel_idx {
            let channel = &mut self.channels[idx];
            if let Some(sub) = channel
                .subscribers
                .iter_mut()
                .find(|s| s.host_ip == host_ip)
            {
                sub.last_report_secs = current_time_secs;
                ExplicitTrackingVerdict::SubscriberRefreshed {
                    vni,
                    port_id,
                    source_ip,
                    group_ip,
                    host_ip,
                }
            } else {
                channel.subscribers.push(HostSubscriber {
                    host_ip,
                    last_report_secs: current_time_secs,
                });
                channel.is_forwarding = true;
                ExplicitTrackingVerdict::SubscriberAdded {
                    vni,
                    port_id,
                    source_ip,
                    group_ip,
                    host_ip,
                    total_subscribers: channel.subscribers.len(),
                    smet_advertise: false, // Already active channel
                }
            }
        } else {
            // First subscriber on this port -> Advertise SMET Route Type 6
            let subscribers = vec![HostSubscriber {
                host_ip,
                last_report_secs: current_time_secs,
            }];
            self.channels.push(ChannelPortState {
                vni,
                port_id,
                source_ip,
                group_ip,
                subscribers,
                is_forwarding: true,
            });
            self.total_smet_advertisements += 1;
            ExplicitTrackingVerdict::SubscriberAdded {
                vni,
                port_id,
                source_ip,
                group_ip,
                host_ip,
                total_subscribers: 1,
                smet_advertise: true,
            }
        }
    }

    pub fn process_leave_group(
        &mut self,
        vni: u32,
        port_id: u16,
        source_ip: Ipv4Address,
        group_ip: Ipv4Address,
        leaving_host: Ipv4Address,
    ) -> ExplicitTrackingVerdict {
        self.total_leaves_processed += 1;

        let channel_idx = self.channels.iter().position(|c| {
            c.vni == vni
                && c.port_id == port_id
                && c.source_ip == source_ip
                && c.group_ip == group_ip
        });

        match channel_idx {
            Some(idx) => {
                let channel = &mut self.channels[idx];
                channel.subscribers.retain(|s| s.host_ip != leaving_host);

                if channel.subscribers.is_empty() {
                    channel.is_forwarding = false;
                    self.total_fast_leaves += 1;
                    self.total_smet_withdrawals += 1;
                    ExplicitTrackingVerdict::FastLeavePruned {
                        vni,
                        port_id,
                        source_ip,
                        group_ip,
                        leaving_host,
                        smet_withdraw: true,
                    }
                } else {
                    let remaining = channel.subscribers.len();
                    ExplicitTrackingVerdict::SubscriberRemovedRemainingActive {
                        vni,
                        port_id,
                        source_ip,
                        group_ip,
                        leaving_host,
                        remaining_subscribers: remaining,
                    }
                }
            }
            None => ExplicitTrackingVerdict::ChannelNotFound {
                vni,
                port_id,
                source_ip,
                group_ip,
            },
        }
    }

    pub fn check_subscriber_aging(
        &mut self,
        current_time_secs: u64,
    ) -> Vec<ExplicitTrackingVerdict> {
        let mut timeouts = Vec::new();
        let timeout_thresh = self.subscriber_timeout_secs;

        for channel in &mut self.channels {
            let was_forwarding = channel.is_forwarding;
            channel.subscribers.retain(|sub| {
                current_time_secs.saturating_sub(sub.last_report_secs) <= timeout_thresh
            });

            if was_forwarding && channel.subscribers.is_empty() {
                channel.is_forwarding = false;
                self.total_smet_withdrawals += 1;
                timeouts.push(ExplicitTrackingVerdict::FastLeavePruned {
                    vni: channel.vni,
                    port_id: channel.port_id,
                    source_ip: channel.source_ip,
                    group_ip: channel.group_ip,
                    leaving_host: Ipv4Address::new(0, 0, 0, 0),
                    smet_withdraw: true,
                });
            }
        }

        timeouts
    }

    pub fn is_port_forwarding(
        &self,
        vni: u32,
        port_id: u16,
        source_ip: Ipv4Address,
        group_ip: Ipv4Address,
    ) -> bool {
        self.channels
            .iter()
            .find(|c| {
                c.vni == vni
                    && c.port_id == port_id
                    && c.source_ip == source_ip
                    && c.group_ip == group_ip
            })
            .map(|c| c.is_forwarding)
            .unwrap_or(false)
    }

    pub fn reset(&mut self) {
        self.channels.clear();
        self.total_reports_processed = 0;
        self.total_leaves_processed = 0;
        self.total_fast_leaves = 0;
        self.total_smet_advertisements = 0;
        self.total_smet_withdrawals = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_explicit_tracking_lifecycle() {
        let mut engine = EvpnIgmpExplicitTrackingEngine::new(60);
        let src = Ipv4Address::new(192, 168, 1, 100);
        let grp = Ipv4Address::new(232, 1, 1, 1);
        let h1 = Ipv4Address::new(10, 0, 0, 10);
        let h2 = Ipv4Address::new(10, 0, 0, 20);

        // Host 1 joins -> SMET Advertised
        let v1 = engine.process_membership_report(100, 1, src, grp, h1, 1000);
        assert!(matches!(
            v1,
            ExplicitTrackingVerdict::SubscriberAdded {
                smet_advertise: true,
                total_subscribers: 1,
                ..
            }
        ));

        // Host 2 joins on same port
        let v2 = engine.process_membership_report(100, 1, src, grp, h2, 1010);
        assert!(matches!(
            v2,
            ExplicitTrackingVerdict::SubscriberAdded {
                smet_advertise: false,
                total_subscribers: 2,
                ..
            }
        ));

        // Host 1 leaves -> Still active because Host 2 remains
        let v3 = engine.process_leave_group(100, 1, src, grp, h1);
        assert!(matches!(
            v3,
            ExplicitTrackingVerdict::SubscriberRemovedRemainingActive {
                remaining_subscribers: 1,
                ..
            }
        ));
        assert!(engine.is_port_forwarding(100, 1, src, grp));

        // Host 2 leaves -> Fast Leave & SMET Withdraw
        let v4 = engine.process_leave_group(100, 1, src, grp, h2);
        assert!(matches!(
            v4,
            ExplicitTrackingVerdict::FastLeavePruned {
                smet_withdraw: true,
                ..
            }
        ));
        assert!(!engine.is_port_forwarding(100, 1, src, grp));
    }
}
