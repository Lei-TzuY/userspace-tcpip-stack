//! EVPN Layer 2 Multicast IGMP/MLD Snooping Group Boundary Filter & CAC Engine (RFC 9251)
//!
//! Enforces per-port / per-VNI multicast group access control lists (ACLs),
//! Channel Admission Control (CAC) subscription quotas, and rogue group join suppression.

use crate::ipv4::Ipv4Address;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum McastAclAction {
    Permit,
    Deny,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct McastFilterRule {
    pub vni: u32,
    pub port_id: u32,
    pub group_start: Ipv4Address,
    pub group_end: Ipv4Address,
    pub action: McastAclAction,
    pub description: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum McastFilterVerdict {
    JoinPermitted {
        vni: u32,
        port_id: u32,
        group_ip: Ipv4Address,
        current_active_channels: usize,
    },
    JoinDeniedByAcl {
        vni: u32,
        port_id: u32,
        group_ip: Ipv4Address,
        reason: String,
    },
    JoinDeniedCacLimitReached {
        vni: u32,
        port_id: u32,
        group_ip: Ipv4Address,
        max_limit: usize,
    },
    ChannelLeft {
        vni: u32,
        port_id: u32,
        group_ip: Ipv4Address,
        remaining_channels: usize,
    },
}

#[derive(Debug, Clone)]
pub struct EvpnMcastSnoopingFilterEngine {
    pub max_channels_per_port: usize,
    pub rules: Vec<McastFilterRule>,
    pub active_subscriptions: Vec<(u32, u32, Ipv4Address)>, // (vni, port_id, group_ip)
    pub total_joins_evaluated: usize,
    pub total_joins_permitted: usize,
    pub total_joins_denied_acl: usize,
    pub total_joins_denied_cac_limit: usize,
}

impl EvpnMcastSnoopingFilterEngine {
    pub fn new(max_channels_per_port: usize) -> Self {
        Self {
            max_channels_per_port: max_channels_per_port.max(1),
            rules: Vec::new(),
            active_subscriptions: Vec::new(),
            total_joins_evaluated: 0,
            total_joins_permitted: 0,
            total_joins_denied_acl: 0,
            total_joins_denied_cac_limit: 0,
        }
    }

    /// Adds a multicast group filter rule.
    pub fn add_rule(
        &mut self,
        vni: u32,
        port_id: u32,
        group_start: Ipv4Address,
        group_end: Ipv4Address,
        action: McastAclAction,
        description: &str,
    ) {
        self.rules.push(McastFilterRule {
            vni,
            port_id,
            group_start,
            group_end,
            action,
            description: description.to_string(),
        });
    }

    /// Evaluates an IGMP/MLD Join subscription request against ACLs and CAC limits.
    pub fn evaluate_join(
        &mut self,
        vni: u32,
        port_id: u32,
        group_ip: Ipv4Address,
    ) -> McastFilterVerdict {
        self.total_joins_evaluated += 1;

        let grp_u32 = u32::from_be_bytes(group_ip.0);

        // 1. ACL Rule Evaluation
        for rule in &self.rules {
            if (rule.vni == 0 || rule.vni == vni) && (rule.port_id == 0 || rule.port_id == port_id)
            {
                let start_u32 = u32::from_be_bytes(rule.group_start.0);
                let end_u32 = u32::from_be_bytes(rule.group_end.0);
                if grp_u32 >= start_u32 && grp_u32 <= end_u32 {
                    if rule.action == McastAclAction::Deny {
                        self.total_joins_denied_acl += 1;
                        return McastFilterVerdict::JoinDeniedByAcl {
                            vni,
                            port_id,
                            group_ip,
                            reason: rule.description.clone(),
                        };
                    }
                    // Explicitly permitted by rule
                    break;
                }
            }
        }

        // 2. CAC Limit Check
        let is_already_subscribed = self
            .active_subscriptions
            .iter()
            .any(|&(v, p, g)| v == vni && p == port_id && g == group_ip);
        if !is_already_subscribed {
            let port_channel_count = self
                .active_subscriptions
                .iter()
                .filter(|&(v, p, _)| *v == vni && *p == port_id)
                .count();
            if port_channel_count >= self.max_channels_per_port {
                self.total_joins_denied_cac_limit += 1;
                return McastFilterVerdict::JoinDeniedCacLimitReached {
                    vni,
                    port_id,
                    group_ip,
                    max_limit: self.max_channels_per_port,
                };
            }
            self.active_subscriptions.push((vni, port_id, group_ip));
        }

        self.total_joins_permitted += 1;
        let count = self
            .active_subscriptions
            .iter()
            .filter(|&(v, p, _)| *v == vni && *p == port_id)
            .count();
        McastFilterVerdict::JoinPermitted {
            vni,
            port_id,
            group_ip,
            current_active_channels: count,
        }
    }

    /// Processes a leave event for a multicast channel on a port.
    pub fn process_leave(
        &mut self,
        vni: u32,
        port_id: u32,
        group_ip: Ipv4Address,
    ) -> McastFilterVerdict {
        self.active_subscriptions
            .retain(|&(v, p, g)| !(v == vni && p == port_id && g == group_ip));
        let remaining = self
            .active_subscriptions
            .iter()
            .filter(|&(v, p, _)| *v == vni && *p == port_id)
            .count();
        McastFilterVerdict::ChannelLeft {
            vni,
            port_id,
            group_ip,
            remaining_channels: remaining,
        }
    }

    /// Alias for `process_leave`.
    pub fn leave_channel(
        &mut self,
        vni: u32,
        port_id: u32,
        group_ip: Ipv4Address,
    ) -> McastFilterVerdict {
        self.process_leave(vni, port_id, group_ip)
    }

    /// Clears active subscriptions and filters.
    pub fn reset(&mut self) {
        self.rules.clear();
        self.active_subscriptions.clear();
        self.total_joins_evaluated = 0;
        self.total_joins_permitted = 0;
        self.total_joins_denied_acl = 0;
        self.total_joins_denied_cac_limit = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_snooping_filter_acl_and_cac() {
        let mut engine = EvpnMcastSnoopingFilterEngine::new(2);
        engine.add_rule(
            100,
            1,
            Ipv4Address::new(239, 255, 0, 0),
            Ipv4Address::new(239, 255, 255, 255),
            McastAclAction::Deny,
            "Block local scoped admin groups",
        );

        let v_denied = engine.evaluate_join(100, 1, Ipv4Address::new(239, 255, 1, 1));
        assert!(matches!(
            v_denied,
            McastFilterVerdict::JoinDeniedByAcl { .. }
        ));

        let v_ok1 = engine.evaluate_join(100, 1, Ipv4Address::new(232, 1, 1, 1));
        assert!(matches!(
            v_ok1,
            McastFilterVerdict::JoinPermitted {
                current_active_channels: 1,
                ..
            }
        ));

        let v_ok2 = engine.evaluate_join(100, 1, Ipv4Address::new(232, 1, 1, 2));
        assert!(matches!(
            v_ok2,
            McastFilterVerdict::JoinPermitted {
                current_active_channels: 2,
                ..
            }
        ));

        let v_cac = engine.evaluate_join(100, 1, Ipv4Address::new(232, 1, 1, 3));
        assert!(matches!(
            v_cac,
            McastFilterVerdict::JoinDeniedCacLimitReached { max_limit: 2, .. }
        ));
    }
}
