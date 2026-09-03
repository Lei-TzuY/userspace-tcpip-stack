//! BGP Flowspec Layer 2 Matching Component Attributes (RFC 8955 / draft-ietf-idr-flowspec-l2vpn).
//!
//! Provides Ethernet Layer 2 flow filtering, frame classification (Source/Destination MAC,
//! EtherType, Single/Dual VLAN tags, 802.1p PCP), and policy enforcement (Drop, Rate-Limit,
//! Redirect, and PCP/VLAN remarking) for EVPN / datacenter fabric switches.

use crate::ethernet::MacAddress;
use std::fmt;

pub const FLOWSPEC_L2_TYPE_SRC_MAC: u8 = 0x10;
pub const FLOWSPEC_L2_TYPE_DST_MAC: u8 = 0x11;
pub const FLOWSPEC_L2_TYPE_ETHERTYPE: u8 = 0x12;
pub const FLOWSPEC_L2_TYPE_VLAN_ID: u8 = 0x13;
pub const FLOWSPEC_L2_TYPE_PCP: u8 = 0x14;
pub const FLOWSPEC_L2_TYPE_INNER_VLAN_ID: u8 = 0x15;

/// Layer 2 Flowspec Filtering Action.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FlowspecL2Action {
    Drop,
    RateLimitBps(u32),
    RedirectInterface(String),
    RedirectVni(u32),
    RemarkPcp(u8),
    RemarkVlan(u16),
}

impl fmt::Display for FlowspecL2Action {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FlowspecL2Action::Drop => write!(f, "DROP"),
            FlowspecL2Action::RateLimitBps(r) => write!(f, "RATE-LIMIT ({} bps)", r),
            FlowspecL2Action::RedirectInterface(iface) => write!(f, "REDIRECT-IFACE ({})", iface),
            FlowspecL2Action::RedirectVni(vni) => write!(f, "REDIRECT-VNI ({})", vni),
            FlowspecL2Action::RemarkPcp(pcp) => write!(f, "REMARK-PCP ({})", pcp),
            FlowspecL2Action::RemarkVlan(vlan) => write!(f, "REMARK-VLAN ({})", vlan),
        }
    }
}

/// Match Criteria for Layer 2 Frames.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct FlowspecL2Match {
    pub src_mac: Option<MacAddress>,
    pub dst_mac: Option<MacAddress>,
    pub ethertype: Option<u16>,
    pub vlan_id: Option<u16>,
    pub pcp: Option<u8>,
    pub inner_vlan_id: Option<u16>,
}

/// Layer 2 Flowspec Rule with Priority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlowspecL2Rule {
    pub rule_id: u32,
    pub priority: u32, // Higher number = higher evaluation precedence
    pub match_fields: FlowspecL2Match,
    pub action: FlowspecL2Action,
}

/// Extracted Layer 2 Header Fields from a Raw Ethernet Frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedL2Frame {
    pub src_mac: MacAddress,
    pub dst_mac: MacAddress,
    pub ethertype: u16,
    pub vlan_id: Option<u16>,
    pub pcp: Option<u8>,
    pub inner_vlan_id: Option<u16>,
    pub payload_offset: usize,
}

impl ParsedL2Frame {
    pub fn parse(raw_frame: &[u8]) -> Option<Self> {
        if raw_frame.len() < 14 {
            return None;
        }

        let dst_mac = MacAddress::new([
            raw_frame[0],
            raw_frame[1],
            raw_frame[2],
            raw_frame[3],
            raw_frame[4],
            raw_frame[5],
        ]);
        let src_mac = MacAddress::new([
            raw_frame[6],
            raw_frame[7],
            raw_frame[8],
            raw_frame[9],
            raw_frame[10],
            raw_frame[11],
        ]);

        let mut offset = 12;
        let mut ethertype = u16::from_be_bytes([raw_frame[offset], raw_frame[offset + 1]]);
        offset += 2;

        let mut vlan_id = None;
        let mut pcp = None;
        let mut inner_vlan_id = None;

        // Check for 802.1Q (0x8100) or 802.1ad (0x88A8) outer tag
        if (ethertype == 0x8100 || ethertype == 0x88A8) && raw_frame.len() >= offset + 4 {
            let tci = u16::from_be_bytes([raw_frame[offset], raw_frame[offset + 1]]);
            pcp = Some(((tci >> 13) & 0x07) as u8);
            vlan_id = Some(tci & 0x0FFF);
            offset += 2;

            ethertype = u16::from_be_bytes([raw_frame[offset], raw_frame[offset + 1]]);
            offset += 2;

            // Check for QinQ inner 802.1Q tag (0x8100)
            if ethertype == 0x8100 && raw_frame.len() >= offset + 4 {
                let inner_tci = u16::from_be_bytes([raw_frame[offset], raw_frame[offset + 1]]);
                inner_vlan_id = Some(inner_tci & 0x0FFF);
                offset += 2;

                ethertype = u16::from_be_bytes([raw_frame[offset], raw_frame[offset + 1]]);
                offset += 2;
            }
        }

        Some(ParsedL2Frame {
            src_mac,
            dst_mac,
            ethertype,
            vlan_id,
            pcp,
            inner_vlan_id,
            payload_offset: offset,
        })
    }
}

/// Policy Enforcement Decision on an Ethernet Frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FlowspecL2Decision {
    Pass,
    Drop { rule_id: u32 },
    RateLimit { rule_id: u32, bps: u32 },
    RedirectInterface { rule_id: u32, iface: String },
    RedirectVni { rule_id: u32, vni: u32 },
    RemarkPcp { rule_id: u32, new_pcp: u8 },
    RemarkVlan { rule_id: u32, new_vlan: u16 },
}

/// BGP Flowspec Layer 2 Filter Engine.
#[derive(Debug, Clone, Default)]
pub struct FlowspecL2Engine {
    pub rules: Vec<FlowspecL2Rule>,
}

impl FlowspecL2Engine {
    pub fn new() -> Self {
        Self { rules: Vec::new() }
    }

    /// Installs a new Flowspec L2 rule and keeps rules sorted by priority (descending).
    pub fn add_rule(&mut self, rule: FlowspecL2Rule) {
        self.rules.retain(|r| r.rule_id != rule.rule_id);
        self.rules.push(rule);
        self.rules.sort_by(|a, b| b.priority.cmp(&a.priority));
    }

    pub fn remove_rule(&mut self, rule_id: u32) -> bool {
        let initial_len = self.rules.len();
        self.rules.retain(|r| r.rule_id != rule_id);
        self.rules.len() < initial_len
    }

    /// Evaluates an incoming Ethernet frame against installed L2 Flowspec rules.
    pub fn evaluate_frame(&self, raw_frame: &[u8]) -> FlowspecL2Decision {
        let parsed = match ParsedL2Frame::parse(raw_frame) {
            Some(f) => f,
            None => return FlowspecL2Decision::Pass,
        };

        for rule in &self.rules {
            let m = &rule.match_fields;

            if let Some(ref smac) = m.src_mac {
                if parsed.src_mac != *smac {
                    continue;
                }
            }

            if let Some(ref dmac) = m.dst_mac {
                if parsed.dst_mac != *dmac {
                    continue;
                }
            }

            if let Some(et) = m.ethertype {
                if parsed.ethertype != et {
                    continue;
                }
            }

            if let Some(vid) = m.vlan_id {
                if parsed.vlan_id != Some(vid) {
                    continue;
                }
            }

            if let Some(pcp_val) = m.pcp {
                if parsed.pcp != Some(pcp_val) {
                    continue;
                }
            }

            if let Some(in_vid) = m.inner_vlan_id {
                if parsed.inner_vlan_id != Some(in_vid) {
                    continue;
                }
            }

            // All match fields satisfied
            return match &rule.action {
                FlowspecL2Action::Drop => FlowspecL2Decision::Drop {
                    rule_id: rule.rule_id,
                },
                FlowspecL2Action::RateLimitBps(bps) => FlowspecL2Decision::RateLimit {
                    rule_id: rule.rule_id,
                    bps: *bps,
                },
                FlowspecL2Action::RedirectInterface(iface) => {
                    FlowspecL2Decision::RedirectInterface {
                        rule_id: rule.rule_id,
                        iface: iface.clone(),
                    }
                }
                FlowspecL2Action::RedirectVni(vni) => FlowspecL2Decision::RedirectVni {
                    rule_id: rule.rule_id,
                    vni: *vni,
                },
                FlowspecL2Action::RemarkPcp(new_pcp) => FlowspecL2Decision::RemarkPcp {
                    rule_id: rule.rule_id,
                    new_pcp: *new_pcp,
                },
                FlowspecL2Action::RemarkVlan(new_vlan) => FlowspecL2Decision::RemarkVlan {
                    rule_id: rule.rule_id,
                    new_vlan: *new_vlan,
                },
            };
        }

        FlowspecL2Decision::Pass
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_flowspec_l2_vlan_pcp_mac_filtering() {
        let mut engine = FlowspecL2Engine::new();

        let attacker_mac = MacAddress::new([0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01]);
        let victim_mac = MacAddress::new([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);

        // Rule 1: Drop frames from attacker MAC on VLAN 100
        engine.add_rule(FlowspecL2Rule {
            rule_id: 1,
            priority: 100,
            match_fields: FlowspecL2Match {
                src_mac: Some(attacker_mac),
                dst_mac: None,
                ethertype: None,
                vlan_id: Some(100),
                pcp: None,
                inner_vlan_id: None,
            },
            action: FlowspecL2Action::Drop,
        });

        // Rule 2: Remark PCP to 7 for Voice traffic (EtherType 0x0800, VLAN 200, PCP 5)
        engine.add_rule(FlowspecL2Rule {
            rule_id: 2,
            priority: 80,
            match_fields: FlowspecL2Match {
                src_mac: None,
                dst_mac: Some(victim_mac),
                ethertype: Some(0x0800),
                vlan_id: Some(200),
                pcp: Some(5),
                inner_vlan_id: None,
            },
            action: FlowspecL2Action::RemarkPcp(7),
        });

        // Frame 1: Attacker frame with 802.1Q (VLAN 100, PCP 0)
        let mut frame1 = Vec::new();
        frame1.extend_from_slice(&victim_mac.bytes());
        frame1.extend_from_slice(&attacker_mac.bytes());
        frame1.extend_from_slice(&[0x81, 0x00]); // 802.1Q TPID
        frame1.extend_from_slice(&[0x00, 100]); // PCP 0, VLAN 100
        frame1.extend_from_slice(&[0x08, 0x00]); // EtherType IPv4
        frame1.extend_from_slice(&[0x45, 0x00, 0x00, 0x20]); // IP header snippet

        let dec1 = engine.evaluate_frame(&frame1);
        assert_eq!(dec1, FlowspecL2Decision::Drop { rule_id: 1 });

        // Frame 2: Voice frame (VLAN 200, PCP 5)
        let normal_src = MacAddress::new([0x00, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE]);
        let mut frame2 = Vec::new();
        frame2.extend_from_slice(&victim_mac.bytes());
        frame2.extend_from_slice(&normal_src.bytes());
        frame2.extend_from_slice(&[0x81, 0x00]);
        let tci = (5u16 << 13) | 200u16; // PCP 5, VLAN 200
        frame2.extend_from_slice(&tci.to_be_bytes());
        frame2.extend_from_slice(&[0x08, 0x00]);
        frame2.extend_from_slice(&[0x45, 0x00, 0x00, 0x20]);

        let dec2 = engine.evaluate_frame(&frame2);
        assert_eq!(
            dec2,
            FlowspecL2Decision::RemarkPcp {
                rule_id: 2,
                new_pcp: 7
            }
        );

        // Frame 3: Normal untagged ARP frame passes
        let mut frame3 = Vec::new();
        frame3.extend_from_slice(&victim_mac.bytes());
        frame3.extend_from_slice(&normal_src.bytes());
        frame3.extend_from_slice(&[0x08, 0x06]); // ARP
        frame3.extend_from_slice(b"ARP_BODY_DATA");

        let dec3 = engine.evaluate_frame(&frame3);
        assert_eq!(dec3, FlowspecL2Decision::Pass);
    }
}
