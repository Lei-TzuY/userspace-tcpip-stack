//! BGP Link-State (BGP-LS - RFC 7752 / RFC 9552).
//!
//! Exposes IGP (OSPF/IS-IS) link-state, TE attributes, and network topology to SDN controllers
//! and Path Computation Elements (PCE) via BGP NLRI (AFI 16388, SAFI 71).

use crate::ipv4::Ipv4Address;
use std::collections::HashMap;

pub const BGP_AFI_BGP_LS: u16 = 16388;
pub const BGP_SAFI_BGP_LS: u8 = 71;

pub const BGP_LS_NLRI_NODE: u16 = 1;
pub const BGP_LS_NLRI_LINK: u16 = 2;
pub const BGP_LS_NLRI_IPV4_PREFIX: u16 = 3;
pub const BGP_LS_NLRI_IPV6_PREFIX: u16 = 4;

// BGP-LS TLVs
pub const BGP_LS_TLV_LOCAL_NODE_DESCRIPTORS: u16 = 256;
pub const BGP_LS_TLV_REMOTE_NODE_DESCRIPTORS: u16 = 257;
pub const BGP_LS_TLV_LINK_DESCRIPTORS: u16 = 258;
pub const BGP_LS_TLV_NODE_NAME: u16 = 1026;
pub const BGP_LS_TLV_ADMIN_GROUP: u16 = 1088;
pub const BGP_LS_TLV_MAX_LINK_BANDWIDTH: u16 = 1089;
pub const BGP_LS_TLV_MAX_RESERVABLE_BANDWIDTH: u16 = 1090;
pub const BGP_LS_TLV_TE_DEFAULT_METRIC: u16 = 1092;
pub const BGP_LS_TLV_IGP_ROUTER_ID: u16 = 512;
pub const BGP_LS_TLV_AUTONOMOUS_SYSTEM: u16 = 514;
pub const BGP_LS_TLV_IPV4_INTERFACE_ADDR: u16 = 259;
pub const BGP_LS_TLV_IPV4_NEIGHBOR_ADDR: u16 = 260;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BgpLsNodeDescriptor {
    pub asn: u32,
    pub igp_router_id: Ipv4Address,
    pub node_name: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct BgpLsLinkDescriptor {
    pub local_node: BgpLsNodeDescriptor,
    pub remote_node: BgpLsNodeDescriptor,
    pub local_interface_ip: Ipv4Address,
    pub remote_neighbor_ip: Ipv4Address,
    pub te_metric: u32,
    pub max_bandwidth_bps: f32,
    pub max_reservable_bandwidth_bps: f32,
    pub admin_group_color: u32,
}

#[derive(Debug, Clone, PartialEq)]
pub enum BgpLsNlri {
    Node(BgpLsNodeDescriptor),
    Link(BgpLsLinkDescriptor),
    Ipv4Prefix {
        node: BgpLsNodeDescriptor,
        prefix: Ipv4Address,
        mask_len: u8,
        igp_metric: u32,
    },
}

impl BgpLsNlri {
    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        match self {
            BgpLsNlri::Node(node) => {
                buf.extend_from_slice(&BGP_LS_NLRI_NODE.to_be_bytes());
                let mut body = Vec::new();

                // Local Node Descriptors TLV 256
                let mut desc = Vec::new();
                desc.extend_from_slice(&BGP_LS_TLV_AUTONOMOUS_SYSTEM.to_be_bytes());
                desc.extend_from_slice(&4u16.to_be_bytes());
                desc.extend_from_slice(&node.asn.to_be_bytes());

                desc.extend_from_slice(&BGP_LS_TLV_IGP_ROUTER_ID.to_be_bytes());
                desc.extend_from_slice(&4u16.to_be_bytes());
                desc.extend_from_slice(&node.igp_router_id.0);

                if let Some(ref name) = node.node_name {
                    desc.extend_from_slice(&BGP_LS_TLV_NODE_NAME.to_be_bytes());
                    desc.extend_from_slice(&(name.len() as u16).to_be_bytes());
                    desc.extend_from_slice(name.as_bytes());
                }

                body.extend_from_slice(&BGP_LS_TLV_LOCAL_NODE_DESCRIPTORS.to_be_bytes());
                body.extend_from_slice(&(desc.len() as u16).to_be_bytes());
                body.extend_from_slice(&desc);

                buf.extend_from_slice(&(body.len() as u16).to_be_bytes());
                buf.extend_from_slice(&body);
            }
            BgpLsNlri::Link(link) => {
                buf.extend_from_slice(&BGP_LS_NLRI_LINK.to_be_bytes());
                let mut body = Vec::new();

                // Local interface IP TLV 259
                body.extend_from_slice(&BGP_LS_TLV_IPV4_INTERFACE_ADDR.to_be_bytes());
                body.extend_from_slice(&4u16.to_be_bytes());
                body.extend_from_slice(&link.local_interface_ip.0);

                // Remote neighbor IP TLV 260
                body.extend_from_slice(&BGP_LS_TLV_IPV4_NEIGHBOR_ADDR.to_be_bytes());
                body.extend_from_slice(&4u16.to_be_bytes());
                body.extend_from_slice(&link.remote_neighbor_ip.0);

                // TE Metric TLV 1092
                body.extend_from_slice(&BGP_LS_TLV_TE_DEFAULT_METRIC.to_be_bytes());
                body.extend_from_slice(&4u16.to_be_bytes());
                body.extend_from_slice(&link.te_metric.to_be_bytes());

                buf.extend_from_slice(&(body.len() as u16).to_be_bytes());
                buf.extend_from_slice(&body);
            }
            BgpLsNlri::Ipv4Prefix {
                node,
                prefix,
                mask_len,
                igp_metric,
            } => {
                buf.extend_from_slice(&BGP_LS_NLRI_IPV4_PREFIX.to_be_bytes());
                let mut body = Vec::new();
                body.extend_from_slice(&node.igp_router_id.0);
                body.push(*mask_len);
                body.extend_from_slice(&prefix.0);
                body.extend_from_slice(&igp_metric.to_be_bytes());

                buf.extend_from_slice(&(body.len() as u16).to_be_bytes());
                buf.extend_from_slice(&body);
            }
        }
        buf
    }

    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 4 {
            return None;
        }

        let nlri_type = u16::from_be_bytes([data[0], data[1]]);
        let total_len = u16::from_be_bytes([data[2], data[3]]) as usize;

        if data.len() < 4 + total_len {
            return None;
        }

        let body = &data[4..4 + total_len];
        match nlri_type {
            BGP_LS_NLRI_NODE => {
                let mut asn = 0;
                let mut igp_router_id = Ipv4Address::new(0, 0, 0, 0);
                let mut node_name = None;

                let mut offset = 0;
                while offset + 4 <= body.len() {
                    let tlv_type = u16::from_be_bytes([body[offset], body[offset + 1]]);
                    let tlv_len = u16::from_be_bytes([body[offset + 2], body[offset + 3]]) as usize;
                    offset += 4;

                    if offset + tlv_len > body.len() {
                        return None;
                    }

                    let tlv_val = &body[offset..offset + tlv_len];
                    if tlv_type == BGP_LS_TLV_LOCAL_NODE_DESCRIPTORS {
                        let mut sub_off = 0;
                        while sub_off + 4 <= tlv_val.len() {
                            let s_type =
                                u16::from_be_bytes([tlv_val[sub_off], tlv_val[sub_off + 1]]);
                            let s_len =
                                u16::from_be_bytes([tlv_val[sub_off + 2], tlv_val[sub_off + 3]])
                                    as usize;
                            sub_off += 4;

                            if sub_off + s_len > tlv_val.len() {
                                return None;
                            }

                            let s_val = &tlv_val[sub_off..sub_off + s_len];
                            match s_type {
                                BGP_LS_TLV_AUTONOMOUS_SYSTEM if s_val.len() >= 4 => {
                                    asn = u32::from_be_bytes([
                                        s_val[0], s_val[1], s_val[2], s_val[3],
                                    ]);
                                }
                                BGP_LS_TLV_IGP_ROUTER_ID if s_val.len() >= 4 => {
                                    igp_router_id =
                                        Ipv4Address([s_val[0], s_val[1], s_val[2], s_val[3]]);
                                }
                                BGP_LS_TLV_NODE_NAME => {
                                    node_name =
                                        std::str::from_utf8(s_val).ok().map(|s| s.to_string());
                                }
                                _ => {}
                            }
                            sub_off += s_len;
                        }
                        if sub_off != tlv_val.len() {
                            return None;
                        }
                    }
                    offset += tlv_len;
                }
                if offset != body.len() {
                    return None;
                }

                Some(BgpLsNlri::Node(BgpLsNodeDescriptor {
                    asn,
                    igp_router_id,
                    node_name,
                }))
            }
            BGP_LS_NLRI_LINK => {
                let mut local_ip = Ipv4Address::new(0, 0, 0, 0);
                let mut remote_ip = Ipv4Address::new(0, 0, 0, 0);
                let mut te_metric = 10;

                let mut offset = 0;
                while offset + 4 <= body.len() {
                    let tlv_type = u16::from_be_bytes([body[offset], body[offset + 1]]);
                    let tlv_len = u16::from_be_bytes([body[offset + 2], body[offset + 3]]) as usize;
                    offset += 4;

                    if offset + tlv_len > body.len() {
                        return None;
                    }

                    let tlv_val = &body[offset..offset + tlv_len];
                    match tlv_type {
                        BGP_LS_TLV_IPV4_INTERFACE_ADDR if tlv_val.len() >= 4 => {
                            local_ip =
                                Ipv4Address([tlv_val[0], tlv_val[1], tlv_val[2], tlv_val[3]]);
                        }
                        BGP_LS_TLV_IPV4_NEIGHBOR_ADDR if tlv_val.len() >= 4 => {
                            remote_ip =
                                Ipv4Address([tlv_val[0], tlv_val[1], tlv_val[2], tlv_val[3]]);
                        }
                        BGP_LS_TLV_TE_DEFAULT_METRIC if tlv_val.len() >= 4 => {
                            te_metric = u32::from_be_bytes([
                                tlv_val[0], tlv_val[1], tlv_val[2], tlv_val[3],
                            ]);
                        }
                        _ => {}
                    }
                    offset += tlv_len;
                }
                if offset != body.len() {
                    return None;
                }

                Some(BgpLsNlri::Link(BgpLsLinkDescriptor {
                    local_node: BgpLsNodeDescriptor {
                        asn: 65001,
                        igp_router_id: local_ip,
                        node_name: None,
                    },
                    remote_node: BgpLsNodeDescriptor {
                        asn: 65001,
                        igp_router_id: remote_ip,
                        node_name: None,
                    },
                    local_interface_ip: local_ip,
                    remote_neighbor_ip: remote_ip,
                    te_metric,
                    max_bandwidth_bps: 10_000_000_000.0,
                    max_reservable_bandwidth_bps: 8_000_000_000.0,
                    admin_group_color: 0x00000001,
                }))
            }
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct BgpLsTopologyDatabase {
    pub nodes: HashMap<Ipv4Address, BgpLsNodeDescriptor>,
    pub links: Vec<BgpLsLinkDescriptor>,
}

impl BgpLsTopologyDatabase {
    pub fn new() -> Self {
        BgpLsTopologyDatabase {
            nodes: HashMap::new(),
            links: Vec::new(),
        }
    }

    pub fn ingest_nlri(&mut self, nlri: BgpLsNlri) {
        match nlri {
            BgpLsNlri::Node(node) => {
                self.nodes.insert(node.igp_router_id, node);
            }
            BgpLsNlri::Link(link) => {
                self.links.push(link);
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bgp_ls_rejects_truncated_node_tlv_value() {
        let raw = [
            0x00, 0x01, 0x00, 0x08, 0x01, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00,
        ];
        assert!(BgpLsNlri::parse(&raw).is_none());
    }

    #[test]
    fn test_bgp_ls_rejects_truncated_node_descriptor_sub_tlv() {
        let raw = [
            0x00, 0x01, 0x00, 0x0c, 0x01, 0x00, 0x00, 0x08, 0x02, 0x02, 0x00, 0x08, 0x00, 0x00,
            0x00, 0x01,
        ];
        assert!(BgpLsNlri::parse(&raw).is_none());
    }

    #[test]
    fn test_bgp_ls_rejects_trailing_partial_tlv_header() {
        let raw = [0x00, 0x01, 0x00, 0x03, 0xaa, 0xbb, 0xcc];
        assert!(BgpLsNlri::parse(&raw).is_none());
    }

    #[test]
    fn test_bgp_ls_rejects_truncated_link_tlv_value() {
        let raw = [0x00, 0x02, 0x00, 0x08, 0x01, 0x03, 0x00, 0x08, 192, 0, 2, 1];
        assert!(BgpLsNlri::parse(&raw).is_none());
    }

    #[test]
    fn test_bgp_ls_node_and_link_nlri_roundtrip() {
        let node = BgpLsNodeDescriptor {
            asn: 65000,
            igp_router_id: Ipv4Address::new(10, 0, 0, 1),
            node_name: Some("Spine-01".to_string()),
        };
        let nlri_node = BgpLsNlri::Node(node.clone());
        let raw_node = nlri_node.serialize();

        let parsed_node = BgpLsNlri::parse(&raw_node).unwrap();
        if let BgpLsNlri::Node(parsed) = parsed_node {
            assert_eq!(parsed.asn, 65000);
            assert_eq!(parsed.igp_router_id, Ipv4Address::new(10, 0, 0, 1));
            assert_eq!(parsed.node_name, Some("Spine-01".to_string()));
        } else {
            panic!("Expected Node NLRI");
        }

        let link = BgpLsLinkDescriptor {
            local_node: node.clone(),
            remote_node: BgpLsNodeDescriptor {
                asn: 65000,
                igp_router_id: Ipv4Address::new(10, 0, 0, 2),
                node_name: Some("Leaf-01".to_string()),
            },
            local_interface_ip: Ipv4Address::new(192, 168, 10, 1),
            remote_neighbor_ip: Ipv4Address::new(192, 168, 10, 2),
            te_metric: 25,
            max_bandwidth_bps: 100_000_000_000.0,
            max_reservable_bandwidth_bps: 80_000_000_000.0,
            admin_group_color: 0x01,
        };
        let nlri_link = BgpLsNlri::Link(link);
        let raw_link = nlri_link.serialize();

        let parsed_link = BgpLsNlri::parse(&raw_link).unwrap();
        if let BgpLsNlri::Link(parsed) = parsed_link {
            assert_eq!(parsed.local_interface_ip, Ipv4Address::new(192, 168, 10, 1));
            assert_eq!(parsed.remote_neighbor_ip, Ipv4Address::new(192, 168, 10, 2));
            assert_eq!(parsed.te_metric, 25);
        } else {
            panic!("Expected Link NLRI");
        }
    }
}
