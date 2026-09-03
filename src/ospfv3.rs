//! Open Shortest Path First Version 3 for IPv6 (OSPFv3 - RFC 5340 / RFC 5838).
//!
//! Link-State dynamic routing protocol natively designed for IPv6 over IP Protocol 89
//! (Multicast ff02::5 AllSPFRouters and ff02::6 AllDRouters).
//!
//! Features:
//! - 16-byte OSPFv3 header with Instance ID and 32-bit Router/Area IDs.
//! - OSPFv3 Hello packet handling (Interface ID, Options, Timers, DR/BDR, Neighbors).
//! - OSPFv3 LSA Hierarchy:
//!   - Link-LSA (0x0008 - Link-Local scope: Link-local IPv6 address + interface prefixes)
//!   - Intra-Area-Prefix-LSA (0x2009 - Area scope: prefixes associated with router/network)
//!   - Router-LSA (0x2001 - Area scope: point-to-point and transit links)
//!   - Network-LSA (0x2002 - Area scope)
//!   - AS-External-LSA (0x4005 - AS scope)
//! - OSPFv3 Dijkstra SPF computation producing shortest-path IPv6 FIB routes with Link-Local next hops.

use crate::ipv6::Ipv6Address;
use std::cmp::Ordering;
use std::collections::{BinaryHeap, HashMap};

pub const IP_PROTO_OSPFV3: u8 = 89;

pub const OSPFV3_ALL_SPF_ROUTERS: Ipv6Address =
    Ipv6Address([0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x05]);
pub const OSPFV3_ALL_D_ROUTERS: Ipv6Address =
    Ipv6Address([0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x06]);

pub const OSPFV3_VERSION: u8 = 3;
pub const OSPFV3_HEADER_LEN: usize = 16;
pub const OSPFV3_LSA_HEADER_LEN: usize = 20;

// OSPFv3 Packet Types
pub const OSPFV3_TYPE_HELLO: u8 = 1;
pub const OSPFV3_TYPE_DB_DESC: u8 = 2;
pub const OSPFV3_TYPE_LS_REQ: u8 = 3;
pub const OSPFV3_TYPE_LS_UPDATE: u8 = 4;
pub const OSPFV3_TYPE_LS_ACK: u8 = 5;

// OSPFv3 LSA Function / Type Codes (with U-bit and Scope)
pub const OSPFV3_LSA_ROUTER: u16 = 0x2001;
pub const OSPFV3_LSA_NETWORK: u16 = 0x2002;
pub const OSPFV3_LSA_INTER_AREA_PREFIX: u16 = 0x2003;
pub const OSPFV3_LSA_INTER_AREA_ROUTER: u16 = 0x2004;
pub const OSPFV3_LSA_AS_EXTERNAL: u16 = 0x4005;
pub const OSPFV3_LSA_LINK: u16 = 0x0008;
pub const OSPFV3_LSA_INTRA_AREA_PREFIX: u16 = 0x2009;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ospfv3Header {
    pub version: u8,
    pub msg_type: u8,
    pub packet_length: u16,
    pub router_id: u32,
    pub area_id: u32,
    pub checksum: u16,
    pub instance_id: u8,
    pub reserved: u8,
}

impl Ospfv3Header {
    pub fn parse(data: &[u8]) -> Result<Self, &'static str> {
        if data.len() < OSPFV3_HEADER_LEN {
            return Err("OSPFv3 packet too short for header");
        }
        let version = data[0];
        if version != OSPFV3_VERSION {
            return Err("Invalid OSPFv3 version");
        }
        let msg_type = data[1];
        let packet_length = u16::from_be_bytes([data[2], data[3]]);
        let router_id = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
        let area_id = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);
        let checksum = u16::from_be_bytes([data[12], data[13]]);
        let instance_id = data[14];
        let reserved = data[15];

        Ok(Ospfv3Header {
            version,
            msg_type,
            packet_length,
            router_id,
            area_id,
            checksum,
            instance_id,
            reserved,
        })
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(OSPFV3_HEADER_LEN);
        buf.push(self.version);
        buf.push(self.msg_type);
        buf.extend_from_slice(&self.packet_length.to_be_bytes());
        buf.extend_from_slice(&self.router_id.to_be_bytes());
        buf.extend_from_slice(&self.area_id.to_be_bytes());
        buf.extend_from_slice(&self.checksum.to_be_bytes());
        buf.push(self.instance_id);
        buf.push(self.reserved);
        buf
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ospfv3HelloPacket {
    pub header: Ospfv3Header,
    pub interface_id: u32,
    pub router_priority: u8,
    pub options: u32, // 24-bit options
    pub hello_interval: u16,
    pub dead_interval: u16,
    pub designated_router: u32,
    pub backup_designated_router: u32,
    pub neighbors: Vec<u32>,
}

impl Ospfv3HelloPacket {
    pub fn parse(data: &[u8]) -> Result<Self, &'static str> {
        let header = Ospfv3Header::parse(data)?;
        if header.msg_type != OSPFV3_TYPE_HELLO {
            return Err("Not an OSPFv3 Hello packet");
        }
        if data.len() < OSPFV3_HEADER_LEN + 20 {
            return Err("OSPFv3 Hello packet too short");
        }

        let body = &data[OSPFV3_HEADER_LEN..];
        let interface_id = u32::from_be_bytes([body[0], body[1], body[2], body[3]]);
        let router_priority = body[4];
        let options = ((body[5] as u32) << 16) | ((body[6] as u32) << 8) | (body[7] as u32);
        let hello_interval = u16::from_be_bytes([body[8], body[9]]);
        let dead_interval = u16::from_be_bytes([body[10], body[11]]);
        let designated_router = u32::from_be_bytes([body[12], body[13], body[14], body[15]]);
        let backup_designated_router = u32::from_be_bytes([body[16], body[17], body[18], body[19]]);

        let mut neighbors = Vec::new();
        let mut offset = 20;
        while offset + 4 <= body.len() {
            let neighbor = u32::from_be_bytes([
                body[offset],
                body[offset + 1],
                body[offset + 2],
                body[offset + 3],
            ]);
            neighbors.push(neighbor);
            offset += 4;
        }

        Ok(Ospfv3HelloPacket {
            header,
            interface_id,
            router_priority,
            options,
            hello_interval,
            dead_interval,
            designated_router,
            backup_designated_router,
            neighbors,
        })
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&self.interface_id.to_be_bytes());
        body.push(self.router_priority);
        body.push(((self.options >> 16) & 0xFF) as u8);
        body.push(((self.options >> 8) & 0xFF) as u8);
        body.push((self.options & 0xFF) as u8);
        body.extend_from_slice(&self.hello_interval.to_be_bytes());
        body.extend_from_slice(&self.dead_interval.to_be_bytes());
        body.extend_from_slice(&self.designated_router.to_be_bytes());
        body.extend_from_slice(&self.backup_designated_router.to_be_bytes());

        for neighbor in &self.neighbors {
            body.extend_from_slice(&neighbor.to_be_bytes());
        }

        let mut hdr = self.header.clone();
        hdr.packet_length = (OSPFV3_HEADER_LEN + body.len()) as u16;

        let mut packet = hdr.serialize();
        packet.extend_from_slice(&body);
        packet
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ospfv3LsaHeader {
    pub age: u16,
    pub lsa_type: u16,
    pub link_state_id: u32,
    pub adv_router: u32,
    pub sequence_number: u32,
    pub checksum: u16,
    pub length: u16,
}

impl Ospfv3LsaHeader {
    pub fn parse(data: &[u8]) -> Result<Self, &'static str> {
        if data.len() < OSPFV3_LSA_HEADER_LEN {
            return Err("LSA header too short");
        }
        let age = u16::from_be_bytes([data[0], data[1]]);
        let lsa_type = u16::from_be_bytes([data[2], data[3]]);
        let link_state_id = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
        let adv_router = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);
        let sequence_number = u32::from_be_bytes([data[12], data[13], data[14], data[15]]);
        let checksum = u16::from_be_bytes([data[16], data[17]]);
        let length = u16::from_be_bytes([data[18], data[19]]);

        Ok(Ospfv3LsaHeader {
            age,
            lsa_type,
            link_state_id,
            adv_router,
            sequence_number,
            checksum,
            length,
        })
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(OSPFV3_LSA_HEADER_LEN);
        buf.extend_from_slice(&self.age.to_be_bytes());
        buf.extend_from_slice(&self.lsa_type.to_be_bytes());
        buf.extend_from_slice(&self.link_state_id.to_be_bytes());
        buf.extend_from_slice(&self.adv_router.to_be_bytes());
        buf.extend_from_slice(&self.sequence_number.to_be_bytes());
        buf.extend_from_slice(&self.checksum.to_be_bytes());
        buf.extend_from_slice(&self.length.to_be_bytes());
        buf
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ospfv3Prefix {
    pub prefix_len: u8,
    pub prefix_options: u8,
    pub metric: u16,
    pub address: Ipv6Address,
}

impl Ospfv3Prefix {
    pub fn parse(data: &[u8]) -> Result<(Self, usize), &'static str> {
        if data.len() < 4 {
            return Err("Prefix descriptor too short");
        }
        let prefix_len = data[0];
        let prefix_options = data[1];
        let metric = u16::from_be_bytes([data[2], data[3]]);

        let bytes_needed = ((prefix_len + 31) / 32 * 4) as usize; // 32-bit aligned
        if data.len() < 4 + bytes_needed {
            return Err("Truncated prefix address bytes");
        }

        let mut addr_bytes = [0u8; 16];
        let copy_len = bytes_needed.min(16);
        addr_bytes[..copy_len].copy_from_slice(&data[4..4 + copy_len]);

        Ok((
            Ospfv3Prefix {
                prefix_len,
                prefix_options,
                metric,
                address: Ipv6Address(addr_bytes),
            },
            4 + bytes_needed,
        ))
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.push(self.prefix_len);
        buf.push(self.prefix_options);
        buf.extend_from_slice(&self.metric.to_be_bytes());

        let bytes_needed = ((self.prefix_len + 31) / 32 * 4) as usize;
        let copy_len = bytes_needed.min(16);
        buf.extend_from_slice(&self.address.0[..copy_len]);
        while buf.len() < 4 + bytes_needed {
            buf.push(0);
        }
        buf
    }
}

/// Link-LSA (0x0008 - RFC 5340 Section A.4.9)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ospfv3LinkLsa {
    pub header: Ospfv3LsaHeader,
    pub router_priority: u8,
    pub options: u32,
    pub link_local_address: Ipv6Address,
    pub prefixes: Vec<Ospfv3Prefix>,
}

impl Ospfv3LinkLsa {
    pub fn parse(data: &[u8]) -> Result<Self, &'static str> {
        let header = Ospfv3LsaHeader::parse(data)?;
        if header.lsa_type != OSPFV3_LSA_LINK {
            return Err("Not a Link-LSA");
        }
        if data.len() < OSPFV3_LSA_HEADER_LEN + 24 {
            return Err("Link-LSA too short");
        }

        let body = &data[OSPFV3_LSA_HEADER_LEN..];
        let router_priority = body[0];
        let options = ((body[1] as u32) << 16) | ((body[2] as u32) << 8) | (body[3] as u32);

        let mut ll_bytes = [0u8; 16];
        ll_bytes.copy_from_slice(&body[4..20]);
        let link_local_address = Ipv6Address(ll_bytes);

        let num_prefixes = u32::from_be_bytes([body[20], body[21], body[22], body[23]]) as usize;
        let mut prefixes = Vec::new();
        let mut offset = 24;

        for _ in 0..num_prefixes {
            if offset >= body.len() {
                break;
            }
            let (prefix, consumed) = Ospfv3Prefix::parse(&body[offset..])?;
            prefixes.push(prefix);
            offset += consumed;
        }

        Ok(Ospfv3LinkLsa {
            header,
            router_priority,
            options,
            link_local_address,
            prefixes,
        })
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut body = Vec::new();
        body.push(self.router_priority);
        body.push(((self.options >> 16) & 0xFF) as u8);
        body.push(((self.options >> 8) & 0xFF) as u8);
        body.push((self.options & 0xFF) as u8);
        body.extend_from_slice(&self.link_local_address.0);
        body.extend_from_slice(&(self.prefixes.len() as u32).to_be_bytes());

        for prefix in &self.prefixes {
            body.extend_from_slice(&prefix.serialize());
        }

        let mut hdr = self.header.clone();
        hdr.length = (OSPFV3_LSA_HEADER_LEN + body.len()) as u16;

        let mut packet = hdr.serialize();
        packet.extend_from_slice(&body);
        packet
    }
}

/// Intra-Area-Prefix-LSA (0x2009 - RFC 5340 Section A.4.10)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ospfv3IntraAreaPrefixLsa {
    pub header: Ospfv3LsaHeader,
    pub ref_ls_type: u16,
    pub ref_link_state_id: u32,
    pub ref_adv_router: u32,
    pub prefixes: Vec<Ospfv3Prefix>,
}

impl Ospfv3IntraAreaPrefixLsa {
    pub fn parse(data: &[u8]) -> Result<Self, &'static str> {
        let header = Ospfv3LsaHeader::parse(data)?;
        if header.lsa_type != OSPFV3_LSA_INTRA_AREA_PREFIX {
            return Err("Not an Intra-Area-Prefix-LSA");
        }
        if data.len() < OSPFV3_LSA_HEADER_LEN + 12 {
            return Err("Intra-Area-Prefix-LSA too short");
        }

        let body = &data[OSPFV3_LSA_HEADER_LEN..];
        let num_prefixes = u16::from_be_bytes([body[0], body[1]]) as usize;
        let ref_ls_type = u16::from_be_bytes([body[2], body[3]]);
        let ref_link_state_id = u32::from_be_bytes([body[4], body[5], body[6], body[7]]);
        let ref_adv_router = u32::from_be_bytes([body[8], body[9], body[10], body[11]]);

        let mut prefixes = Vec::new();
        let mut offset = 12;

        for _ in 0..num_prefixes {
            if offset >= body.len() {
                break;
            }
            let (prefix, consumed) = Ospfv3Prefix::parse(&body[offset..])?;
            prefixes.push(prefix);
            offset += consumed;
        }

        Ok(Ospfv3IntraAreaPrefixLsa {
            header,
            ref_ls_type,
            ref_link_state_id,
            ref_adv_router,
            prefixes,
        })
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&(self.prefixes.len() as u16).to_be_bytes());
        body.extend_from_slice(&self.ref_ls_type.to_be_bytes());
        body.extend_from_slice(&self.ref_link_state_id.to_be_bytes());
        body.extend_from_slice(&self.ref_adv_router.to_be_bytes());

        for prefix in &self.prefixes {
            body.extend_from_slice(&prefix.serialize());
        }

        let mut hdr = self.header.clone();
        hdr.length = (OSPFV3_LSA_HEADER_LEN + body.len()) as u16;

        let mut packet = hdr.serialize();
        packet.extend_from_slice(&body);
        packet
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ospfv3Route {
    pub destination: Ipv6Address,
    pub prefix_len: u8,
    pub next_hop: Ipv6Address,
    pub metric: u32,
    pub adv_router: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SpfNode {
    cost: u32,
    router_id: u32,
}

impl Ord for SpfNode {
    fn cmp(&self, other: &Self) -> Ordering {
        other.cost.cmp(&self.cost) // Min-heap
    }
}

impl PartialOrd for SpfNode {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

#[derive(Debug, Clone, Default)]
pub struct Ospfv3Lsdb {
    pub link_lsas: HashMap<(u32, u32), Ospfv3LinkLsa>, // (interface_id, adv_router)
    pub intra_prefix_lsas: Vec<Ospfv3IntraAreaPrefixLsa>,
    pub adjacencies: HashMap<u32, Vec<(u32, u32)>>, // router_id -> Vec<(neighbor_router_id, metric)>
}

impl Ospfv3Lsdb {
    pub fn new() -> Self {
        Ospfv3Lsdb {
            link_lsas: HashMap::new(),
            intra_prefix_lsas: Vec::new(),
            adjacencies: HashMap::new(),
        }
    }

    pub fn add_link_lsa(&mut self, lsa: Ospfv3LinkLsa) {
        self.link_lsas
            .insert((lsa.header.link_state_id, lsa.header.adv_router), lsa);
    }

    pub fn add_intra_area_prefix_lsa(&mut self, lsa: Ospfv3IntraAreaPrefixLsa) {
        self.intra_prefix_lsas.push(lsa);
    }

    pub fn add_adjacency(&mut self, r1: u32, r2: u32, metric: u32) {
        self.adjacencies.entry(r1).or_default().push((r2, metric));
        self.adjacencies.entry(r2).or_default().push((r1, metric));
    }

    /// Computes Dijkstra SPF for the given `root_router_id` and produces IPv6 routing table.
    pub fn compute_spf(&self, root_router_id: u32) -> Vec<Ospfv3Route> {
        let mut distances: HashMap<u32, u32> = HashMap::new();
        let mut next_hops: HashMap<u32, u32> = HashMap::new();
        let mut heap = BinaryHeap::new();

        distances.insert(root_router_id, 0);
        heap.push(SpfNode {
            cost: 0,
            router_id: root_router_id,
        });

        while let Some(SpfNode { cost, router_id }) = heap.pop() {
            if cost > *distances.get(&router_id).unwrap_or(&u32::MAX) {
                continue;
            }

            if let Some(neighbors) = self.adjacencies.get(&router_id) {
                for &(nbr, edge_cost) in neighbors {
                    let new_cost = cost + edge_cost;
                    if new_cost < *distances.get(&nbr).unwrap_or(&u32::MAX) {
                        distances.insert(nbr, new_cost);

                        // If from root, next hop is nbr; otherwise propagate next hop
                        let nh = if router_id == root_router_id {
                            nbr
                        } else {
                            *next_hops.get(&router_id).unwrap_or(&nbr)
                        };
                        next_hops.insert(nbr, nh);

                        heap.push(SpfNode {
                            cost: new_cost,
                            router_id: nbr,
                        });
                    }
                }
            }
        }

        // Map computed router distances to advertised prefixes in Intra-Area-Prefix-LSAs
        let mut routes = Vec::new();
        for lsa in &self.intra_prefix_lsas {
            let target_router = lsa.ref_adv_router;
            if let Some(&cost) = distances.get(&target_router) {
                let nh_router = *next_hops.get(&target_router).unwrap_or(&target_router);

                // Find link-local next-hop address from Link-LSA of the next hop
                let nh_ipv6 = self
                    .link_lsas
                    .values()
                    .find(|ll| ll.header.adv_router == nh_router)
                    .map(|ll| ll.link_local_address)
                    .unwrap_or(Ipv6Address([
                        0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
                    ]));

                for prefix in &lsa.prefixes {
                    routes.push(Ospfv3Route {
                        destination: prefix.address,
                        prefix_len: prefix.prefix_len,
                        next_hop: nh_ipv6,
                        metric: cost + prefix.metric as u32,
                        adv_router: target_router,
                    });
                }
            }
        }

        routes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ospfv3_hello_codec_roundtrip() {
        let hello = Ospfv3HelloPacket {
            header: Ospfv3Header {
                version: OSPFV3_VERSION,
                msg_type: OSPFV3_TYPE_HELLO,
                packet_length: 0,
                router_id: 0x0A000001, // 10.0.0.1
                area_id: 0,
                checksum: 0,
                instance_id: 0,
                reserved: 0,
            },
            interface_id: 1,
            router_priority: 1,
            options: 0x000013,
            hello_interval: 10,
            dead_interval: 40,
            designated_router: 0x0A000001,
            backup_designated_router: 0x0A000002,
            neighbors: vec![0x0A000002, 0x0A000003],
        };

        let raw = hello.serialize();
        let parsed = Ospfv3HelloPacket::parse(&raw).unwrap();

        assert_eq!(parsed.header.router_id, 0x0A000001);
        assert_eq!(parsed.interface_id, 1);
        assert_eq!(parsed.hello_interval, 10);
        assert_eq!(parsed.dead_interval, 40);
        assert_eq!(parsed.designated_router, 0x0A000001);
        assert_eq!(parsed.neighbors, vec![0x0A000002, 0x0A000003]);
    }

    #[test]
    fn test_ospfv3_link_and_intra_area_prefix_lsas() {
        let link_lsa = Ospfv3LinkLsa {
            header: Ospfv3LsaHeader {
                age: 1,
                lsa_type: OSPFV3_LSA_LINK,
                link_state_id: 1,
                adv_router: 0x0A000001,
                sequence_number: 0x80000001,
                checksum: 0,
                length: 0,
            },
            router_priority: 1,
            options: 0x000013,
            link_local_address: Ipv6Address([
                0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x00, 0x01,
            ]),
            prefixes: vec![Ospfv3Prefix {
                prefix_len: 64,
                prefix_options: 0,
                metric: 10,
                address: Ipv6Address([
                    0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                ]),
            }],
        };

        let raw_link = link_lsa.serialize();
        let parsed_link = Ospfv3LinkLsa::parse(&raw_link).unwrap();

        assert_eq!(parsed_link.link_local_address, link_lsa.link_local_address);
        assert_eq!(parsed_link.prefixes.len(), 1);
        assert_eq!(parsed_link.prefixes[0].prefix_len, 64);
    }

    #[test]
    fn test_ospfv3_spf_graph_dijkstra() {
        let mut lsdb = Ospfv3Lsdb::new();

        // R1: 0x01, R2: 0x02, R3: 0x03
        // Topology: R1 --(10)--> R2 --(20)--> R3
        lsdb.add_adjacency(0x01, 0x02, 10);
        lsdb.add_adjacency(0x02, 0x03, 20);

        // Link-LSA for R2 (advertising its link-local next-hop)
        lsdb.add_link_lsa(Ospfv3LinkLsa {
            header: Ospfv3LsaHeader {
                age: 1,
                lsa_type: OSPFV3_LSA_LINK,
                link_state_id: 2,
                adv_router: 0x02,
                sequence_number: 1,
                checksum: 0,
                length: 0,
            },
            router_priority: 1,
            options: 0,
            link_local_address: Ipv6Address([
                0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x00, 0x02,
            ]),
            prefixes: Vec::new(),
        });

        // Intra-Area-Prefix-LSA for R3 advertising 2001:db8:3::/64
        let r3_prefix = Ipv6Address([
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x03, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ]);
        lsdb.add_intra_area_prefix_lsa(Ospfv3IntraAreaPrefixLsa {
            header: Ospfv3LsaHeader {
                age: 1,
                lsa_type: OSPFV3_LSA_INTRA_AREA_PREFIX,
                link_state_id: 3,
                adv_router: 0x03,
                sequence_number: 1,
                checksum: 0,
                length: 0,
            },
            ref_ls_type: OSPFV3_LSA_ROUTER,
            ref_link_state_id: 0,
            ref_adv_router: 0x03,
            prefixes: vec![Ospfv3Prefix {
                prefix_len: 64,
                prefix_options: 0,
                metric: 5,
                address: r3_prefix,
            }],
        });

        let routes = lsdb.compute_spf(0x01);
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].destination, r3_prefix);
        assert_eq!(routes[0].metric, 10 + 20 + 5); // 35
        assert_eq!(
            routes[0].next_hop,
            Ipv6Address([0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x00, 0x02])
        );
    }
}
