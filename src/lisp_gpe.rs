//! Generic Protocol Extension for LISP (LISP-GPE - RFC 9245 / RFC 6830).
//!
//! Extends Locator/ID Separation Protocol (LISP) data encapsulation from IPv4/IPv6 only
//! to multi-protocol overlays (IPv4, IPv6, Ethernet frames, and Network Service Headers (NSH))
//! across modern software-defined datacenter and WAN underlays over UDP port 4341.
//!
//! Features:
//! - 8-byte LISP-GPE header with P-bit (Protocol bit), I-bit (Instance ID / VNI), and V-bit (Virtualization).
//! - Next Protocol multiplexing:
//!   - `0x01`: IPv4 Datagram
//!   - `0x02`: IPv6 Datagram
//!   - `0x03`: Ethernet II Frame
//!   - `0x04`: Network Service Header (NSH RFC 8300)
//! - Multi-tenant L2/L3 overlay router with EID-to-RLOC encapsulation & decapsulation.

use crate::ipv4::Ipv4Address;
use std::collections::HashMap;
use std::fmt;

pub const LISP_GPE_UDP_PORT: u16 = 4341;
pub const LISP_GPE_HEADER_LEN: usize = 8;

pub const LISP_GPE_FLAG_N: u8 = 0x80; // Nonce present
pub const LISP_GPE_FLAG_L: u8 = 0x40; // LSB present
pub const LISP_GPE_FLAG_E: u8 = 0x20; // Echo-Nonce request
pub const LISP_GPE_FLAG_V: u8 = 0x10; // Virtualization / Instance ID present
pub const LISP_GPE_FLAG_I: u8 = 0x08; // Instance ID present
pub const LISP_GPE_FLAG_P: u8 = 0x04; // Next Protocol bit

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LispGpeNextProto {
    Ipv4,
    Ipv6,
    Ethernet,
    Nsh,
    Unknown(u8),
}

impl From<u8> for LispGpeNextProto {
    fn from(val: u8) -> Self {
        match val {
            1 => LispGpeNextProto::Ipv4,
            2 => LispGpeNextProto::Ipv6,
            3 => LispGpeNextProto::Ethernet,
            4 => LispGpeNextProto::Nsh,
            other => LispGpeNextProto::Unknown(other),
        }
    }
}

impl From<LispGpeNextProto> for u8 {
    fn from(proto: LispGpeNextProto) -> Self {
        match proto {
            LispGpeNextProto::Ipv4 => 1,
            LispGpeNextProto::Ipv6 => 2,
            LispGpeNextProto::Ethernet => 3,
            LispGpeNextProto::Nsh => 4,
            LispGpeNextProto::Unknown(val) => val,
        }
    }
}

impl fmt::Display for LispGpeNextProto {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LispGpeNextProto::Ipv4 => write!(f, "IPv4 (1)"),
            LispGpeNextProto::Ipv6 => write!(f, "IPv6 (2)"),
            LispGpeNextProto::Ethernet => write!(f, "Ethernet (3)"),
            LispGpeNextProto::Nsh => write!(f, "NSH (4)"),
            LispGpeNextProto::Unknown(u) => write!(f, "Unknown ({})", u),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LispGpeHeader {
    pub flags: u8,
    pub version: u8,
    pub instance_id: u32, // 24-bit
    pub next_protocol: LispGpeNextProto,
}

impl LispGpeHeader {
    pub fn new(instance_id: u32, next_protocol: LispGpeNextProto) -> Self {
        let mut flags = LISP_GPE_FLAG_P;
        if instance_id > 0 {
            flags |= LISP_GPE_FLAG_I | LISP_GPE_FLAG_V;
        }
        LispGpeHeader {
            flags,
            version: 0,
            instance_id: instance_id & 0x00FF_FFFF,
            next_protocol,
        }
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(LISP_GPE_HEADER_LEN);
        buf.push(self.flags);
        buf.push(self.version);
        buf.push(0); // Reserved byte
        buf.push(self.next_protocol.into());

        let iid_bytes = self.instance_id.to_be_bytes();
        buf.push(iid_bytes[1]);
        buf.push(iid_bytes[2]);
        buf.push(iid_bytes[3]);
        buf.push(0); // Reserved byte in word 2
        buf
    }

    pub fn parse(data: &[u8]) -> Result<Self, &'static str> {
        if data.len() < LISP_GPE_HEADER_LEN {
            return Err("LISP-GPE packet too short");
        }

        let flags = data[0];
        let version = data[1];
        let next_proto_raw = data[3];
        let next_protocol = LispGpeNextProto::from(next_proto_raw);

        let instance_id = u32::from_be_bytes([0, data[4], data[5], data[6]]);

        Ok(LispGpeHeader {
            flags,
            version,
            instance_id,
            next_protocol,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LispGpePacket {
    pub header: LispGpeHeader,
    pub payload: Vec<u8>,
}

impl LispGpePacket {
    pub fn new(instance_id: u32, next_protocol: LispGpeNextProto, payload: Vec<u8>) -> Self {
        LispGpePacket {
            header: LispGpeHeader::new(instance_id, next_protocol),
            payload,
        }
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = self.header.serialize();
        buf.extend_from_slice(&self.payload);
        buf
    }

    pub fn parse(data: &[u8]) -> Result<Self, &'static str> {
        let header = LispGpeHeader::parse(data)?;
        let payload = data[LISP_GPE_HEADER_LEN..].to_vec();
        Ok(LispGpePacket { header, payload })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LispGpeMapping {
    pub instance_id: u32,
    pub rloc_underlay_ip: Ipv4Address,
    pub next_protocol: LispGpeNextProto,
}

#[derive(Debug, Clone, Default)]
pub struct LispGpeEngine {
    pub eid_mappings: HashMap<(u32, Vec<u8>), LispGpeMapping>, // (instance_id, eid_key) -> mapping
}

impl LispGpeEngine {
    pub fn new() -> Self {
        LispGpeEngine {
            eid_mappings: HashMap::new(),
        }
    }

    pub fn add_mapping(&mut self, instance_id: u32, eid_key: Vec<u8>, mapping: LispGpeMapping) {
        self.eid_mappings.insert((instance_id, eid_key), mapping);
    }

    pub fn encapsulate(
        &self,
        instance_id: u32,
        next_proto: LispGpeNextProto,
        payload: &[u8],
    ) -> LispGpePacket {
        LispGpePacket::new(instance_id, next_proto, payload.to_vec())
    }

    pub fn decapsulate(&self, packet: &LispGpePacket) -> (u32, LispGpeNextProto, Vec<u8>) {
        (
            packet.header.instance_id,
            packet.header.next_protocol,
            packet.payload.clone(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lisp_gpe_header_codec() {
        let header = LispGpeHeader::new(5000, LispGpeNextProto::Ethernet);
        let bytes = header.serialize();
        assert_eq!(bytes.len(), 8);

        let parsed = LispGpeHeader::parse(&bytes).unwrap();
        assert_eq!(parsed.instance_id, 5000);
        assert_eq!(parsed.next_protocol, LispGpeNextProto::Ethernet);
        assert_eq!(parsed.flags & LISP_GPE_FLAG_P, LISP_GPE_FLAG_P);
    }

    #[test]
    fn test_lisp_gpe_multi_protocol_encapsulation() {
        let engine = LispGpeEngine::new();

        // 1. Encapsulate IPv4
        let ipv4_pkt = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let enc_v4 = engine.encapsulate(100, LispGpeNextProto::Ipv4, ipv4_pkt);
        let raw_v4 = enc_v4.serialize();
        let parsed_v4 = LispGpePacket::parse(&raw_v4).unwrap();
        let (iid4, proto4, data4) = engine.decapsulate(&parsed_v4);
        assert_eq!(iid4, 100);
        assert_eq!(proto4, LispGpeNextProto::Ipv4);
        assert_eq!(data4, ipv4_pkt);

        // 2. Encapsulate Ethernet Frame (L2 overlay)
        let eth_frame = vec![
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x08, 0x00,
        ];
        let enc_eth = engine.encapsulate(200, LispGpeNextProto::Ethernet, &eth_frame);
        let raw_eth = enc_eth.serialize();
        let parsed_eth = LispGpePacket::parse(&raw_eth).unwrap();
        let (iid_eth, proto_eth, data_eth) = engine.decapsulate(&parsed_eth);
        assert_eq!(iid_eth, 200);
        assert_eq!(proto_eth, LispGpeNextProto::Ethernet);
        assert_eq!(data_eth, eth_frame);

        // 3. Encapsulate NSH
        let nsh_header = vec![0x00, 0x04, 0x01, 0x03, 0x00, 0x00, 0x01, 0xff];
        let enc_nsh = engine.encapsulate(300, LispGpeNextProto::Nsh, &nsh_header);
        let raw_nsh = enc_nsh.serialize();
        let parsed_nsh = LispGpePacket::parse(&raw_nsh).unwrap();
        let (iid_nsh, proto_nsh, data_nsh) = engine.decapsulate(&parsed_nsh);
        assert_eq!(iid_nsh, 300);
        assert_eq!(proto_nsh, LispGpeNextProto::Nsh);
        assert_eq!(data_nsh, nsh_header);
    }
}
