//! Cisco Discovery Protocol (CDPv2).
//!
//! Proprietary Layer 2 network device discovery protocol operating over SNAP/LLC framing.

use crate::checksum::{compute_checksum, verify_checksum};
use crate::ethernet::MacAddress;
use crate::ipv4::Ipv4Address;
use std::collections::BTreeMap;
use std::fmt;

pub const CDP_MULTICAST_MAC: MacAddress = MacAddress([0x01, 0x00, 0x0C, 0xCC, 0xCC, 0xCC]);
pub const CDP_SNAP_HEADER: [u8; 8] = [0xAA, 0xAA, 0x03, 0x00, 0x00, 0x0C, 0x20, 0x00];

// CDP TLV Types
pub const CDP_TLV_DEVICE_ID: u16 = 0x0001;
pub const CDP_TLV_ADDRESSES: u16 = 0x0002;
pub const CDP_TLV_PORT_ID: u16 = 0x0003;
pub const CDP_TLV_CAPABILITIES: u16 = 0x0004;
pub const CDP_TLV_SOFTWARE_VERSION: u16 = 0x0005;
pub const CDP_TLV_PLATFORM: u16 = 0x0006;
pub const CDP_TLV_NATIVE_VLAN: u16 = 0x000A;

// CDP Capabilities bitmask
pub const CDP_CAP_ROUTER: u32 = 0x0001;
pub const CDP_CAP_SWITCH: u32 = 0x0008;
pub const CDP_CAP_HOST: u32 = 0x0010;

const CDP_TLV_HEADER_LEN: usize = 4;
const CDP_TLV_MAX_VALUE_LEN: usize = u16::MAX as usize - CDP_TLV_HEADER_LEN;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CdpTlv {
    pub tlv_type: u16,
    pub value: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CdpPacket {
    pub version: u8,
    pub ttl: u8,
    pub checksum: u16,
    pub tlvs: Vec<CdpTlv>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CdpNeighbor {
    pub device_id: String,
    pub port_id: String,
    pub platform: String,
    pub ip_address: Option<Ipv4Address>,
    pub ttl: u8,
}

#[derive(Debug, Clone, Default)]
pub struct CdpNeighborTable {
    pub neighbors: BTreeMap<String, CdpNeighbor>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CdpError {
    PacketTooShort(usize),
    InvalidVersion(u8),
    InvalidChecksum,
    InvalidTlvLength,
}

impl fmt::Display for CdpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CdpError::PacketTooShort(l) => write!(f, "CDP packet too short ({} bytes)", l),
            CdpError::InvalidVersion(v) => write!(f, "Invalid CDP version: {}", v),
            CdpError::InvalidChecksum => write!(f, "CDP checksum mismatch"),
            CdpError::InvalidTlvLength => write!(f, "Invalid CDP TLV length"),
        }
    }
}

impl std::error::Error for CdpError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CdpSerializeError {
    InvalidVersion(u8),
    TlvValueTooLong {
        tlv_type: u16,
        length: usize,
        max: usize,
    },
}

impl fmt::Display for CdpSerializeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CdpSerializeError::InvalidVersion(v) => write!(f, "Invalid CDP version: {}", v),
            CdpSerializeError::TlvValueTooLong {
                tlv_type,
                length,
                max,
            } => write!(
                f,
                "CDP TLV {} value is {} bytes, exceeding the {}-byte 16-bit length limit",
                tlv_type, length, max
            ),
        }
    }
}

impl std::error::Error for CdpSerializeError {}

impl CdpPacket {
    pub fn build(device_id: &str, port_id: &str, platform: &str, ip: Ipv4Address) -> Self {
        let mut tlvs = Vec::new();

        // 1. Device ID
        tlvs.push(CdpTlv {
            tlv_type: CDP_TLV_DEVICE_ID,
            value: device_id.as_bytes().to_vec(),
        });

        // 2. IP Address (CDP Address format: 4B count + 1B proto type + 1B proto len + 1B proto (0xCC) + 2B addr len + 4B IP)
        let mut addr_val = Vec::new();
        addr_val.extend_from_slice(&1u32.to_be_bytes()); // 1 address
        addr_val.push(0x01); // NLPID
        addr_val.push(0x01); // 1 byte proto
        addr_val.push(0xCC); // IPv4
        addr_val.extend_from_slice(&4u16.to_be_bytes());
        addr_val.extend_from_slice(&ip.0);
        tlvs.push(CdpTlv {
            tlv_type: CDP_TLV_ADDRESSES,
            value: addr_val,
        });

        // 3. Port ID
        tlvs.push(CdpTlv {
            tlv_type: CDP_TLV_PORT_ID,
            value: port_id.as_bytes().to_vec(),
        });

        // 4. Platform
        tlvs.push(CdpTlv {
            tlv_type: CDP_TLV_PLATFORM,
            value: platform.as_bytes().to_vec(),
        });

        // 5. Capabilities (Router | Switch)
        tlvs.push(CdpTlv {
            tlv_type: CDP_TLV_CAPABILITIES,
            value: (CDP_CAP_ROUTER | CDP_CAP_SWITCH).to_be_bytes().to_vec(),
        });

        CdpPacket {
            version: 2,
            ttl: 180,
            checksum: 0,
            tlvs,
        }
    }

    pub fn serialize(&self) -> Vec<u8> {
        self.try_serialize()
            .expect("CDP version and TLV lengths must be representable on the wire")
    }

    pub fn try_serialize(&self) -> Result<Vec<u8>, CdpSerializeError> {
        if self.version != 1 && self.version != 2 {
            return Err(CdpSerializeError::InvalidVersion(self.version));
        }

        let mut buf = Vec::new();
        buf.push(self.version);
        buf.push(self.ttl);
        buf.extend_from_slice(&0u16.to_be_bytes()); // Checksum placeholder

        for tlv in &self.tlvs {
            if tlv.value.len() > CDP_TLV_MAX_VALUE_LEN {
                return Err(CdpSerializeError::TlvValueTooLong {
                    tlv_type: tlv.tlv_type,
                    length: tlv.value.len(),
                    max: CDP_TLV_MAX_VALUE_LEN,
                });
            }

            buf.extend_from_slice(&tlv.tlv_type.to_be_bytes());
            let len = (CDP_TLV_HEADER_LEN + tlv.value.len()) as u16;
            buf.extend_from_slice(&len.to_be_bytes());
            buf.extend_from_slice(&tlv.value);
        }

        let chk = compute_checksum(&buf);
        buf[2..4].copy_from_slice(&chk.to_be_bytes());
        Ok(buf)
    }

    pub fn parse(data: &[u8]) -> Result<Self, CdpError> {
        if data.len() < 4 {
            return Err(CdpError::PacketTooShort(data.len()));
        }

        let version = data[0];
        if version != 2 && version != 1 {
            return Err(CdpError::InvalidVersion(version));
        }

        if !verify_checksum(data) {
            return Err(CdpError::InvalidChecksum);
        }

        let ttl = data[1];
        let checksum = u16::from_be_bytes([data[2], data[3]]);

        let mut offset = 4;
        let mut tlvs = Vec::new();

        while offset < data.len() {
            if data.len() - offset < 4 {
                return Err(CdpError::InvalidTlvLength);
            }

            let tlv_type = u16::from_be_bytes([data[offset], data[offset + 1]]);
            let tlv_len = u16::from_be_bytes([data[offset + 2], data[offset + 3]]) as usize;

            if tlv_len < 4 || offset + tlv_len > data.len() {
                return Err(CdpError::InvalidTlvLength);
            }

            let value = data[offset + 4..offset + tlv_len].to_vec();
            tlvs.push(CdpTlv { tlv_type, value });
            offset += tlv_len;
        }

        Ok(CdpPacket {
            version,
            ttl,
            checksum,
            tlvs,
        })
    }
}

impl CdpNeighborTable {
    pub fn new() -> Self {
        CdpNeighborTable {
            neighbors: BTreeMap::new(),
        }
    }

    pub fn ingest_packet(&mut self, pkt: &CdpPacket) {
        let mut device_id = String::new();
        let mut port_id = String::new();
        let mut platform = String::new();
        let mut ip_address = None;

        for tlv in &pkt.tlvs {
            match tlv.tlv_type {
                CDP_TLV_DEVICE_ID => device_id = String::from_utf8_lossy(&tlv.value).to_string(),
                CDP_TLV_PORT_ID => port_id = String::from_utf8_lossy(&tlv.value).to_string(),
                CDP_TLV_PLATFORM => platform = String::from_utf8_lossy(&tlv.value).to_string(),
                CDP_TLV_ADDRESSES if tlv.value.len() >= 13 && tlv.value[6] == 0xCC => {
                    ip_address = Some(Ipv4Address([
                        tlv.value[9],
                        tlv.value[10],
                        tlv.value[11],
                        tlv.value[12],
                    ]));
                }
                _ => {}
            }
        }

        if !device_id.is_empty() {
            self.neighbors.insert(
                device_id.clone(),
                CdpNeighbor {
                    device_id,
                    port_id,
                    platform,
                    ip_address,
                    ttl: pkt.ttl,
                },
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cdp_packet_roundtrip_and_neighbor_table() {
        let pkt = CdpPacket::build(
            "Switch-Core-01",
            "GigabitEthernet0/1",
            "cisco WS-C2960",
            Ipv4Address::new(10, 0, 0, 1),
        );
        let raw = pkt.serialize();

        let parsed = CdpPacket::parse(&raw).unwrap();
        assert_eq!(parsed.version, 2);
        assert_eq!(parsed.ttl, 180);
        assert_eq!(parsed.tlvs.len(), 5);

        let mut table = CdpNeighborTable::new();
        table.ingest_packet(&parsed);

        let n = table.neighbors.get("Switch-Core-01").unwrap();
        assert_eq!(n.port_id, "GigabitEthernet0/1");
        assert_eq!(n.platform, "cisco WS-C2960");
        assert_eq!(n.ip_address, Some(Ipv4Address::new(10, 0, 0, 1)));
    }

    #[test]
    fn test_try_serialize_rejects_invalid_version() {
        let pkt = CdpPacket {
            version: 3,
            ttl: 180,
            checksum: 0,
            tlvs: Vec::new(),
        };

        assert_eq!(
            pkt.try_serialize(),
            Err(CdpSerializeError::InvalidVersion(3))
        );
    }

    #[test]
    fn test_try_serialize_accepts_maximum_tlv_value() {
        let pkt = CdpPacket {
            version: 2,
            ttl: 180,
            checksum: 0,
            tlvs: vec![CdpTlv {
                tlv_type: CDP_TLV_DEVICE_ID,
                value: vec![0; CDP_TLV_MAX_VALUE_LEN],
            }],
        };

        let raw = pkt.try_serialize().unwrap();
        assert_eq!(
            u16::from_be_bytes([raw[6], raw[7]]) as usize,
            u16::MAX as usize
        );
    }

    #[test]
    fn test_try_serialize_rejects_oversized_tlv_value() {
        let pkt = CdpPacket {
            version: 2,
            ttl: 180,
            checksum: 0,
            tlvs: vec![CdpTlv {
                tlv_type: CDP_TLV_DEVICE_ID,
                value: vec![0; CDP_TLV_MAX_VALUE_LEN + 1],
            }],
        };

        assert_eq!(
            pkt.try_serialize(),
            Err(CdpSerializeError::TlvValueTooLong {
                tlv_type: CDP_TLV_DEVICE_ID,
                length: CDP_TLV_MAX_VALUE_LEN + 1,
                max: CDP_TLV_MAX_VALUE_LEN,
            })
        );
    }

    #[test]
    fn test_parse_rejects_corrupted_checksum() {
        let pkt = CdpPacket::build(
            "Switch-Core-01",
            "GigabitEthernet0/1",
            "cisco WS-C2960",
            Ipv4Address::new(10, 0, 0, 1),
        );
        let mut raw = pkt.serialize();
        let last = raw.len() - 1;
        raw[last] ^= 0x01;

        assert_eq!(CdpPacket::parse(&raw), Err(CdpError::InvalidChecksum));
    }

    #[test]
    fn test_parse_rejects_trailing_partial_tlv_header() {
        let pkt = CdpPacket::build(
            "Switch-Core-01",
            "GigabitEthernet0/1",
            "cisco WS-C2960",
            Ipv4Address::new(10, 0, 0, 1),
        );
        let mut raw = pkt.serialize();
        raw.extend_from_slice(&[0x00, 0x01, 0x00]);
        raw[2] = 0;
        raw[3] = 0;
        let checksum = compute_checksum(&raw);
        raw[2..4].copy_from_slice(&checksum.to_be_bytes());

        assert_eq!(CdpPacket::parse(&raw), Err(CdpError::InvalidTlvLength));
    }
}
