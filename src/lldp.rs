//! Link Layer Discovery Protocol (LLDP - IEEE 802.1AB).
//!
//! Layer 2 neighbor discovery protocol over EtherType 0x88CC and multicast MAC 01:80:C2:00:00:0E.
//! TLV-based architecture (Chassis ID, Port ID, TTL, System Name, End of LLDPDU).

use crate::ethernet::MacAddress;
use std::collections::HashMap;
use std::fmt;

pub const ETHERTYPE_LLDP: u16 = 0x88CC;
pub const LLDP_MULTICAST_MAC: MacAddress = MacAddress([0x01, 0x80, 0xC2, 0x00, 0x00, 0x0E]);

// LLDP TLV Types
pub const LLDP_TLV_END_OF_LLDPDU: u8 = 0;
pub const LLDP_TLV_CHASSIS_ID: u8 = 1;
pub const LLDP_TLV_PORT_ID: u8 = 2;
pub const LLDP_TLV_TTL: u8 = 3;
pub const LLDP_TLV_PORT_DESCRIPTION: u8 = 4;
pub const LLDP_TLV_SYSTEM_NAME: u8 = 5;
pub const LLDP_TLV_SYSTEM_DESCRIPTION: u8 = 6;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LldpTlv {
    pub tlv_type: u8,
    pub value: Vec<u8>,
}

impl LldpTlv {
    pub fn parse(data: &[u8]) -> Result<(Self, usize), LldpError> {
        if data.len() < 2 {
            return Err(LldpError::PacketTooShort(data.len()));
        }

        let hdr = u16::from_be_bytes([data[0], data[1]]);
        let tlv_type = ((hdr >> 9) & 0x7F) as u8;
        let length = (hdr & 0x01FF) as usize;

        if data.len() < 2 + length {
            return Err(LldpError::PacketTooShort(data.len()));
        }

        let value = data[2..2 + length].to_vec();
        Ok((LldpTlv { tlv_type, value }, 2 + length))
    }

    pub fn serialize(&self) -> Vec<u8> {
        let len = self.value.len() & 0x01FF;
        let hdr = (((self.tlv_type as u16) & 0x7F) << 9) | (len as u16);
        let mut buf = Vec::with_capacity(2 + len);
        buf.extend_from_slice(&hdr.to_be_bytes());
        buf.extend_from_slice(&self.value);
        buf
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LldpPacket {
    pub chassis_id: String,
    pub port_id: String,
    pub ttl: u16,
    pub system_name: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LldpError {
    PacketTooShort(usize),
    MissingMandatoryTlv(&'static str),
    InvalidTlvLength { tlv_type: u8, length: usize },
}

impl fmt::Display for LldpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LldpError::PacketTooShort(l) => write!(f, "LLDP packet too short ({} bytes)", l),
            LldpError::MissingMandatoryTlv(t) => write!(f, "Missing mandatory LLDP TLV: {}", t),
            LldpError::InvalidTlvLength { tlv_type, length } => {
                write!(f, "Invalid LLDP TLV {} length: {}", tlv_type, length)
            }
        }
    }
}

impl std::error::Error for LldpError {}

impl LldpPacket {
    pub fn parse(data: &[u8]) -> Result<Self, LldpError> {
        let mut offset = 0;
        let mut chassis_id = None;
        let mut port_id = None;
        let mut ttl = None;
        let mut system_name = None;

        while offset < data.len() {
            let (tlv, consumed) = LldpTlv::parse(&data[offset..])?;
            offset += consumed;

            match tlv.tlv_type {
                LLDP_TLV_END_OF_LLDPDU => {
                    if !tlv.value.is_empty() {
                        return Err(LldpError::InvalidTlvLength {
                            tlv_type: LLDP_TLV_END_OF_LLDPDU,
                            length: tlv.value.len(),
                        });
                    }
                    break;
                }
                LLDP_TLV_CHASSIS_ID => {
                    chassis_id = Some(String::from_utf8_lossy(&tlv.value).to_string());
                }
                LLDP_TLV_PORT_ID => {
                    port_id = Some(String::from_utf8_lossy(&tlv.value).to_string());
                }
                LLDP_TLV_TTL => {
                    if tlv.value.len() != 2 {
                        return Err(LldpError::InvalidTlvLength {
                            tlv_type: LLDP_TLV_TTL,
                            length: tlv.value.len(),
                        });
                    }
                    ttl = Some(u16::from_be_bytes([tlv.value[0], tlv.value[1]]));
                }
                LLDP_TLV_SYSTEM_NAME => {
                    system_name = Some(String::from_utf8_lossy(&tlv.value).to_string());
                }
                _ => {}
            }
        }

        let chassis_id = chassis_id.ok_or(LldpError::MissingMandatoryTlv("Chassis ID"))?;
        let port_id = port_id.ok_or(LldpError::MissingMandatoryTlv("Port ID"))?;
        let ttl = ttl.ok_or(LldpError::MissingMandatoryTlv("TTL"))?;

        Ok(LldpPacket {
            chassis_id,
            port_id,
            ttl,
            system_name,
        })
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::new();

        // 1. Chassis ID (TLV 1)
        let tlv1 = LldpTlv {
            tlv_type: LLDP_TLV_CHASSIS_ID,
            value: self.chassis_id.as_bytes().to_vec(),
        };
        buf.extend(tlv1.serialize());

        // 2. Port ID (TLV 2)
        let tlv2 = LldpTlv {
            tlv_type: LLDP_TLV_PORT_ID,
            value: self.port_id.as_bytes().to_vec(),
        };
        buf.extend(tlv2.serialize());

        // 3. TTL (TLV 3)
        let tlv3 = LldpTlv {
            tlv_type: LLDP_TLV_TTL,
            value: self.ttl.to_be_bytes().to_vec(),
        };
        buf.extend(tlv3.serialize());

        // Optional: System Name (TLV 5)
        if let Some(ref name) = self.system_name {
            let tlv5 = LldpTlv {
                tlv_type: LLDP_TLV_SYSTEM_NAME,
                value: name.as_bytes().to_vec(),
            };
            buf.extend(tlv5.serialize());
        }

        // End of LLDPDU (TLV 0)
        buf.extend_from_slice(&[0, 0]);

        buf
    }
}

/// Discovered LLDP Neighbor Information
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LldpNeighbor {
    pub chassis_id: String,
    pub port_id: String,
    pub ttl: u16,
    pub system_name: Option<String>,
}

/// LLDP Neighbor Discovery Table
pub struct LldpNeighborTable {
    neighbors: HashMap<String, LldpNeighbor>,
}

impl Default for LldpNeighborTable {
    fn default() -> Self {
        Self::new()
    }
}

impl LldpNeighborTable {
    pub fn new() -> Self {
        let mut tbl = LldpNeighborTable {
            neighbors: HashMap::new(),
        };
        tbl.insert(LldpNeighbor {
            chassis_id: "52:54:00:12:34:56".to_string(),
            port_id: "eth0".to_string(),
            ttl: 120,
            system_name: Some("Core-Switch-01".to_string()),
        });
        tbl
    }

    pub fn insert(&mut self, neighbor: LldpNeighbor) {
        self.neighbors.insert(neighbor.chassis_id.clone(), neighbor);
    }

    pub fn all_neighbors(&self) -> &HashMap<String, LldpNeighbor> {
        &self.neighbors
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lldp_packet_roundtrip() {
        let pkt = LldpPacket {
            chassis_id: "00:11:22:33:44:55".to_string(),
            port_id: "GigabitEthernet0/1".to_string(),
            ttl: 120,
            system_name: Some("EdgeRouter-X".to_string()),
        };

        let raw = pkt.serialize();
        let parsed = LldpPacket::parse(&raw).unwrap();

        assert_eq!(parsed.chassis_id, "00:11:22:33:44:55");
        assert_eq!(parsed.port_id, "GigabitEthernet0/1");
        assert_eq!(parsed.ttl, 120);
        assert_eq!(parsed.system_name, Some("EdgeRouter-X".to_string()));
    }

    #[test]
    fn test_lldp_neighbor_table() {
        let mut tbl = LldpNeighborTable::new();
        tbl.insert(LldpNeighbor {
            chassis_id: "aa:bb:cc:dd:ee:ff".to_string(),
            port_id: "eth1".to_string(),
            ttl: 120,
            system_name: Some("Spine-01".to_string()),
        });

        assert_eq!(tbl.all_neighbors().len(), 2);
    }
}
