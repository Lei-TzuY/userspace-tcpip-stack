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

// IEEE 802.1AB identifier subtypes supported by the high-level LldpPacket API.
pub const LLDP_CHASSIS_ID_SUBTYPE_MAC_ADDRESS: u8 = 4;
pub const LLDP_CHASSIS_ID_SUBTYPE_LOCALLY_ASSIGNED: u8 = 7;
pub const LLDP_PORT_ID_SUBTYPE_MAC_ADDRESS: u8 = 3;
pub const LLDP_PORT_ID_SUBTYPE_INTERFACE_NAME: u8 = 5;

const LLDP_TLV_MAX_TYPE: u8 = 0x7F;
const LLDP_TLV_MAX_VALUE_LEN: usize = 0x01FF;

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
        self.try_serialize()
            .expect("LLDP TLV type and value must fit the wire header")
    }

    pub fn try_serialize(&self) -> Result<Vec<u8>, LldpSerializeError> {
        if self.tlv_type > LLDP_TLV_MAX_TYPE {
            return Err(LldpSerializeError::TlvTypeOutOfRange {
                tlv_type: self.tlv_type,
                max: LLDP_TLV_MAX_TYPE,
            });
        }

        let len = self.value.len();
        if len > LLDP_TLV_MAX_VALUE_LEN {
            return Err(LldpSerializeError::TlvValueTooLong {
                tlv_type: self.tlv_type,
                length: len,
                max: LLDP_TLV_MAX_VALUE_LEN,
            });
        }

        let hdr = ((self.tlv_type as u16) << 9) | (len as u16);
        let mut buf = Vec::with_capacity(2 + len);
        buf.extend_from_slice(&hdr.to_be_bytes());
        buf.extend_from_slice(&self.value);
        Ok(buf)
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
    MissingEndOfLldpdu,
    InvalidMandatoryTlvOrder {
        expected: &'static str,
        found: u8,
    },
    InvalidTlvLength {
        tlv_type: u8,
        length: usize,
    },
    DuplicateTlv {
        tlv_type: u8,
    },
    UnsupportedIdentifierSubtype {
        tlv_type: u8,
        subtype: u8,
        expected: u8,
    },
    InvalidUtf8Identifier {
        tlv_type: u8,
    },
}

impl fmt::Display for LldpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LldpError::PacketTooShort(l) => write!(f, "LLDP packet too short ({} bytes)", l),
            LldpError::MissingMandatoryTlv(t) => write!(f, "Missing mandatory LLDP TLV: {}", t),
            LldpError::MissingEndOfLldpdu => write!(f, "Missing LLDP End-of-LLDPDU TLV"),
            LldpError::InvalidMandatoryTlvOrder { expected, found } => write!(
                f,
                "Invalid LLDP TLV order: expected {}, found TLV type {}",
                expected, found
            ),
            LldpError::InvalidTlvLength { tlv_type, length } => {
                write!(f, "Invalid LLDP TLV {} length: {}", tlv_type, length)
            }
            LldpError::DuplicateTlv { tlv_type } => {
                write!(f, "Duplicate LLDP TLV type {}", tlv_type)
            }
            LldpError::UnsupportedIdentifierSubtype {
                tlv_type,
                subtype,
                expected,
            } => write!(
                f,
                "Unsupported LLDP TLV {} identifier subtype {} (expected {} or MAC address)",
                tlv_type, subtype, expected
            ),
            LldpError::InvalidUtf8Identifier { tlv_type } => {
                write!(f, "LLDP TLV {} identifier is not valid UTF-8", tlv_type)
            }
        }
    }
}

impl std::error::Error for LldpError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LldpSerializeError {
    TlvTypeOutOfRange {
        tlv_type: u8,
        max: u8,
    },
    TlvValueTooLong {
        tlv_type: u8,
        length: usize,
        max: usize,
    },
    EmptyIdentifier {
        tlv_type: u8,
    },
}

impl fmt::Display for LldpSerializeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LldpSerializeError::TlvTypeOutOfRange { tlv_type, max } => write!(
                f,
                "LLDP TLV type {} exceeds the {} maximum representable by the 7-bit type field",
                tlv_type, max
            ),
            LldpSerializeError::TlvValueTooLong {
                tlv_type,
                length,
                max,
            } => write!(
                f,
                "LLDP TLV {} value is {} bytes, exceeding the {}-byte 9-bit length limit",
                tlv_type, length, max
            ),
            LldpSerializeError::EmptyIdentifier { tlv_type } => {
                write!(f, "LLDP TLV {} identifier must not be empty", tlv_type)
            }
        }
    }
}

impl std::error::Error for LldpSerializeError {}

fn parse_identifier(tlv: &LldpTlv, text_subtype: u8, mac_subtype: u8) -> Result<String, LldpError> {
    if tlv.value.len() < 2 {
        return Err(LldpError::InvalidTlvLength {
            tlv_type: tlv.tlv_type,
            length: tlv.value.len(),
        });
    }

    let subtype = tlv.value[0];
    if subtype == mac_subtype {
        if tlv.value.len() != 7 {
            return Err(LldpError::InvalidTlvLength {
                tlv_type: tlv.tlv_type,
                length: tlv.value.len(),
            });
        }
        let mac = &tlv.value[1..];
        return Ok(format!(
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
        ));
    }

    if subtype != text_subtype {
        return Err(LldpError::UnsupportedIdentifierSubtype {
            tlv_type: tlv.tlv_type,
            subtype,
            expected: text_subtype,
        });
    }

    std::str::from_utf8(&tlv.value[1..])
        .map(str::to_owned)
        .map_err(|_| LldpError::InvalidUtf8Identifier {
            tlv_type: tlv.tlv_type,
        })
}

impl LldpPacket {
    pub fn parse(data: &[u8]) -> Result<Self, LldpError> {
        let mut offset = 0;
        let mut chassis_id = None;
        let mut port_id = None;
        let mut ttl = None;
        let mut system_name = None;
        let mut mandatory_count = 0u8;
        let mut saw_end = false;

        while offset < data.len() {
            let (tlv, consumed) = LldpTlv::parse(&data[offset..])?;
            offset += consumed;

            let expected = match mandatory_count {
                0 => "Chassis ID",
                1 => "Port ID",
                2 => "TTL",
                _ => "optional TLV or End-of-LLDPDU",
            };

            match tlv.tlv_type {
                LLDP_TLV_END_OF_LLDPDU => {
                    if !tlv.value.is_empty() {
                        return Err(LldpError::InvalidTlvLength {
                            tlv_type: LLDP_TLV_END_OF_LLDPDU,
                            length: tlv.value.len(),
                        });
                    }
                    if mandatory_count < 3 {
                        return Err(LldpError::MissingMandatoryTlv(expected));
                    }
                    saw_end = true;
                    break;
                }
                LLDP_TLV_CHASSIS_ID => {
                    if mandatory_count != 0 {
                        return Err(LldpError::InvalidMandatoryTlvOrder {
                            expected,
                            found: tlv.tlv_type,
                        });
                    }
                    chassis_id = Some(parse_identifier(
                        &tlv,
                        LLDP_CHASSIS_ID_SUBTYPE_LOCALLY_ASSIGNED,
                        LLDP_CHASSIS_ID_SUBTYPE_MAC_ADDRESS,
                    )?);
                    mandatory_count = 1;
                }
                LLDP_TLV_PORT_ID => {
                    if mandatory_count != 1 {
                        return Err(LldpError::InvalidMandatoryTlvOrder {
                            expected,
                            found: tlv.tlv_type,
                        });
                    }
                    port_id = Some(parse_identifier(
                        &tlv,
                        LLDP_PORT_ID_SUBTYPE_INTERFACE_NAME,
                        LLDP_PORT_ID_SUBTYPE_MAC_ADDRESS,
                    )?);
                    mandatory_count = 2;
                }
                LLDP_TLV_TTL => {
                    if mandatory_count != 2 {
                        return Err(LldpError::InvalidMandatoryTlvOrder {
                            expected,
                            found: tlv.tlv_type,
                        });
                    }
                    if tlv.value.len() != 2 {
                        return Err(LldpError::InvalidTlvLength {
                            tlv_type: LLDP_TLV_TTL,
                            length: tlv.value.len(),
                        });
                    }
                    ttl = Some(u16::from_be_bytes([tlv.value[0], tlv.value[1]]));
                    mandatory_count = 3;
                }
                LLDP_TLV_SYSTEM_NAME => {
                    if mandatory_count < 3 {
                        return Err(LldpError::InvalidMandatoryTlvOrder {
                            expected,
                            found: tlv.tlv_type,
                        });
                    }
                    if system_name.is_some() {
                        return Err(LldpError::DuplicateTlv {
                            tlv_type: LLDP_TLV_SYSTEM_NAME,
                        });
                    }
                    system_name = Some(
                        std::str::from_utf8(&tlv.value)
                            .map(str::to_owned)
                            .map_err(|_| LldpError::InvalidUtf8Identifier {
                                tlv_type: LLDP_TLV_SYSTEM_NAME,
                            })?,
                    );
                }
                _ => {
                    if mandatory_count < 3 {
                        return Err(LldpError::InvalidMandatoryTlvOrder {
                            expected,
                            found: tlv.tlv_type,
                        });
                    }
                }
            }
        }

        if !saw_end {
            if mandatory_count < 3 {
                let missing = match mandatory_count {
                    0 => "Chassis ID",
                    1 => "Port ID",
                    _ => "TTL",
                };
                return Err(LldpError::MissingMandatoryTlv(missing));
            }
            return Err(LldpError::MissingEndOfLldpdu);
        }

        Ok(LldpPacket {
            chassis_id: chassis_id.expect("mandatory Chassis ID was validated"),
            port_id: port_id.expect("mandatory Port ID was validated"),
            ttl: ttl.expect("mandatory TTL was validated"),
            system_name,
        })
    }

    pub fn serialize(&self) -> Vec<u8> {
        self.try_serialize()
            .expect("LLDP packet TLV values must fit their 9-bit length fields")
    }

    pub fn try_serialize(&self) -> Result<Vec<u8>, LldpSerializeError> {
        let mut buf = Vec::new();

        if self.chassis_id.is_empty() {
            return Err(LldpSerializeError::EmptyIdentifier {
                tlv_type: LLDP_TLV_CHASSIS_ID,
            });
        }
        if self.port_id.is_empty() {
            return Err(LldpSerializeError::EmptyIdentifier {
                tlv_type: LLDP_TLV_PORT_ID,
            });
        }

        // 1. Chassis ID (TLV 1): subtype + identifier.
        let mut chassis_value = Vec::with_capacity(1 + self.chassis_id.len());
        chassis_value.push(LLDP_CHASSIS_ID_SUBTYPE_LOCALLY_ASSIGNED);
        chassis_value.extend_from_slice(self.chassis_id.as_bytes());
        let tlv1 = LldpTlv {
            tlv_type: LLDP_TLV_CHASSIS_ID,
            value: chassis_value,
        };
        buf.extend(tlv1.try_serialize()?);

        // 2. Port ID (TLV 2): subtype + identifier.
        let mut port_value = Vec::with_capacity(1 + self.port_id.len());
        port_value.push(LLDP_PORT_ID_SUBTYPE_INTERFACE_NAME);
        port_value.extend_from_slice(self.port_id.as_bytes());
        let tlv2 = LldpTlv {
            tlv_type: LLDP_TLV_PORT_ID,
            value: port_value,
        };
        buf.extend(tlv2.try_serialize()?);

        // 3. TTL (TLV 3)
        let tlv3 = LldpTlv {
            tlv_type: LLDP_TLV_TTL,
            value: self.ttl.to_be_bytes().to_vec(),
        };
        buf.extend(tlv3.try_serialize()?);

        // Optional: System Name (TLV 5)
        if let Some(ref name) = self.system_name {
            let tlv5 = LldpTlv {
                tlv_type: LLDP_TLV_SYSTEM_NAME,
                value: name.as_bytes().to_vec(),
            };
            buf.extend(tlv5.try_serialize()?);
        }

        // End of LLDPDU (TLV 0)
        buf.extend_from_slice(&[0, 0]);

        Ok(buf)
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
    fn test_duplicate_system_name_is_rejected() {
        let pkt = LldpPacket {
            chassis_id: "chassis".to_string(),
            port_id: "eth0".to_string(),
            ttl: 120,
            system_name: Some("first".to_string()),
        };

        let mut raw = pkt.serialize();
        raw.truncate(raw.len() - 2);
        raw.extend(
            LldpTlv {
                tlv_type: LLDP_TLV_SYSTEM_NAME,
                value: b"second".to_vec(),
            }
            .serialize(),
        );
        raw.extend_from_slice(&[0, 0]);

        assert_eq!(
            LldpPacket::parse(&raw),
            Err(LldpError::DuplicateTlv {
                tlv_type: LLDP_TLV_SYSTEM_NAME,
            })
        );
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

    #[test]
    fn test_tlv_type_127_roundtrips() {
        let tlv = LldpTlv {
            tlv_type: LLDP_TLV_MAX_TYPE,
            value: vec![0x5a],
        };

        let raw = tlv.try_serialize().unwrap();
        assert_eq!(
            (u16::from_be_bytes([raw[0], raw[1]]) >> 9) as u8,
            LLDP_TLV_MAX_TYPE
        );

        let (parsed, consumed) = LldpTlv::parse(&raw).unwrap();
        assert_eq!(consumed, raw.len());
        assert_eq!(parsed, tlv);
    }

    #[test]
    fn test_tlv_type_128_is_rejected() {
        let tlv = LldpTlv {
            tlv_type: LLDP_TLV_MAX_TYPE + 1,
            value: Vec::new(),
        };

        assert_eq!(
            tlv.try_serialize(),
            Err(LldpSerializeError::TlvTypeOutOfRange {
                tlv_type: LLDP_TLV_MAX_TYPE + 1,
                max: LLDP_TLV_MAX_TYPE,
            })
        );
    }

    #[test]
    fn test_tlv_type_255_is_rejected_instead_of_wrapping() {
        let tlv = LldpTlv {
            tlv_type: u8::MAX,
            value: vec![0x01],
        };

        assert_eq!(
            tlv.try_serialize(),
            Err(LldpSerializeError::TlvTypeOutOfRange {
                tlv_type: u8::MAX,
                max: LLDP_TLV_MAX_TYPE,
            })
        );
    }

    #[test]
    fn test_tlv_511_byte_value_roundtrips() {
        let tlv = LldpTlv {
            tlv_type: LLDP_TLV_SYSTEM_DESCRIPTION,
            value: vec![0x5a; LLDP_TLV_MAX_VALUE_LEN],
        };

        let raw = tlv.try_serialize().unwrap();
        assert_eq!(raw.len(), 2 + LLDP_TLV_MAX_VALUE_LEN);
        assert_eq!(u16::from_be_bytes([raw[0], raw[1]]) & 0x01ff, 0x01ff);

        let (parsed, consumed) = LldpTlv::parse(&raw).unwrap();
        assert_eq!(consumed, raw.len());
        assert_eq!(parsed, tlv);
    }

    #[test]
    fn test_tlv_512_byte_value_is_rejected() {
        let tlv = LldpTlv {
            tlv_type: LLDP_TLV_SYSTEM_DESCRIPTION,
            value: vec![0x5a; LLDP_TLV_MAX_VALUE_LEN + 1],
        };

        assert_eq!(
            tlv.try_serialize(),
            Err(LldpSerializeError::TlvValueTooLong {
                tlv_type: LLDP_TLV_SYSTEM_DESCRIPTION,
                length: LLDP_TLV_MAX_VALUE_LEN + 1,
                max: LLDP_TLV_MAX_VALUE_LEN,
            })
        );
    }

    #[test]
    fn test_packet_allows_510_byte_identifier() {
        let pkt = LldpPacket {
            chassis_id: "c".repeat(LLDP_TLV_MAX_VALUE_LEN - 1),
            port_id: "p".repeat(LLDP_TLV_MAX_VALUE_LEN - 1),
            ttl: 120,
            system_name: None,
        };

        let raw = pkt.try_serialize().unwrap();
        let parsed = LldpPacket::parse(&raw).unwrap();
        assert_eq!(parsed.chassis_id, pkt.chassis_id);
        assert_eq!(parsed.port_id, pkt.port_id);
    }

    #[test]
    fn test_packet_rejects_511_byte_identifier() {
        let pkt = LldpPacket {
            chassis_id: "c".repeat(LLDP_TLV_MAX_VALUE_LEN),
            port_id: "eth0".to_string(),
            ttl: 120,
            system_name: None,
        };

        assert_eq!(
            pkt.try_serialize(),
            Err(LldpSerializeError::TlvValueTooLong {
                tlv_type: LLDP_TLV_CHASSIS_ID,
                length: LLDP_TLV_MAX_VALUE_LEN + 1,
                max: LLDP_TLV_MAX_VALUE_LEN,
            })
        );
    }

    #[test]
    fn test_packet_rejects_empty_identifiers() {
        let empty_chassis = LldpPacket {
            chassis_id: String::new(),
            port_id: "eth0".to_string(),
            ttl: 120,
            system_name: None,
        };
        let empty_port = LldpPacket {
            chassis_id: "chassis".to_string(),
            port_id: String::new(),
            ttl: 120,
            system_name: None,
        };

        assert_eq!(
            empty_chassis.try_serialize(),
            Err(LldpSerializeError::EmptyIdentifier {
                tlv_type: LLDP_TLV_CHASSIS_ID,
            })
        );
        assert_eq!(
            empty_port.try_serialize(),
            Err(LldpSerializeError::EmptyIdentifier {
                tlv_type: LLDP_TLV_PORT_ID,
            })
        );
    }

    #[test]
    fn test_packet_rejects_512_byte_system_name() {
        let pkt = LldpPacket {
            chassis_id: "chassis".to_string(),
            port_id: "eth0".to_string(),
            ttl: 120,
            system_name: Some("s".repeat(LLDP_TLV_MAX_VALUE_LEN + 1)),
        };

        assert_eq!(
            pkt.try_serialize(),
            Err(LldpSerializeError::TlvValueTooLong {
                tlv_type: LLDP_TLV_SYSTEM_NAME,
                length: LLDP_TLV_MAX_VALUE_LEN + 1,
                max: LLDP_TLV_MAX_VALUE_LEN,
            })
        );
    }
}
