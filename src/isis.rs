//! Intermediate System to Intermediate System (IS-IS - ISO/IEC 10589 / RFC 1195).
//!
//! Layer 2 Link-State Dynamic Routing Protocol for Tier-1 Service Provider Backbones.

use crate::ipv4::Ipv4Address;
use std::fmt;

pub const ETHERTYPE_ISIS: u16 = 0x8870;
pub const ISIS_NLPID_DISCRIMINATOR: u8 = 0x83;
pub const ISIS_COMMON_HEADER_LEN: usize = 8;
pub const ISIS_LAN_IIH_FIXED_LEN: usize = 19;

// IS-IS PDU Types
pub const ISIS_PDU_L1_LAN_IIH: u8 = 15;
pub const ISIS_PDU_L2_LAN_IIH: u8 = 16;
pub const ISIS_PDU_P2P_IIH: u8 = 17;
pub const ISIS_PDU_L1_LSP: u8 = 18;
pub const ISIS_PDU_L2_LSP: u8 = 20;

// IS-IS Standard TLV Types
pub const ISIS_TLV_AREA_ADDRESSES: u8 = 1;
pub const ISIS_TLV_IS_NEIGHBORS: u8 = 2;
pub const ISIS_TLV_PROTOCOLS_SUPPORTED: u8 = 129;
pub const ISIS_TLV_IP_INTERFACE_ADDR: u8 = 132;

// NLPID Protocol Identifiers
pub const NLPID_IPV4: u8 = 0xCC;
pub const NLPID_IPV6: u8 = 0x8E;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IsisTlv {
    pub tlv_type: u8,
    pub value: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IsisHeader {
    pub nlpid: u8,
    pub header_length: u8,
    pub version_id: u8,
    pub id_length: u8,
    pub pdu_type: u8,
    pub version: u8,
    pub max_area_addresses: u8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IsisHelloPacket {
    pub header: IsisHeader,
    pub circuit_type: u8,
    pub source_id: [u8; 6],
    pub holding_time: u16,
    pub priority: u8,
    pub lan_id: [u8; 7],
    pub tlvs: Vec<IsisTlv>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IsisError {
    PacketTooShort(usize),
    InvalidDiscriminator(u8),
    InvalidPduType(u8),
    InvalidPduLength(u16),
    InvalidTlvLength,
}

impl fmt::Display for IsisError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IsisError::PacketTooShort(l) => write!(f, "IS-IS packet too short ({} bytes)", l),
            IsisError::InvalidDiscriminator(d) => {
                write!(f, "Invalid IS-IS discriminator 0x{:02X} (expected 0x83)", d)
            }
            IsisError::InvalidPduType(t) => write!(f, "Unsupported IS-IS PDU type: {}", t),
            IsisError::InvalidPduLength(l) => write!(f, "Invalid IS-IS PDU length: {}", l),
            IsisError::InvalidTlvLength => write!(f, "Invalid IS-IS TLV length field"),
        }
    }
}

impl std::error::Error for IsisError {}

impl IsisHelloPacket {
    pub fn parse(data: &[u8]) -> Result<Self, IsisError> {
        let min_len = ISIS_COMMON_HEADER_LEN + ISIS_LAN_IIH_FIXED_LEN;
        if data.len() < min_len {
            return Err(IsisError::PacketTooShort(data.len()));
        }

        let nlpid = data[0];
        if nlpid != ISIS_NLPID_DISCRIMINATOR {
            return Err(IsisError::InvalidDiscriminator(nlpid));
        }

        let header_length = data[1];
        let version_id = data[2];
        let id_length = data[3];
        let pdu_type = data[4] & 0x1F;
        let version = data[5];
        let max_area_addresses = data[7];

        let header = IsisHeader {
            nlpid,
            header_length,
            version_id,
            id_length,
            pdu_type,
            version,
            max_area_addresses,
        };

        let circuit_type = data[8];
        let mut source_id = [0u8; 6];
        source_id.copy_from_slice(&data[9..15]);

        let holding_time = u16::from_be_bytes([data[15], data[16]]);
        let pdu_length = u16::from_be_bytes([data[17], data[18]]);
        let pdu_len = pdu_length as usize;
        if pdu_len < min_len || pdu_len > data.len() {
            return Err(IsisError::InvalidPduLength(pdu_length));
        }
        let pdu = &data[..pdu_len];
        let priority = pdu[19] & 0x7F;

        let mut lan_id = [0u8; 7];
        lan_id.copy_from_slice(&pdu[20..27]);

        let mut tlvs = Vec::new();
        let mut offset = 27;
        while offset < pdu.len() {
            if offset + 2 > pdu.len() {
                return Err(IsisError::InvalidTlvLength);
            }
            let tlv_type = pdu[offset];
            let tlv_len = pdu[offset + 1] as usize;
            if offset + 2 + tlv_len > pdu.len() {
                return Err(IsisError::InvalidTlvLength);
            }
            let value = pdu[offset + 2..offset + 2 + tlv_len].to_vec();
            tlvs.push(IsisTlv { tlv_type, value });
            offset += 2 + tlv_len;
        }

        Ok(IsisHelloPacket {
            header,
            circuit_type,
            source_id,
            holding_time,
            priority,
            lan_id,
            tlvs,
        })
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut tlvs_bytes = Vec::new();
        for tlv in &self.tlvs {
            tlvs_bytes.push(tlv.tlv_type);
            tlvs_bytes.push(tlv.value.len() as u8);
            tlvs_bytes.extend_from_slice(&tlv.value);
        }

        let total_pdu_len =
            (ISIS_COMMON_HEADER_LEN + ISIS_LAN_IIH_FIXED_LEN + tlvs_bytes.len()) as u16;
        let mut buf = vec![0u8; total_pdu_len as usize];

        buf[0] = self.header.nlpid;
        buf[1] = self.header.header_length;
        buf[2] = self.header.version_id;
        buf[3] = self.header.id_length;
        buf[4] = self.header.pdu_type;
        buf[5] = self.header.version;
        buf[6] = 0x00; // Reserved
        buf[7] = self.header.max_area_addresses;

        buf[8] = self.circuit_type;
        buf[9..15].copy_from_slice(&self.source_id);
        buf[15..17].copy_from_slice(&self.holding_time.to_be_bytes());
        buf[17..19].copy_from_slice(&total_pdu_len.to_be_bytes());
        buf[19] = self.priority & 0x7F;
        buf[20..27].copy_from_slice(&self.lan_id);

        buf[27..].copy_from_slice(&tlvs_bytes);

        buf
    }

    pub fn build_l1_lan_hello(system_id: [u8; 6], area_id: &[u8], ip: Ipv4Address) -> Self {
        let header = IsisHeader {
            nlpid: ISIS_NLPID_DISCRIMINATOR,
            header_length: (ISIS_COMMON_HEADER_LEN + ISIS_LAN_IIH_FIXED_LEN) as u8,
            version_id: 1,
            id_length: 0,
            pdu_type: ISIS_PDU_L1_LAN_IIH,
            version: 1,
            max_area_addresses: 0,
        };

        let mut area_tlv = vec![area_id.len() as u8];
        area_tlv.extend_from_slice(area_id);

        let tlvs = vec![
            IsisTlv {
                tlv_type: ISIS_TLV_AREA_ADDRESSES,
                value: area_tlv,
            },
            IsisTlv {
                tlv_type: ISIS_TLV_PROTOCOLS_SUPPORTED,
                value: vec![NLPID_IPV4, NLPID_IPV6],
            },
            IsisTlv {
                tlv_type: ISIS_TLV_IP_INTERFACE_ADDR,
                value: ip.0.to_vec(),
            },
        ];

        let mut lan_id = [0u8; 7];
        lan_id[..6].copy_from_slice(&system_id);
        lan_id[6] = 0x01; // Pseudonode ID

        IsisHelloPacket {
            header,
            circuit_type: 1, // Level 1 only
            source_id: system_id,
            holding_time: 30,
            priority: 64,
            lan_id,
            tlvs,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_isis_rejects_declared_pdu_length_below_fixed_header() {
        let hello = IsisHelloPacket::build_l1_lan_hello(
            [0, 0, 0, 0, 0, 1],
            &[0x49, 0x00, 0x01],
            Ipv4Address::new(192, 0, 2, 1),
        );
        let mut raw = hello.serialize();
        raw[17..19].copy_from_slice(&26u16.to_be_bytes());
        assert_eq!(
            IsisHelloPacket::parse(&raw),
            Err(IsisError::InvalidPduLength(26))
        );
    }

    #[test]
    fn test_isis_rejects_declared_pdu_length_beyond_packet() {
        let hello = IsisHelloPacket::build_l1_lan_hello(
            [0, 0, 0, 0, 0, 1],
            &[0x49, 0x00, 0x01],
            Ipv4Address::new(192, 0, 2, 1),
        );
        let mut raw = hello.serialize();
        let declared = raw.len() as u16 + 1;
        raw[17..19].copy_from_slice(&declared.to_be_bytes());
        assert_eq!(
            IsisHelloPacket::parse(&raw),
            Err(IsisError::InvalidPduLength(declared))
        );
    }

    #[test]
    fn test_isis_ignores_bytes_after_declared_pdu_length() {
        let hello = IsisHelloPacket::build_l1_lan_hello(
            [0, 0, 0, 0, 0, 1],
            &[0x49, 0x00, 0x01],
            Ipv4Address::new(192, 0, 2, 1),
        );
        let mut raw = hello.serialize();
        raw.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
        let parsed = IsisHelloPacket::parse(&raw).expect("Ethernet padding must be outside PDU");
        assert_eq!(parsed.tlvs, hello.tlvs);
    }

    #[test]
    fn test_isis_rejects_partial_tlv_header_within_declared_pdu() {
        let hello = IsisHelloPacket::build_l1_lan_hello(
            [0, 0, 0, 0, 0, 1],
            &[0x49, 0x00, 0x01],
            Ipv4Address::new(192, 0, 2, 1),
        );
        let mut raw = hello.serialize();
        raw.push(ISIS_TLV_PROTOCOLS_SUPPORTED);
        let declared = raw.len() as u16;
        raw[17..19].copy_from_slice(&declared.to_be_bytes());
        assert_eq!(
            IsisHelloPacket::parse(&raw),
            Err(IsisError::InvalidTlvLength)
        );
    }

    #[test]
    fn test_isis_lan_hello_roundtrip() {
        let sys_id = [0x00, 0x00, 0x00, 0x00, 0x00, 0x01];
        let area = &[0x49, 0x00, 0x01];
        let ip = Ipv4Address::new(192, 168, 1, 1);

        let hello = IsisHelloPacket::build_l1_lan_hello(sys_id, area, ip);
        let raw = hello.serialize();

        assert!(raw.len() >= ISIS_COMMON_HEADER_LEN + ISIS_LAN_IIH_FIXED_LEN);
        let parsed = IsisHelloPacket::parse(&raw).unwrap();

        assert_eq!(parsed.header.nlpid, ISIS_NLPID_DISCRIMINATOR);
        assert_eq!(parsed.header.pdu_type, ISIS_PDU_L1_LAN_IIH);
        assert_eq!(parsed.source_id, sys_id);
        assert_eq!(parsed.priority, 64);
        assert_eq!(parsed.tlvs.len(), 3);
        assert_eq!(parsed.tlvs[1].tlv_type, ISIS_TLV_PROTOCOLS_SUPPORTED);
        assert_eq!(parsed.tlvs[1].value, vec![NLPID_IPV4, NLPID_IPV6]);
    }
}
