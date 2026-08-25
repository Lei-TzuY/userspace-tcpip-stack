//! Network Service Header (NSH) MD Type 2 Dynamic Variable-Length Context Headers (RFC 8300 Section 3.5.2).
//!
//! Implements NSH Metadata Type 2 with dynamic Type-Length-Value (TLV) context headers for Service Function
//! Chaining (SFC). Supports dynamic tenant classification, flow hashing, in-band path telemetry, and security group tags.

/// NSH Base Header Length in bytes (Version, Length, MD Type, Next Protocol).
pub const NSH_BASE_HEADER_LEN: usize = 4;

/// NSH Service Path Header Length in bytes (SPI and SI).
pub const NSH_SERVICE_PATH_HEADER_LEN: usize = 4;

/// Metadata Type 2 indicator.
pub const NSH_MD_TYPE_2: u8 = 0x02;

/// Standard IETF Metadata Class (RFC 8300 Section 3.5.2).
pub const NSH_TLV_CLASS_IETF: u16 = 0x0000;

/// Standard TLV Types under IETF Class.
pub const NSH_TLV_TYPE_TENANT_ID: u8 = 0x01;
pub const NSH_TLV_TYPE_SOURCE_INTERFACE: u8 = 0x02;
pub const NSH_TLV_TYPE_FLOW_HASH: u8 = 0x03;
pub const NSH_TLV_TYPE_SECURITY_GROUP_TAG: u8 = 0x04;
pub const NSH_TLV_TYPE_INBAND_PATH_TRACE: u8 = 0x05;

/// Next Protocol Values.
pub const NSH_NP_IPV4: u8 = 0x01;
pub const NSH_NP_IPV6: u8 = 0x02;
pub const NSH_NP_ETHERNET: u8 = 0x03;
pub const NSH_NP_NSH: u8 = 0x04;
pub const NSH_NP_MPLS: u8 = 0x05;

/// Variable-Length Context Header TLV (RFC 8300 Section 3.5.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NshContextTlv {
    pub class: u16,
    pub tlv_type: u8,
    pub critical: bool,
    pub data: Vec<u8>,
}

impl NshContextTlv {
    pub fn new(class: u16, tlv_type: u8, critical: bool, data: Vec<u8>) -> Self {
        let mut padded = data;
        while padded.len() % 4 != 0 {
            padded.push(0);
        }
        NshContextTlv {
            class,
            tlv_type,
            critical,
            data: padded,
        }
    }

    pub fn new_tenant_id(tenant_id: u32) -> Self {
        Self::new(
            NSH_TLV_CLASS_IETF,
            NSH_TLV_TYPE_TENANT_ID,
            false,
            tenant_id.to_be_bytes().to_vec(),
        )
    }

    pub fn new_source_interface(ifindex: u32) -> Self {
        Self::new(
            NSH_TLV_CLASS_IETF,
            NSH_TLV_TYPE_SOURCE_INTERFACE,
            false,
            ifindex.to_be_bytes().to_vec(),
        )
    }

    pub fn new_flow_hash(hash: u32) -> Self {
        Self::new(
            NSH_TLV_CLASS_IETF,
            NSH_TLV_TYPE_FLOW_HASH,
            false,
            hash.to_be_bytes().to_vec(),
        )
    }

    pub fn new_security_group_tag(sgt: u32) -> Self {
        Self::new(
            NSH_TLV_CLASS_IETF,
            NSH_TLV_TYPE_SECURITY_GROUP_TAG,
            false,
            sgt.to_be_bytes().to_vec(),
        )
    }

    /// Serializes this TLV to bytes.
    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&self.class.to_be_bytes());
        buf.push(self.tlv_type);

        let words_len = (self.data.len() / 4) as u8;
        let flags_len = if self.critical { 0x40 | (words_len & 0x3F) } else { words_len & 0x3F };
        buf.push(flags_len);

        buf.extend_from_slice(&self.data);
        buf
    }

    /// Parses a Variable Context TLV from a byte slice.
    pub fn parse(data: &[u8]) -> Option<(Self, usize)> {
        if data.len() < 4 {
            return None;
        }
        let class = u16::from_be_bytes([data[0], data[1]]);
        let tlv_type = data[2];
        let flags_len = data[3];
        let critical = (flags_len & 0x40) != 0;
        let words_len = (flags_len & 0x3F) as usize;
        let data_len = words_len * 4;

        if data.len() < 4 + data_len {
            return None;
        }

        let tlv_data = data[4..4 + data_len].to_vec();
        Some((
            NshContextTlv {
                class,
                tlv_type,
                critical,
                data: tlv_data,
            },
            4 + data_len,
        ))
    }
}

/// NSH MD Type 2 Header (RFC 8300 Section 3.5.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NshMd2Header {
    pub oam: bool,
    pub critical: bool,
    pub next_protocol: u8,
    pub service_path_id: u32, // 24-bit SPI
    pub service_index: u8,    // 8-bit SI
    pub tlvs: Vec<NshContextTlv>,
}

impl NshMd2Header {
    pub fn new(spi: u32, si: u8, next_proto: u8) -> Self {
        NshMd2Header {
            oam: false,
            critical: false,
            next_protocol: next_proto,
            service_path_id: spi & 0x00FF_FFFF,
            service_index: si,
            tlvs: Vec::new(),
        }
    }

    pub fn with_tlv(mut self, tlv: NshContextTlv) -> Self {
        self.tlvs.push(tlv);
        self
    }

    /// Total header length in 4-byte (32-bit) words.
    pub fn length_words(&self) -> usize {
        let mut tlv_bytes = 0;
        for t in &self.tlvs {
            tlv_bytes += 4 + t.data.len();
        }
        (NSH_BASE_HEADER_LEN + NSH_SERVICE_PATH_HEADER_LEN + tlv_bytes) / 4
    }

    pub fn serialize(&self) -> Vec<u8> {
        let total_words = self.length_words();
        let mut buf = Vec::with_capacity(total_words * 4);

        let mut b0 = 0u8; // Version 0
        if self.oam {
            b0 |= 0x20;
        }
        if self.critical {
            b0 |= 0x10;
        }
        buf.push(b0);
        buf.push(total_words as u8);
        buf.push(NSH_MD_TYPE_2);
        buf.push(self.next_protocol);

        let spi_bytes = (self.service_path_id & 0x00FF_FFFF).to_be_bytes();
        buf.extend_from_slice(&spi_bytes[1..4]);
        buf.push(self.service_index);

        for t in &self.tlvs {
            buf.extend_from_slice(&t.serialize());
        }

        buf
    }

    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 8 {
            return None;
        }
        let b0 = data[0];
        let version = (b0 >> 6) & 0x03;
        if version != 0 {
            return None;
        }
        let oam = (b0 & 0x20) != 0;
        let critical = (b0 & 0x10) != 0;
        let total_words = data[1] as usize;
        let total_bytes = total_words * 4;

        if total_bytes < 8 || data.len() < total_bytes {
            return None;
        }

        let md_type = data[2];
        if md_type != NSH_MD_TYPE_2 {
            return None;
        }
        let next_protocol = data[3];

        let spi = u32::from_be_bytes([0, data[4], data[5], data[6]]);
        let service_index = data[7];

        let mut offset = 8;
        let mut tlvs = Vec::new();

        while offset < total_bytes {
            let (tlv, consumed) = NshContextTlv::parse(&data[offset..total_bytes])?;
            tlvs.push(tlv);
            offset += consumed;
        }

        Some(NshMd2Header {
            oam,
            critical,
            next_protocol,
            service_path_id: spi,
            service_index,
            tlvs,
        })
    }
}

/// Full NSH MD Type 2 Packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NshMd2Packet {
    pub header: NshMd2Header,
    pub payload: Vec<u8>,
}

impl NshMd2Packet {
    pub fn new(header: NshMd2Header, payload: Vec<u8>) -> Self {
        NshMd2Packet { header, payload }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = self.header.serialize();
        bytes.extend_from_slice(&self.payload);
        bytes
    }

    pub fn decode(data: &[u8]) -> Option<Self> {
        let header = NshMd2Header::parse(data)?;
        let hdr_len = header.length_words() * 4;
        let payload = data[hdr_len..].to_vec();
        Some(NshMd2Packet { header, payload })
    }
}

/// Forwarding action taken by a Service Function Forwarder (SFF).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SffForwardingAction {
    ForwardNextHop {
        spi: u32,
        new_si: u8,
        next_hop_node_id: u32,
    },
    EndChain {
        inner_protocol: u8,
    },
    DropServiceIndexZero,
}

/// Service Function Chaining (SFC) Forwarding Engine.
#[derive(Debug, Clone, Default)]
pub struct NshMd2SffEngine {
    pub service_paths: std::collections::HashMap<(u32, u8), u32>, // (SPI, SI) -> Next Node ID
}

pub type NshMd2ForwarderEngine = NshMd2SffEngine;

impl NshMd2SffEngine {
    pub fn new() -> Self {
        NshMd2SffEngine {
            service_paths: std::collections::HashMap::new(),
        }
    }

    pub fn add_path_hop(&mut self, spi: u32, si: u8, next_node_id: u32) {
        self.service_paths.insert((spi, si), next_node_id);
    }

    /// Advances the Service Index (SI) and returns the next forwarding action.
    pub fn process_packet(&self, pkt: &mut NshMd2Packet) -> SffForwardingAction {
        if pkt.header.service_index == 0 {
            return SffForwardingAction::DropServiceIndexZero;
        }

        let current_spi = pkt.header.service_path_id;
        let current_si = pkt.header.service_index;

        if current_si == 1 {
            // Reached tail of chain -> strip NSH header and forward raw payload
            return SffForwardingAction::EndChain {
                inner_protocol: pkt.header.next_protocol,
            };
        }

        let next_si = current_si - 1;
        pkt.header.service_index = next_si;

        if let Some(&next_node) = self.service_paths.get(&(current_spi, current_si)) {
            SffForwardingAction::ForwardNextHop {
                spi: current_spi,
                new_si: next_si,
                next_hop_node_id: next_node,
            }
        } else {
            SffForwardingAction::ForwardNextHop {
                spi: current_spi,
                new_si: next_si,
                next_hop_node_id: 0,
            }
        }
    }
}
