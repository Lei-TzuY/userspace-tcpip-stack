//! Generic Network Virtualization Encapsulation (Geneve - RFC 8926).
//!
//! Next-generation cloud data center overlay network virtualization over UDP port 6081.

use std::fmt;

pub const GENEVE_UDP_PORT: u16 = 6081;
pub const GENEVE_BASE_HEADER_LEN: usize = 8;
pub const ETHERTYPE_TRANSPARENT_ETH: u16 = 0x6558;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GeneveOption {
    pub class: u16,
    pub opt_type: u8,
    pub critical: bool,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GenevePacket {
    pub version: u8,
    pub oam: bool,
    pub critical: bool,
    pub protocol_type: u16,
    pub vni: u32,
    pub options: Vec<GeneveOption>,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GeneveError {
    PacketTooShort(usize),
    InvalidVersion(u8),
    OptionLengthMismatch(usize, usize),
}

impl fmt::Display for GeneveError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            GeneveError::PacketTooShort(l) => {
                write!(f, "Geneve packet too short ({} bytes, min 8)", l)
            }
            GeneveError::InvalidVersion(v) => {
                write!(f, "Invalid Geneve version: expected 0, found {}", v)
            }
            GeneveError::OptionLengthMismatch(exp, act) => write!(
                f,
                "Geneve option length mismatch: expected {}, buffer has {}",
                exp, act
            ),
        }
    }
}

impl std::error::Error for GeneveError {}

impl GenevePacket {
    pub fn parse(data: &[u8]) -> Result<Self, GeneveError> {
        if data.len() < GENEVE_BASE_HEADER_LEN {
            return Err(GeneveError::PacketTooShort(data.len()));
        }

        let b0 = data[0];
        let version = b0 >> 6;
        let opt_len_words = (b0 & 0x3F) as usize;
        let opt_len_bytes = opt_len_words * 4;

        if version != 0 {
            return Err(GeneveError::InvalidVersion(version));
        }

        if data.len() < GENEVE_BASE_HEADER_LEN + opt_len_bytes {
            return Err(GeneveError::OptionLengthMismatch(
                GENEVE_BASE_HEADER_LEN + opt_len_bytes,
                data.len(),
            ));
        }

        let b1 = data[1];
        let oam = (b1 & 0x80) != 0;
        let critical = (b1 & 0x40) != 0;

        let protocol_type = u16::from_be_bytes([data[2], data[3]]);
        let vni = ((data[4] as u32) << 16) | ((data[5] as u32) << 8) | (data[6] as u32);

        // Parse variable Options
        let mut options = Vec::new();
        let mut offset = GENEVE_BASE_HEADER_LEN;
        let opt_end = GENEVE_BASE_HEADER_LEN + opt_len_bytes;

        while offset < opt_end {
            if offset + 4 > opt_end {
                break;
            }
            let class = u16::from_be_bytes([data[offset], data[offset + 1]]);
            let raw_type = data[offset + 2];
            let critical_opt = (raw_type & 0x80) != 0;
            let opt_type = raw_type & 0x7F;
            let opt_data_words = (data[offset + 3] & 0x1F) as usize;
            let opt_data_bytes = opt_data_words * 4;

            if offset + 4 + opt_data_bytes > opt_end {
                return Err(GeneveError::OptionLengthMismatch(
                    offset + 4 + opt_data_bytes,
                    opt_end,
                ));
            }

            let opt_data = data[offset + 4..offset + 4 + opt_data_bytes].to_vec();
            options.push(GeneveOption {
                class,
                opt_type,
                critical: critical_opt,
                data: opt_data,
            });

            offset += 4 + opt_data_bytes;
        }

        let payload = data[opt_end..].to_vec();

        Ok(GenevePacket {
            version,
            oam,
            critical,
            protocol_type,
            vni,
            options,
            payload,
        })
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut options_bytes = Vec::new();
        for opt in &self.options {
            options_bytes.extend_from_slice(&opt.class.to_be_bytes());
            let raw_type = if opt.critical {
                opt.opt_type | 0x80
            } else {
                opt.opt_type
            };
            options_bytes.push(raw_type);
            let opt_data_words = (opt.data.len() / 4) as u8;
            options_bytes.push(opt_data_words & 0x1F);
            options_bytes.extend_from_slice(&opt.data);
        }

        let opt_len_words = (options_bytes.len() / 4) as u8;
        let mut buf = vec![0u8; GENEVE_BASE_HEADER_LEN + options_bytes.len() + self.payload.len()];

        buf[0] = (self.version << 6) | (opt_len_words & 0x3F);
        let mut b1 = 0u8;
        if self.oam {
            b1 |= 0x80;
        }
        if self.critical {
            b1 |= 0x40;
        }
        buf[1] = b1;

        buf[2..4].copy_from_slice(&self.protocol_type.to_be_bytes());
        buf[4] = ((self.vni >> 16) & 0xFF) as u8;
        buf[5] = ((self.vni >> 8) & 0xFF) as u8;
        buf[6] = (self.vni & 0xFF) as u8;
        buf[7] = 0x00; // Reserved

        buf[GENEVE_BASE_HEADER_LEN..GENEVE_BASE_HEADER_LEN + options_bytes.len()]
            .copy_from_slice(&options_bytes);
        buf[GENEVE_BASE_HEADER_LEN + options_bytes.len()..].copy_from_slice(&self.payload);

        buf
    }

    pub fn encapsulate_eth(vni: u32, inner_eth_frame: &[u8]) -> Vec<u8> {
        let pkt = GenevePacket {
            version: 0,
            oam: false,
            critical: false,
            protocol_type: ETHERTYPE_TRANSPARENT_ETH,
            vni,
            options: Vec::new(),
            payload: inner_eth_frame.to_vec(),
        };
        pkt.serialize()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_geneve_encapsulation_roundtrip() {
        let inner_eth = vec![
            0x00, 0x50, 0x56, 0x11, 0x22, 0x33, 0x00, 0x0C, 0x29, 0x44, 0x55, 0x66, 0x08, 0x00,
        ];
        let encap = GenevePacket::encapsulate_eth(100200, &inner_eth);

        assert_eq!(encap.len(), GENEVE_BASE_HEADER_LEN + inner_eth.len());
        let parsed = GenevePacket::parse(&encap).unwrap();
        assert_eq!(parsed.version, 0);
        assert_eq!(parsed.vni, 100200);
        assert_eq!(parsed.protocol_type, ETHERTYPE_TRANSPARENT_ETH);
        assert_eq!(parsed.payload, inner_eth);
    }

    #[test]
    fn test_geneve_with_options() {
        let opt = GeneveOption {
            class: 0x0100, // Open Virtual Network (OVN)
            opt_type: 1,
            critical: false,
            data: vec![0x11, 0x22, 0x33, 0x44],
        };

        let pkt = GenevePacket {
            version: 0,
            oam: false,
            critical: false,
            protocol_type: ETHERTYPE_TRANSPARENT_ETH,
            vni: 5001,
            options: vec![opt.clone()],
            payload: b"Inner Frame".to_vec(),
        };

        let raw = pkt.serialize();
        assert_eq!(raw.len(), GENEVE_BASE_HEADER_LEN + 8 + 11);

        let parsed = GenevePacket::parse(&raw).unwrap();
        assert_eq!(parsed.options.len(), 1);
        assert_eq!(parsed.options[0].class, 0x0100);
        assert_eq!(parsed.options[0].data, vec![0x11, 0x22, 0x33, 0x44]);
    }

    #[test]
    fn test_geneve_rejects_option_data_past_declared_option_area() {
        let mut raw = vec![0u8; GENEVE_BASE_HEADER_LEN + 4];
        raw[0] = 1; // Opt Len = one 4-byte option header.
        raw[8..10].copy_from_slice(&0x0100u16.to_be_bytes());
        raw[10] = 1;
        raw[11] = 1; // Option itself claims another 4 data bytes.

        assert_eq!(
            GenevePacket::parse(&raw),
            Err(GeneveError::OptionLengthMismatch(16, 12))
        );
    }

    #[test]
    fn test_geneve_zero_data_option_remains_valid() {
        let mut raw = vec![0u8; GENEVE_BASE_HEADER_LEN + 4 + 3];
        raw[0] = 1; // Opt Len = one 4-byte option header.
        raw[8..10].copy_from_slice(&0x0100u16.to_be_bytes());
        raw[10] = 7;
        raw[11] = 0; // Zero option-data words is legal.
        raw[12..].copy_from_slice(&[0xaa, 0xbb, 0xcc]);

        let parsed = GenevePacket::parse(&raw).unwrap();
        assert_eq!(parsed.options.len(), 1);
        assert_eq!(parsed.options[0].class, 0x0100);
        assert_eq!(parsed.options[0].opt_type, 7);
        assert!(parsed.options[0].data.is_empty());
        assert_eq!(parsed.payload, vec![0xaa, 0xbb, 0xcc]);
    }
}
