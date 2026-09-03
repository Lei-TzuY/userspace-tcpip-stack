//! Virtual eXtensible Local Area Network (VXLAN - RFC 7348).
//!
//! Layer 2 overlay encapsulation over UDP port 4789 with a 24-bit VXLAN Network Identifier (VNI).
//! Enables 16 million virtual subnets across Layer 3 underlay networks.

use std::fmt;

pub const VXLAN_UDP_PORT: u16 = 4789;
pub const VXLAN_HEADER_LEN: usize = 8;
pub const VXLAN_FLAG_VNI_VALID: u8 = 0x08;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VxlanHeader {
    pub flags: u8,
    pub vni: u32, // 24-bit (0..16,777,215)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VxlanPacket {
    pub header: VxlanHeader,
    pub inner_frame: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VxlanError {
    PacketTooShort(usize),
    InvalidFlags(u8),
    InvalidVni(u32),
}

impl fmt::Display for VxlanError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VxlanError::PacketTooShort(l) => {
                write!(f, "VXLAN packet too short ({} bytes, min 8)", l)
            }
            VxlanError::InvalidFlags(fl) => {
                write!(f, "Invalid VXLAN flags: 0x{:02x} (expected 0x08)", fl)
            }
            VxlanError::InvalidVni(v) => write!(f, "VXLAN VNI exceeds 24 bits: {}", v),
        }
    }
}

impl std::error::Error for VxlanError {}

impl VxlanHeader {
    pub fn new(vni: u32) -> Result<Self, VxlanError> {
        if vni > 0x00FF_FFFF {
            return Err(VxlanError::InvalidVni(vni));
        }
        Ok(VxlanHeader {
            flags: VXLAN_FLAG_VNI_VALID,
            vni,
        })
    }

    pub fn parse(data: &[u8]) -> Result<Self, VxlanError> {
        if data.len() < VXLAN_HEADER_LEN {
            return Err(VxlanError::PacketTooShort(data.len()));
        }

        let flags = data[0];
        if (flags & VXLAN_FLAG_VNI_VALID) == 0 {
            return Err(VxlanError::InvalidFlags(flags));
        }

        let vni = ((data[4] as u32) << 16) | ((data[5] as u32) << 8) | (data[6] as u32);
        Ok(VxlanHeader { flags, vni })
    }

    pub fn serialize(&self) -> [u8; 8] {
        let mut b = [0u8; 8];
        // RFC 7348 requires the I bit on and all other flag bits zero on transmission.
        b[0] = VXLAN_FLAG_VNI_VALID;
        b[4] = ((self.vni >> 16) & 0xFF) as u8;
        b[5] = ((self.vni >> 8) & 0xFF) as u8;
        b[6] = (self.vni & 0xFF) as u8;
        b
    }
}

impl VxlanPacket {
    pub fn parse(data: &[u8]) -> Result<Self, VxlanError> {
        let header = VxlanHeader::parse(data)?;
        let inner_frame = data[VXLAN_HEADER_LEN..].to_vec();
        Ok(VxlanPacket {
            header,
            inner_frame,
        })
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(VXLAN_HEADER_LEN + self.inner_frame.len());
        buf.extend_from_slice(&self.header.serialize());
        buf.extend_from_slice(&self.inner_frame);
        buf
    }

    pub fn encapsulate(vni: u32, inner_ethernet_frame: &[u8]) -> Result<Vec<u8>, VxlanError> {
        let hdr = VxlanHeader::new(vni)?;
        let pkt = VxlanPacket {
            header: hdr,
            inner_frame: inner_ethernet_frame.to_vec(),
        };
        Ok(pkt.serialize())
    }

    pub fn decapsulate(data: &[u8]) -> Result<(u32, Vec<u8>), VxlanError> {
        let pkt = Self::parse(data)?;
        Ok((pkt.header.vni, pkt.inner_frame))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vxlan_header_roundtrip() {
        let hdr = VxlanHeader::new(100500).unwrap();
        let raw = hdr.serialize();

        assert_eq!(raw.len(), 8);
        assert_eq!(raw[0], VXLAN_FLAG_VNI_VALID);

        let parsed = VxlanHeader::parse(&raw).unwrap();
        assert_eq!(parsed.vni, 100500);
    }

    #[test]
    fn test_vxlan_serializer_clears_reserved_flag_bits() {
        let mut hdr = VxlanHeader::new(42).unwrap();
        hdr.flags = 0xFF;

        let raw = hdr.serialize();

        assert_eq!(raw[0], VXLAN_FLAG_VNI_VALID);
    }

    #[test]
    fn test_vxlan_encapsulate_and_decapsulate() {
        let inner_ether = vec![0x52, 0x54, 0x00, 0x12, 0x34, 0x56, 0x08, 0x00, 0x45, 0x00];
        let encap = VxlanPacket::encapsulate(5001, &inner_ether).unwrap();

        assert_eq!(encap.len(), 8 + inner_ether.len());

        let (vni, recovered_inner) = VxlanPacket::decapsulate(&encap).unwrap();
        assert_eq!(vni, 5001);
        assert_eq!(recovered_inner, inner_ether);
    }
}
