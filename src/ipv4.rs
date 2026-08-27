//! Layer 3: IPv4 packet parsing, validation, and serialization (RFC 791).

use crate::checksum::{compute_checksum, verify_checksum};
use std::fmt;
use std::str::FromStr;

pub const IPV4_MIN_HEADER_LEN: usize = 20;

pub const IP_PROTO_ICMP: u8 = 1;
pub const IP_PROTO_TCP: u8 = 6;
pub const IP_PROTO_UDP: u8 = 17;

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Ipv4Address(pub [u8; 4]);

impl Ipv4Address {
    pub const BROADCAST: Ipv4Address = Ipv4Address([255, 255, 255, 255]);
    pub const LOCALHOST: Ipv4Address = Ipv4Address([127, 0, 0, 1]);
    pub const UNSPECIFIED: Ipv4Address = Ipv4Address([0, 0, 0, 0]);

    pub fn new(a: u8, b: u8, c: u8, d: u8) -> Self {
        Ipv4Address([a, b, c, d])
    }

    pub fn from_bytes(bytes: [u8; 4]) -> Self {
        Ipv4Address(bytes)
    }

    pub fn to_u32(&self) -> u32 {
        u32::from_be_bytes(self.0)
    }

    pub fn from_u32(val: u32) -> Self {
        Ipv4Address(val.to_be_bytes())
    }

    pub fn mask(&self, prefix_len: u8) -> Self {
        if prefix_len == 0 {
            Ipv4Address::UNSPECIFIED
        } else if prefix_len >= 32 {
            *self
        } else {
            let netmask = !((1u32 << (32 - prefix_len)) - 1);
            Ipv4Address::from_u32(self.to_u32() & netmask)
        }
    }

    pub fn is_loopback(&self) -> bool {
        self.0[0] == 127
    }

    pub fn is_multicast(&self) -> bool {
        self.0[0] >= 224 && self.0[0] <= 239
    }

    pub fn is_broadcast(&self) -> bool {
        self.0 == [255, 255, 255, 255]
    }

    pub fn is_unspecified(&self) -> bool {
        self.0 == [0, 0, 0, 0]
    }
}

impl fmt::Debug for Ipv4Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}.{}", self.0[0], self.0[1], self.0[2], self.0[3])
    }
}

impl fmt::Display for Ipv4Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

impl FromStr for Ipv4Address {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts: Vec<&str> = s.split('.').collect();
        if parts.len() != 4 {
            return Err(
                "Invalid IPv4 address format (expected 4 dot-separated octets)".to_string(),
            );
        }
        let mut bytes = [0u8; 4];
        for (i, p) in parts.iter().enumerate() {
            bytes[i] = p
                .parse::<u8>()
                .map_err(|e| format!("Invalid octet '{}': {}", p, e))?;
        }
        Ok(Ipv4Address(bytes))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpProtocol {
    Icmp,
    Tcp,
    Udp,
    Other(u8),
}

impl IpProtocol {
    pub fn from_u8(val: u8) -> Self {
        match val {
            IP_PROTO_ICMP => IpProtocol::Icmp,
            IP_PROTO_TCP => IpProtocol::Tcp,
            IP_PROTO_UDP => IpProtocol::Udp,
            other => IpProtocol::Other(other),
        }
    }

    pub fn to_u8(&self) -> u8 {
        match self {
            IpProtocol::Icmp => IP_PROTO_ICMP,
            IpProtocol::Tcp => IP_PROTO_TCP,
            IpProtocol::Udp => IP_PROTO_UDP,
            IpProtocol::Other(v) => *v,
        }
    }
}

impl fmt::Display for IpProtocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IpProtocol::Icmp => write!(f, "ICMP (1)"),
            IpProtocol::Tcp => write!(f, "TCP (6)"),
            IpProtocol::Udp => write!(f, "UDP (17)"),
            IpProtocol::Other(v) => write!(f, "Protocol ({})", v),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ipv4Header {
    pub version: u8,
    pub ihl: u8, // in 32-bit words
    pub dscp_ecn: u8,
    pub total_length: u16,
    pub identification: u16,
    pub dont_fragment: bool,
    pub more_fragments: bool,
    pub fragment_offset: u16,
    pub ttl: u8,
    pub protocol: IpProtocol,
    pub checksum: u16,
    pub src_ip: Ipv4Address,
    pub dst_ip: Ipv4Address,
}

impl Ipv4Header {
    pub fn header_len_bytes(&self) -> usize {
        (self.ihl as usize) * 4
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ipv4Packet<'a> {
    pub header: Ipv4Header,
    pub payload: &'a [u8],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Ipv4Error {
    PacketTooShort(usize),
    InvalidVersion(u8),
    InvalidIhl(u8),
    TotalLengthMismatch {
        declared: usize,
        available: usize,
    },
    TotalLengthSmallerThanHeader {
        total_length: usize,
        header_length: usize,
    },
    ReservedFragmentFlagSet,
    NonFinalFragmentLengthNotMultipleOfEight {
        payload_length: usize,
    },
    InvalidChecksum {
        computed: u16,
        found: u16,
    },
}

impl fmt::Display for Ipv4Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Ipv4Error::PacketTooShort(len) => {
                write!(f, "IPv4 packet too short ({} bytes, min 20)", len)
            }
            Ipv4Error::InvalidVersion(v) => write!(f, "Invalid IP version: {} (expected 4)", v),
            Ipv4Error::InvalidIhl(ihl) => write!(f, "Invalid IHL: {} (min 5)", ihl),
            Ipv4Error::TotalLengthMismatch {
                declared,
                available,
            } => {
                write!(
                    f,
                    "IPv4 total length {} exceeds available data {}",
                    declared, available
                )
            }
            Ipv4Error::TotalLengthSmallerThanHeader {
                total_length,
                header_length,
            } => {
                write!(
                    f,
                    "IPv4 total length {} is smaller than header length {}",
                    total_length, header_length
                )
            }
            Ipv4Error::ReservedFragmentFlagSet => {
                write!(f, "IPv4 reserved fragmentation flag must be zero")
            }
            Ipv4Error::NonFinalFragmentLengthNotMultipleOfEight { payload_length } => {
                write!(
                    f,
                    "IPv4 non-final fragment payload length {} is not a multiple of 8",
                    payload_length
                )
            }
            Ipv4Error::InvalidChecksum { computed, found } => {
                write!(
                    f,
                    "IPv4 checksum mismatch: computed 0x{:04x}, found 0x{:04x}",
                    computed, found
                )
            }
        }
    }
}

impl std::error::Error for Ipv4Error {}

impl<'a> Ipv4Packet<'a> {
    pub fn parse(data: &'a [u8], check_checksum: bool) -> Result<Self, Ipv4Error> {
        if data.len() < IPV4_MIN_HEADER_LEN {
            return Err(Ipv4Error::PacketTooShort(data.len()));
        }

        let ver_ihl = data[0];
        let version = ver_ihl >> 4;
        let ihl = ver_ihl & 0x0F;

        if version != 4 {
            return Err(Ipv4Error::InvalidVersion(version));
        }

        if ihl < 5 {
            return Err(Ipv4Error::InvalidIhl(ihl));
        }

        let header_len = (ihl as usize) * 4;
        if data.len() < header_len {
            return Err(Ipv4Error::PacketTooShort(data.len()));
        }

        let dscp_ecn = data[1];
        let total_length = u16::from_be_bytes([data[2], data[3]]);
        if (total_length as usize) < header_len {
            return Err(Ipv4Error::TotalLengthSmallerThanHeader {
                total_length: total_length as usize,
                header_length: header_len,
            });
        }
        if (total_length as usize) > data.len() {
            return Err(Ipv4Error::TotalLengthMismatch {
                declared: total_length as usize,
                available: data.len(),
            });
        }

        let identification = u16::from_be_bytes([data[4], data[5]]);
        let flags_frag = u16::from_be_bytes([data[6], data[7]]);
        if (flags_frag & 0x8000) != 0 {
            return Err(Ipv4Error::ReservedFragmentFlagSet);
        }
        let dont_fragment = (flags_frag & 0x4000) != 0;
        let more_fragments = (flags_frag & 0x2000) != 0;
        let fragment_offset = flags_frag & 0x1FFF;
        let payload_length = total_length as usize - header_len;
        if more_fragments && payload_length % 8 != 0 {
            return Err(Ipv4Error::NonFinalFragmentLengthNotMultipleOfEight { payload_length });
        }

        let ttl = data[8];
        let protocol_raw = data[9];
        let protocol = IpProtocol::from_u8(protocol_raw);
        let checksum = u16::from_be_bytes([data[10], data[11]]);

        if check_checksum && !verify_checksum(&data[0..header_len]) {
            let actual = compute_checksum(&data[0..header_len]);
            return Err(Ipv4Error::InvalidChecksum {
                computed: actual,
                found: checksum,
            });
        }

        let mut src = [0u8; 4];
        src.copy_from_slice(&data[12..16]);

        let mut dst = [0u8; 4];
        dst.copy_from_slice(&data[16..20]);

        let end = total_length as usize;
        let payload = &data[header_len..end];

        let header = Ipv4Header {
            version,
            ihl,
            dscp_ecn,
            total_length,
            identification,
            dont_fragment,
            more_fragments,
            fragment_offset,
            ttl,
            protocol,
            checksum,
            src_ip: Ipv4Address(src),
            dst_ip: Ipv4Address(dst),
        };

        Ok(Ipv4Packet { header, payload })
    }

    /// Decrements the TTL of an already-serialized IPv4 datagram while preserving
    /// every other header field, including options and fragmentation metadata.
    /// Returns `Ok(false)` when the packet has no forwardable TTL remaining.
    pub fn decrement_ttl_in_place(data: &mut [u8]) -> Result<bool, Ipv4Error> {
        let (header_len, ttl) = {
            let parsed = Ipv4Packet::parse(data, true)?;
            (parsed.header.header_len_bytes(), parsed.header.ttl)
        };

        if ttl <= 1 {
            return Ok(false);
        }

        data[8] = ttl - 1;
        data[10..12].copy_from_slice(&[0, 0]);
        let checksum = compute_checksum(&data[..header_len]);
        data[10..12].copy_from_slice(&checksum.to_be_bytes());
        Ok(true)
    }

    pub fn serialize(
        src_ip: Ipv4Address,
        dst_ip: Ipv4Address,
        protocol: u8,
        identification: u16,
        ttl: u8,
        payload: &[u8],
    ) -> Vec<u8> {
        let total_length = (IPV4_MIN_HEADER_LEN + payload.len()) as u16;
        let mut buf = Vec::with_capacity(total_length as usize);

        buf.push(0x45); // Version 4, IHL 5
        buf.push(0x00); // DSCP / ECN
        buf.extend_from_slice(&total_length.to_be_bytes());
        buf.extend_from_slice(&identification.to_be_bytes());
        buf.extend_from_slice(&0x4000u16.to_be_bytes()); // DF = 1
        buf.push(ttl);
        buf.push(protocol);
        buf.extend_from_slice(&[0x00, 0x00]); // Checksum placeholder
        buf.extend_from_slice(&src_ip.0);
        buf.extend_from_slice(&dst_ip.0);

        // Compute checksum over the 20-byte header
        let csum = compute_checksum(&buf[0..IPV4_MIN_HEADER_LEN]);
        buf[10..12].copy_from_slice(&csum.to_be_bytes());

        // Append payload
        buf.extend_from_slice(payload);
        buf
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_rejects_total_length_smaller_than_minimum_header() {
        let mut raw = vec![0u8; IPV4_MIN_HEADER_LEN];
        raw[0] = 0x45;
        raw[2..4].copy_from_slice(&19u16.to_be_bytes());

        assert_eq!(
            Ipv4Packet::parse(&raw, false),
            Err(Ipv4Error::TotalLengthSmallerThanHeader {
                total_length: 19,
                header_length: IPV4_MIN_HEADER_LEN,
            })
        );
    }

    #[test]
    fn parse_rejects_total_length_smaller_than_options_header() {
        let mut raw = vec![0u8; 24];
        raw[0] = 0x46;
        raw[2..4].copy_from_slice(&20u16.to_be_bytes());

        assert_eq!(
            Ipv4Packet::parse(&raw, false),
            Err(Ipv4Error::TotalLengthSmallerThanHeader {
                total_length: 20,
                header_length: 24,
            })
        );
    }

    #[test]
    fn parse_accepts_total_length_equal_to_options_header() {
        let mut raw = vec![0u8; 24];
        raw[0] = 0x46;
        raw[2..4].copy_from_slice(&24u16.to_be_bytes());
        raw[8] = 64;
        raw[9] = IP_PROTO_UDP;
        raw[12..16].copy_from_slice(&Ipv4Address::new(192, 0, 2, 1).0);
        raw[16..20].copy_from_slice(&Ipv4Address::new(198, 51, 100, 1).0);
        raw[20..24].copy_from_slice(&[1, 1, 1, 0]);
        let checksum = compute_checksum(&raw[..24]);
        raw[10..12].copy_from_slice(&checksum.to_be_bytes());

        let parsed = Ipv4Packet::parse(&raw, true).unwrap();
        assert_eq!(parsed.header.ihl, 6);
        assert_eq!(parsed.header.total_length, 24);
        assert!(parsed.payload.is_empty());
    }

    #[test]
    fn parse_rejects_reserved_fragment_flag() {
        let mut raw = Ipv4Packet::serialize(
            Ipv4Address::new(192, 0, 2, 1),
            Ipv4Address::new(198, 51, 100, 1),
            IP_PROTO_UDP,
            1,
            64,
            &[],
        );
        raw[6..8].copy_from_slice(&0x8000u16.to_be_bytes());

        assert_eq!(
            Ipv4Packet::parse(&raw, false),
            Err(Ipv4Error::ReservedFragmentFlagSet)
        );
    }

    #[test]
    fn parse_rejects_non_final_fragment_with_unaligned_payload_length() {
        let mut raw = vec![0u8; 30];
        raw[0] = 0x45;
        raw[2..4].copy_from_slice(&30u16.to_be_bytes());
        raw[6..8].copy_from_slice(&0x2000u16.to_be_bytes());

        assert_eq!(
            Ipv4Packet::parse(&raw, false),
            Err(Ipv4Error::NonFinalFragmentLengthNotMultipleOfEight { payload_length: 10 })
        );
    }

    #[test]
    fn parse_accepts_non_final_fragment_with_aligned_payload_length() {
        let mut raw = vec![0u8; 28];
        raw[0] = 0x45;
        raw[2..4].copy_from_slice(&28u16.to_be_bytes());
        raw[6..8].copy_from_slice(&0x2000u16.to_be_bytes());

        let parsed = Ipv4Packet::parse(&raw, false).unwrap();
        assert!(parsed.header.more_fragments);
        assert_eq!(parsed.payload.len(), 8);
    }

    #[test]
    fn test_ipv4_packet_build_and_parse() {
        let src = Ipv4Address::new(192, 168, 1, 100);
        let dst = Ipv4Address::new(8, 8, 8, 8);
        let payload = b"ICMP Echo Payload";

        let raw = Ipv4Packet::serialize(src, dst, IP_PROTO_ICMP, 0x1337, 64, payload);
        assert_eq!(raw.len(), 20 + payload.len());

        let pkt = Ipv4Packet::parse(&raw, true).unwrap();
        assert_eq!(pkt.header.version, 4);
        assert_eq!(pkt.header.ihl, 5);
        assert_eq!(pkt.header.src_ip, src);
        assert_eq!(pkt.header.dst_ip, dst);
        assert_eq!(pkt.header.protocol, IpProtocol::Icmp);
        assert_eq!(pkt.header.ttl, 64);
        assert_eq!(pkt.payload, payload);
    }
}
