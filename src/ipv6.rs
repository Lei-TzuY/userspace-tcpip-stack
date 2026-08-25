//! Layer 3: Internet Protocol Version 6 (IPv6 - RFC 8200, RFC 5952).
//!
//! Provides 128-bit IPv6 addressing with RFC 5952 zero compression formatting,
//! 40-byte fixed header parsing and serialization, and IPv6 pseudo-header checksum computation.

use crate::checksum::compute_checksum;
use std::fmt;
use std::str::FromStr;

pub const IPV6_HEADER_LEN: usize = 40;

pub const NEXT_HEADER_HOP_BY_HOP: u8 = 0;
pub const NEXT_HEADER_TCP: u8 = 6;
pub const NEXT_HEADER_UDP: u8 = 17;
pub const NEXT_HEADER_ROUTING: u8 = 43;
pub const NEXT_HEADER_FRAGMENT: u8 = 44;
pub const NEXT_HEADER_GRE: u8 = 47;
pub const NEXT_HEADER_ICMPV6: u8 = 58;
pub const NEXT_HEADER_NO_NEXT: u8 = 59;
pub const NEXT_HEADER_DEST_OPTS: u8 = 60;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Ipv6Address(pub [u8; 16]);

impl Ipv6Address {
    pub const UNSPECIFIED: Ipv6Address = Ipv6Address([0; 16]);
    pub const LOOPBACK: Ipv6Address = Ipv6Address([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
    pub const LINK_LOCAL_ALL_NODES: Ipv6Address =
        Ipv6Address([0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
    pub const LINK_LOCAL_ALL_ROUTERS: Ipv6Address =
        Ipv6Address([0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);

    pub fn new(words: [u16; 8]) -> Self {
        let mut bytes = [0u8; 16];
        for (i, &w) in words.iter().enumerate() {
            bytes[i * 2] = (w >> 8) as u8;
            bytes[i * 2 + 1] = (w & 0xFF) as u8;
        }
        Ipv6Address(bytes)
    }

    pub fn to_words(&self) -> [u16; 8] {
        let mut words = [0u16; 8];
        for (i, word) in words.iter_mut().enumerate() {
            *word = u16::from_be_bytes([self.0[i * 2], self.0[i * 2 + 1]]);
        }
        words
    }

    /// Returns this address masked to `prefix_len` bits.
    pub fn mask(self, prefix_len: u8) -> Self {
        let prefix_len = prefix_len.min(128);
        let mut bytes = self.0;
        let whole = (prefix_len / 8) as usize;
        let rem = prefix_len % 8;
        if rem != 0 && whole < bytes.len() {
            bytes[whole] &= 0xff << (8 - rem);
        }
        let clear_from = whole + usize::from(rem != 0);
        for byte in &mut bytes[clear_from..] {
            *byte = 0;
        }
        Ipv6Address(bytes)
    }

    pub fn is_unspecified(&self) -> bool {
        *self == Self::UNSPECIFIED
    }

    pub fn is_loopback(&self) -> bool {
        *self == Self::LOOPBACK
    }

    pub fn is_multicast(&self) -> bool {
        self.0[0] == 0xFF
    }

    pub fn is_link_local(&self) -> bool {
        self.0[0] == 0xFE && (self.0[1] & 0xC0) == 0x80
    }

    /// RFC 4291 solicited-node multicast address for this unicast/anycast target.
    pub fn solicited_node_multicast(&self) -> Ipv6Address {
        let mut bytes = [0u8; 16];
        bytes[0] = 0xff;
        bytes[1] = 0x02;
        bytes[11] = 0x01;
        bytes[12] = 0xff;
        bytes[13..16].copy_from_slice(&self.0[13..16]);
        Ipv6Address(bytes)
    }
}

impl fmt::Display for Ipv6Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let words = self.to_words();

        // Find longest sequence of zeros for RFC 5952 compression
        let mut best_start = 0;
        let mut best_len = 0;
        let mut cur_start = 0;
        let mut cur_len = 0;

        for (i, &w) in words.iter().enumerate() {
            if w == 0 {
                if cur_len == 0 {
                    cur_start = i;
                }
                cur_len += 1;
                if cur_len > best_len {
                    best_len = cur_len;
                    best_start = cur_start;
                }
            } else {
                cur_len = 0;
            }
        }

        if best_len <= 1 {
            // No compression
            let formatted: Vec<String> = words.iter().map(|w| format!("{:x}", w)).collect();
            write!(f, "{}", formatted.join(":"))
        } else if best_len == 8 {
            write!(f, "::")
        } else {
            let mut parts = Vec::new();
            let mut i = 0;
            while i < 8 {
                if i == best_start {
                    if best_start == 0 {
                        parts.push("".to_string());
                    }
                    parts.push("".to_string());
                    i += best_len;
                    if i == 8 {
                        parts.push("".to_string());
                    }
                } else {
                    parts.push(format!("{:x}", words[i]));
                    i += 1;
                }
            }
            write!(f, "{}", parts.join(":"))
        }
    }
}

impl FromStr for Ipv6Address {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s == "::" {
            return Ok(Ipv6Address::UNSPECIFIED);
        }

        let parts: Vec<&str> = s.split("::").collect();
        if parts.len() > 2 {
            return Err(());
        }

        let mut words = [0u16; 8];

        if parts.len() == 1 {
            let segs: Vec<&str> = parts[0].split(':').collect();
            if segs.len() != 8 {
                return Err(());
            }
            for (i, seg) in segs.iter().enumerate() {
                words[i] = u16::from_str_radix(seg, 16).map_err(|_| ())?;
            }
        } else {
            let left_segs: Vec<&str> = if parts[0].is_empty() {
                Vec::new()
            } else {
                parts[0].split(':').collect()
            };
            let right_segs: Vec<&str> = if parts[1].is_empty() {
                Vec::new()
            } else {
                parts[1].split(':').collect()
            };

            if left_segs.len() + right_segs.len() >= 8 {
                return Err(());
            }

            for (i, seg) in left_segs.iter().enumerate() {
                words[i] = u16::from_str_radix(seg, 16).map_err(|_| ())?;
            }

            let right_start = 8 - right_segs.len();
            for (i, seg) in right_segs.iter().enumerate() {
                words[right_start + i] = u16::from_str_radix(seg, 16).map_err(|_| ())?;
            }
        }

        Ok(Ipv6Address::new(words))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ipv6Header {
    pub version: u8,
    pub traffic_class: u8,
    pub flow_label: u32,
    pub payload_length: u16,
    pub next_header: u8,
    pub hop_limit: u8,
    pub src_ip: Ipv6Address,
    pub dst_ip: Ipv6Address,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ipv6Packet<'a> {
    pub header: Ipv6Header,
    pub payload: &'a [u8],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Ipv6Error {
    PacketTooShort(usize),
    InvalidVersion(u8),
    PayloadLengthMismatch {
        header_len: usize,
        actual_len: usize,
    },
}

impl fmt::Display for Ipv6Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Ipv6Error::PacketTooShort(len) => {
                write!(f, "IPv6 packet too short ({} bytes, min 40)", len)
            }
            Ipv6Error::InvalidVersion(v) => {
                write!(f, "Invalid IP version: expected 6, found {}", v)
            }
            Ipv6Error::PayloadLengthMismatch {
                header_len,
                actual_len,
            } => {
                write!(
                    f,
                    "IPv6 payload length mismatch: header specifies {}, found {}",
                    header_len, actual_len
                )
            }
        }
    }
}

impl std::error::Error for Ipv6Error {}

impl<'a> Ipv6Packet<'a> {
    pub fn parse(data: &'a [u8]) -> Result<Self, Ipv6Error> {
        if data.len() < IPV6_HEADER_LEN {
            return Err(Ipv6Error::PacketTooShort(data.len()));
        }

        let v_tc_fl = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
        let version = ((v_tc_fl >> 28) & 0x0F) as u8;
        if version != 6 {
            return Err(Ipv6Error::InvalidVersion(version));
        }

        let traffic_class = ((v_tc_fl >> 20) & 0xFF) as u8;
        let flow_label = v_tc_fl & 0x000F_FFFF;

        let payload_length = u16::from_be_bytes([data[4], data[5]]);
        let next_header = data[6];
        let hop_limit = data[7];

        let mut src_bytes = [0u8; 16];
        src_bytes.copy_from_slice(&data[8..24]);
        let src_ip = Ipv6Address(src_bytes);

        let mut dst_bytes = [0u8; 16];
        dst_bytes.copy_from_slice(&data[24..40]);
        let dst_ip = Ipv6Address(dst_bytes);

        let available_payload = data.len() - IPV6_HEADER_LEN;
        if available_payload < payload_length as usize {
            return Err(Ipv6Error::PayloadLengthMismatch {
                header_len: payload_length as usize,
                actual_len: available_payload,
            });
        }

        let payload = &data[IPV6_HEADER_LEN..IPV6_HEADER_LEN + payload_length as usize];

        Ok(Ipv6Packet {
            header: Ipv6Header {
                version,
                traffic_class,
                flow_label,
                payload_length,
                next_header,
                hop_limit,
                src_ip,
                dst_ip,
            },
            payload,
        })
    }

    pub fn serialize(
        src_ip: Ipv6Address,
        dst_ip: Ipv6Address,
        next_header: u8,
        hop_limit: u8,
        payload: &[u8],
    ) -> Vec<u8> {
        let total_len = IPV6_HEADER_LEN + payload.len();
        let mut buf = Vec::with_capacity(total_len);

        // Version = 6, Traffic Class = 0, Flow Label = 0 -> 0x60000000
        buf.extend_from_slice(&0x6000_0000u32.to_be_bytes());
        buf.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        buf.push(next_header);
        buf.push(hop_limit);
        buf.extend_from_slice(&src_ip.0);
        buf.extend_from_slice(&dst_ip.0);
        buf.extend_from_slice(payload);

        buf
    }
}

/// Computes the IPv6 Transport Layer Pseudo-Header Checksum (RFC 8200 Section 8.1).
pub fn compute_ipv6_transport_checksum(
    src_ip: Ipv6Address,
    dst_ip: Ipv6Address,
    next_header: u8,
    payload: &[u8],
) -> u16 {
    let mut pseudo_header = Vec::with_capacity(40 + payload.len());
    pseudo_header.extend_from_slice(&src_ip.0);
    pseudo_header.extend_from_slice(&dst_ip.0);
    pseudo_header.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    pseudo_header.extend_from_slice(&[0, 0, 0, next_header]);
    pseudo_header.extend_from_slice(payload);

    compute_checksum(&pseudo_header)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ipv6_address_parsing_and_formatting() {
        let loopback = Ipv6Address::from_str("::1").unwrap();
        assert_eq!(loopback, Ipv6Address::LOOPBACK);
        assert_eq!(loopback.to_string(), "::1");

        let addr = Ipv6Address::from_str("2001:db8::1").unwrap();
        assert_eq!(addr.to_string(), "2001:db8::1");

        let link_local = Ipv6Address::from_str("fe80::1").unwrap();
        assert!(link_local.is_link_local());
        assert_eq!(link_local.to_string(), "fe80::1");
    }

    #[test]
    fn test_ipv6_packet_build_and_parse() {
        let src = Ipv6Address::from_str("2001:db8::1").unwrap();
        let dst = Ipv6Address::from_str("2001:db8::2").unwrap();
        let payload = b"Hello IPv6 World!";

        let raw = Ipv6Packet::serialize(src, dst, NEXT_HEADER_UDP, 64, payload);
        let parsed = Ipv6Packet::parse(&raw).unwrap();

        assert_eq!(parsed.header.version, 6);
        assert_eq!(parsed.header.src_ip, src);
        assert_eq!(parsed.header.dst_ip, dst);
        assert_eq!(parsed.header.next_header, NEXT_HEADER_UDP);
        assert_eq!(parsed.header.hop_limit, 64);
        assert_eq!(parsed.payload, payload);
    }
}
