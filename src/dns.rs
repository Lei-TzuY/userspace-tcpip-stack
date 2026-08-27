//! Application Layer: Domain Name System (DNS - RFC 1035).
//!
//! Handles encoding and decoding DNS queries and Type-A IPv4 address responses over UDP port 53.

use crate::ipv4::Ipv4Address;
use std::fmt;

pub const DNS_PORT: u16 = 53;
pub const DNS_TYPE_A: u16 = 1;
pub const DNS_CLASS_IN: u16 = 1;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsQuestion {
    pub name: String,
    pub qtype: u16,
    pub qclass: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsAnswer {
    pub name: String,
    pub rtype: u16,
    pub rclass: u16,
    pub ttl: u32,
    pub ip: Ipv4Address,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsMessage {
    pub id: u16,
    pub is_response: bool,
    pub recursion_desired: bool,
    pub recursion_available: bool,
    pub rcode: u8,
    pub questions: Vec<DnsQuestion>,
    pub answers: Vec<DnsAnswer>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsError {
    PacketTooShort(usize),
    InvalidLabel(String),
    InvalidCompressionPointer(usize),
    CompressionLoop,
    ReservedLabelType(u8),
    NameTooLong,
    UnsupportedFormat,
}

impl fmt::Display for DnsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DnsError::PacketTooShort(len) => {
                write!(f, "DNS packet too short ({} bytes, min 12)", len)
            }
            DnsError::InvalidLabel(l) => write!(f, "Invalid DNS label format: {}", l),
            DnsError::InvalidCompressionPointer(offset) => {
                write!(
                    f,
                    "DNS compression pointer {} is outside the packet",
                    offset
                )
            }
            DnsError::CompressionLoop => write!(f, "DNS compression pointer loop detected"),
            DnsError::ReservedLabelType(value) => {
                write!(f, "Reserved DNS label type 0x{:02x}", value)
            }
            DnsError::NameTooLong => write!(f, "Expanded DNS name exceeds 255 octets"),
            DnsError::UnsupportedFormat => write!(f, "Unsupported DNS record format"),
        }
    }
}

impl std::error::Error for DnsError {}

impl DnsMessage {
    pub fn build_query(id: u16, hostname: &str) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&id.to_be_bytes());
        // Flags: Standard query, Recursion Desired (RD = 1) -> 0x0100
        buf.extend_from_slice(&0x0100u16.to_be_bytes());
        buf.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT = 1
        buf.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT = 0
        buf.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT = 0
        buf.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT = 0

        // Encode QNAME: "www.example.com" -> 3www7example3com0
        encode_qname(hostname, &mut buf);

        // QTYPE = A (1), QCLASS = IN (1)
        buf.extend_from_slice(&DNS_TYPE_A.to_be_bytes());
        buf.extend_from_slice(&DNS_CLASS_IN.to_be_bytes());

        buf
    }

    pub fn build_response(id: u16, hostname: &str, ip: Ipv4Address, ttl: u32) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&id.to_be_bytes());
        // Flags: QR=1 (Response), AA=1 (Authoritative), RA=1 -> 0x8180
        buf.extend_from_slice(&0x8180u16.to_be_bytes());
        buf.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT = 1
        buf.extend_from_slice(&1u16.to_be_bytes()); // ANCOUNT = 1
        buf.extend_from_slice(&0u16.to_be_bytes());
        buf.extend_from_slice(&0u16.to_be_bytes());

        // Question section
        let qname_start = buf.len();
        encode_qname(hostname, &mut buf);
        buf.extend_from_slice(&DNS_TYPE_A.to_be_bytes());
        buf.extend_from_slice(&DNS_CLASS_IN.to_be_bytes());

        // Answer section: Name pointer to QNAME (0xC000 | qname_start)
        let ptr = 0xC000u16 | (qname_start as u16);
        buf.extend_from_slice(&ptr.to_be_bytes());
        buf.extend_from_slice(&DNS_TYPE_A.to_be_bytes());
        buf.extend_from_slice(&DNS_CLASS_IN.to_be_bytes());
        buf.extend_from_slice(&ttl.to_be_bytes());
        buf.extend_from_slice(&4u16.to_be_bytes()); // RDLENGTH = 4
        buf.extend_from_slice(&ip.0);

        buf
    }

    pub fn parse(data: &[u8]) -> Result<Self, DnsError> {
        if data.len() < 12 {
            return Err(DnsError::PacketTooShort(data.len()));
        }

        let id = u16::from_be_bytes([data[0], data[1]]);
        let flags = u16::from_be_bytes([data[2], data[3]]);
        let is_response = (flags & 0x8000) != 0;
        let recursion_desired = (flags & 0x0100) != 0;
        let recursion_available = (flags & 0x0080) != 0;
        let rcode = (flags & 0x000F) as u8;

        let qdcount = u16::from_be_bytes([data[4], data[5]]);
        let ancount = u16::from_be_bytes([data[6], data[7]]);

        let mut offset = 12;
        let mut questions = Vec::new();

        for _ in 0..qdcount {
            let (name, next_off) = decode_qname(data, offset)?;
            offset = next_off;
            if offset + 4 > data.len() {
                return Err(DnsError::PacketTooShort(data.len()));
            }
            let qtype = u16::from_be_bytes([data[offset], data[offset + 1]]);
            let qclass = u16::from_be_bytes([data[offset + 2], data[offset + 3]]);
            offset += 4;
            questions.push(DnsQuestion {
                name,
                qtype,
                qclass,
            });
        }

        let mut answers = Vec::new();
        for _ in 0..ancount {
            let (name, next_off) = decode_qname(data, offset)?;
            offset = next_off;
            if offset + 10 > data.len() {
                return Err(DnsError::PacketTooShort(data.len()));
            }
            let rtype = u16::from_be_bytes([data[offset], data[offset + 1]]);
            let rclass = u16::from_be_bytes([data[offset + 2], data[offset + 3]]);
            let ttl = u32::from_be_bytes([
                data[offset + 4],
                data[offset + 5],
                data[offset + 6],
                data[offset + 7],
            ]);
            let rdlength = u16::from_be_bytes([data[offset + 8], data[offset + 9]]) as usize;
            offset += 10;

            if offset + rdlength > data.len() {
                return Err(DnsError::PacketTooShort(data.len()));
            }

            if rtype == DNS_TYPE_A && rdlength == 4 {
                let mut ip_bytes = [0u8; 4];
                ip_bytes.copy_from_slice(&data[offset..offset + 4]);
                answers.push(DnsAnswer {
                    name,
                    rtype,
                    rclass,
                    ttl,
                    ip: Ipv4Address(ip_bytes),
                });
            }
            offset += rdlength;
        }

        Ok(DnsMessage {
            id,
            is_response,
            recursion_desired,
            recursion_available,
            rcode,
            questions,
            answers,
        })
    }
}

fn encode_qname(hostname: &str, buf: &mut Vec<u8>) {
    for label in hostname.split('.') {
        if !label.is_empty() {
            buf.push(label.len() as u8);
            buf.extend_from_slice(label.as_bytes());
        }
    }
    buf.push(0x00);
}

fn decode_qname(data: &[u8], mut offset: usize) -> Result<(String, usize), DnsError> {
    let mut labels = Vec::new();
    let mut jumped = false;
    let mut return_offset = offset;
    let mut visited_offsets = std::collections::HashSet::new();
    // RFC 1035 section 2.3.4 limits a complete domain name, including label
    // length octets and the root terminator, to 255 octets.
    let mut expanded_wire_len = 1usize;

    loop {
        if offset >= data.len() {
            return Err(DnsError::PacketTooShort(data.len()));
        }
        if !visited_offsets.insert(offset) {
            return Err(DnsError::CompressionLoop);
        }

        let len = data[offset];
        if len == 0 {
            if !jumped {
                return_offset = offset + 1;
            }
            break;
        }

        match len & 0xC0 {
            // Pointer compression: 0b11xxxxxx
            0xC0 => {
                if offset + 1 >= data.len() {
                    return Err(DnsError::PacketTooShort(data.len()));
                }
                let ptr_offset = (((len & 0x3F) as usize) << 8) | (data[offset + 1] as usize);
                if ptr_offset >= data.len() {
                    return Err(DnsError::InvalidCompressionPointer(ptr_offset));
                }
                if !jumped {
                    return_offset = offset + 2;
                    jumped = true;
                }
                offset = ptr_offset;
                continue;
            }
            // Ordinary RFC 1035 label. The top two bits must be zero, which
            // also caps the label payload at 63 octets.
            0x00 => {}
            reserved => return Err(DnsError::ReservedLabelType(reserved)),
        }

        let label_len = len as usize;
        expanded_wire_len = expanded_wire_len
            .checked_add(1 + label_len)
            .ok_or(DnsError::NameTooLong)?;
        if expanded_wire_len > 255 {
            return Err(DnsError::NameTooLong);
        }

        offset += 1;
        let end = offset + label_len;
        if end > data.len() {
            return Err(DnsError::PacketTooShort(data.len()));
        }

        let label = String::from_utf8_lossy(&data[offset..end]).to_string();
        labels.push(label);
        offset = end;
    }

    Ok((labels.join("."), return_offset))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn query_header() -> Vec<u8> {
        let mut raw = vec![0u8; 12];
        raw[4..6].copy_from_slice(&1u16.to_be_bytes());
        raw
    }

    #[test]
    fn rejects_self_referential_compression_pointer() {
        let mut raw = query_header();
        raw.extend_from_slice(&[0xc0, 0x0c]);
        raw.extend_from_slice(&DNS_TYPE_A.to_be_bytes());
        raw.extend_from_slice(&DNS_CLASS_IN.to_be_bytes());

        assert_eq!(DnsMessage::parse(&raw), Err(DnsError::CompressionLoop));
    }

    #[test]
    fn rejects_multi_pointer_compression_cycle() {
        let mut raw = query_header();
        raw.extend_from_slice(&[0xc0, 0x0e, 0xc0, 0x0c]);
        raw.extend_from_slice(&DNS_TYPE_A.to_be_bytes());
        raw.extend_from_slice(&DNS_CLASS_IN.to_be_bytes());

        assert_eq!(DnsMessage::parse(&raw), Err(DnsError::CompressionLoop));
    }

    #[test]
    fn rejects_compression_pointer_outside_packet() {
        let mut raw = query_header();
        raw.extend_from_slice(&[0xc0, 0xff]);
        raw.extend_from_slice(&DNS_TYPE_A.to_be_bytes());
        raw.extend_from_slice(&DNS_CLASS_IN.to_be_bytes());

        assert_eq!(
            DnsMessage::parse(&raw),
            Err(DnsError::InvalidCompressionPointer(255))
        );
    }

    #[test]
    fn rejects_reserved_dns_label_type() {
        let mut raw = query_header();
        raw.push(0x40);
        raw.extend_from_slice(&[0u8; 64]);
        raw.push(0);
        raw.extend_from_slice(&DNS_TYPE_A.to_be_bytes());
        raw.extend_from_slice(&DNS_CLASS_IN.to_be_bytes());

        assert_eq!(
            DnsMessage::parse(&raw),
            Err(DnsError::ReservedLabelType(0x40))
        );
    }

    fn query_with_label_lengths(lengths: &[usize]) -> Vec<u8> {
        let mut raw = query_header();
        for &len in lengths {
            raw.push(len as u8);
            raw.extend(std::iter::repeat_n(b'a', len));
        }
        raw.push(0);
        raw.extend_from_slice(&DNS_TYPE_A.to_be_bytes());
        raw.extend_from_slice(&DNS_CLASS_IN.to_be_bytes());
        raw
    }

    #[test]
    fn rejects_expanded_name_over_255_octets() {
        let raw = query_with_label_lengths(&[63, 63, 63, 62]);
        assert_eq!(DnsMessage::parse(&raw), Err(DnsError::NameTooLong));
    }

    #[test]
    fn accepts_expanded_name_at_255_octet_boundary() {
        let raw = query_with_label_lengths(&[63, 63, 63, 61]);
        let parsed = DnsMessage::parse(&raw).unwrap();
        assert_eq!(parsed.questions.len(), 1);
        assert_eq!(
            parsed.questions[0].name.len(),
            63 + 1 + 63 + 1 + 63 + 1 + 61
        );
    }

    #[test]
    fn test_dns_query_and_response_roundtrip() {
        let hostname = "toy-tcpip.org";
        let resolved_ip = Ipv4Address::new(192, 168, 1, 10);
        let id = 0xbeef;

        // 1. Build Query
        let query_bytes = DnsMessage::build_query(id, hostname);
        let query = DnsMessage::parse(&query_bytes).unwrap();
        assert_eq!(query.id, id);
        assert!(!query.is_response);
        assert_eq!(query.questions.len(), 1);
        assert_eq!(query.questions[0].name, hostname);

        // 2. Build Response
        let resp_bytes = DnsMessage::build_response(id, hostname, resolved_ip, 300);
        let resp = DnsMessage::parse(&resp_bytes).unwrap();
        assert_eq!(resp.id, id);
        assert!(resp.is_response);
        assert_eq!(resp.answers.len(), 1);
        assert_eq!(resp.answers[0].ip, resolved_ip);
        assert_eq!(resp.answers[0].ttl, 300);
    }
}
