//! Application Layer: Domain Name System (DNS - RFC 1035, RFC 3596, RFC 2782, RFC 6891, RFC 2308).
//!
//! Handles encoding and decoding DNS queries and responses for multiple record types (A, AAAA,
//! CNAME, PTR, TXT, MX, NS, SRV, SOA, EDNS0 OPT) over UDP port 53, with label compression and caching.

use crate::ipv4::Ipv4Address;
use crate::ipv6::Ipv6Address;
use std::collections::HashMap;
use std::fmt;

pub const DNS_PORT: u16 = 53;

// DNS Record Types
pub const DNS_TYPE_A: u16 = 1;
pub const DNS_TYPE_NS: u16 = 2;
pub const DNS_TYPE_CNAME: u16 = 5;
pub const DNS_TYPE_SOA: u16 = 6;
pub const DNS_TYPE_PTR: u16 = 12;
pub const DNS_TYPE_MX: u16 = 15;
pub const DNS_TYPE_TXT: u16 = 16;
pub const DNS_TYPE_AAAA: u16 = 28;
pub const DNS_TYPE_SRV: u16 = 33;
pub const DNS_TYPE_OPT: u16 = 41;
pub const DNS_TYPE_ANY: u16 = 255;

// DNS Classes
pub const DNS_CLASS_IN: u16 = 1;
pub const DNS_CLASS_ANY: u16 = 255;

// DNS Response Codes (RCODE)
pub const DNS_RCODE_NOERROR: u8 = 0;
pub const DNS_RCODE_FORMERR: u8 = 1;
pub const DNS_RCODE_SERVFAIL: u8 = 2;
pub const DNS_RCODE_NXDOMAIN: u8 = 3;
pub const DNS_RCODE_NOTIMP: u8 = 4;
pub const DNS_RCODE_REFUSED: u8 = 5;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsQuestion {
    pub name: String,
    pub qtype: u16,
    pub qclass: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsRecordData {
    A(Ipv4Address),
    Aaaa(Ipv6Address),
    Cname(String),
    Ptr(String),
    Txt(Vec<String>),
    Mx {
        preference: u16,
        exchange: String,
    },
    Ns(String),
    Srv {
        priority: u16,
        weight: u16,
        port: u16,
        target: String,
    },
    Soa {
        mname: String,
        rname: String,
        serial: u32,
        refresh: u32,
        retry: u32,
        expire: u32,
        minimum: u32,
    },
    Opt {
        udp_payload_size: u16,
        ext_rcode: u8,
        version: u8,
        flags: u16,
        data: Vec<u8>,
    },
    Raw(Vec<u8>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsAnswer {
    pub name: String,
    pub rtype: u16,
    pub rclass: u16,
    pub ttl: u32,
    pub ip: Ipv4Address,
    pub data: DnsRecordData,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsMessage {
    pub id: u16,
    pub is_response: bool,
    pub recursion_desired: bool,
    pub recursion_available: bool,
    pub authoritative: bool,
    pub truncated: bool,
    pub rcode: u8,
    pub questions: Vec<DnsQuestion>,
    pub answers: Vec<DnsAnswer>,
    pub authorities: Vec<DnsAnswer>,
    pub additionals: Vec<DnsAnswer>,
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
    /// Builds a standard IPv4 (Type A) DNS query for a given hostname.
    pub fn build_query(id: u16, hostname: &str) -> Vec<u8> {
        Self::build_typed_query(id, hostname, DNS_TYPE_A)
    }

    /// Builds a typed DNS query for a given hostname and QTYPE.
    pub fn build_typed_query(id: u16, hostname: &str, qtype: u16) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&id.to_be_bytes());
        // Flags: Standard query, Recursion Desired (RD = 1) -> 0x0100
        buf.extend_from_slice(&0x0100u16.to_be_bytes());
        buf.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT = 1
        buf.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT = 0
        buf.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT = 0
        buf.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT = 0

        encode_qname(hostname, &mut buf);

        buf.extend_from_slice(&qtype.to_be_bytes());
        buf.extend_from_slice(&DNS_CLASS_IN.to_be_bytes());

        buf
    }

    /// Builds an IPv6 (Type AAAA) DNS query.
    pub fn build_aaaa_query(id: u16, hostname: &str) -> Vec<u8> {
        Self::build_typed_query(id, hostname, DNS_TYPE_AAAA)
    }

    /// Converts an IPv4 address to its reverse DNS in-addr.arpa pointer query.
    pub fn build_ptr_query_v4(id: u16, ip: Ipv4Address) -> Vec<u8> {
        let octets = ip.0;
        let ptr_name = format!(
            "{}.{}.{}.{}.in-addr.arpa",
            octets[3], octets[2], octets[1], octets[0]
        );
        Self::build_typed_query(id, &ptr_name, DNS_TYPE_PTR)
    }

    /// Converts an IPv6 address to its reverse DNS ip6.arpa pointer query.
    pub fn build_ptr_query_v6(id: u16, ip: Ipv6Address) -> Vec<u8> {
        let bytes = ip.0;
        let mut nibbles = Vec::with_capacity(64);
        for b in bytes.iter().rev() {
            let low = b & 0x0f;
            let high = (b >> 4) & 0x0f;
            nibbles.push(format!("{:x}", low));
            nibbles.push(format!("{:x}", high));
        }
        let ptr_name = format!("{}.ip6.arpa", nibbles.join("."));
        Self::build_typed_query(id, &ptr_name, DNS_TYPE_PTR)
    }

    /// Builds a single IPv4 (Type A) response message.
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

    /// Builds a single IPv6 (Type AAAA) response message.
    pub fn build_aaaa_response(id: u16, hostname: &str, ip: Ipv6Address, ttl: u32) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&id.to_be_bytes());
        buf.extend_from_slice(&0x8180u16.to_be_bytes());
        buf.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT = 1
        buf.extend_from_slice(&1u16.to_be_bytes()); // ANCOUNT = 1
        buf.extend_from_slice(&0u16.to_be_bytes());
        buf.extend_from_slice(&0u16.to_be_bytes());

        let qname_start = buf.len();
        encode_qname(hostname, &mut buf);
        buf.extend_from_slice(&DNS_TYPE_AAAA.to_be_bytes());
        buf.extend_from_slice(&DNS_CLASS_IN.to_be_bytes());

        let ptr = 0xC000u16 | (qname_start as u16);
        buf.extend_from_slice(&ptr.to_be_bytes());
        buf.extend_from_slice(&DNS_TYPE_AAAA.to_be_bytes());
        buf.extend_from_slice(&DNS_CLASS_IN.to_be_bytes());
        buf.extend_from_slice(&ttl.to_be_bytes());
        buf.extend_from_slice(&16u16.to_be_bytes()); // RDLENGTH = 16
        buf.extend_from_slice(&ip.0);

        buf
    }

    /// Builds a Canonical Name (CNAME) response message.
    pub fn build_cname_response(id: u16, hostname: &str, target: &str, ttl: u32) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&id.to_be_bytes());
        buf.extend_from_slice(&0x8180u16.to_be_bytes());
        buf.extend_from_slice(&1u16.to_be_bytes());
        buf.extend_from_slice(&1u16.to_be_bytes());
        buf.extend_from_slice(&0u16.to_be_bytes());
        buf.extend_from_slice(&0u16.to_be_bytes());

        let qname_start = buf.len();
        encode_qname(hostname, &mut buf);
        buf.extend_from_slice(&DNS_TYPE_CNAME.to_be_bytes());
        buf.extend_from_slice(&DNS_CLASS_IN.to_be_bytes());

        let ptr = 0xC000u16 | (qname_start as u16);
        buf.extend_from_slice(&ptr.to_be_bytes());
        buf.extend_from_slice(&DNS_TYPE_CNAME.to_be_bytes());
        buf.extend_from_slice(&DNS_CLASS_IN.to_be_bytes());
        buf.extend_from_slice(&ttl.to_be_bytes());

        let mut rdata = Vec::new();
        encode_qname(target, &mut rdata);
        buf.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        buf.extend_from_slice(&rdata);

        buf
    }

    /// Builds a Pointer (PTR) reverse DNS response message.
    pub fn build_ptr_response(id: u16, ptr_name: &str, target: &str, ttl: u32) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&id.to_be_bytes());
        buf.extend_from_slice(&0x8180u16.to_be_bytes());
        buf.extend_from_slice(&1u16.to_be_bytes());
        buf.extend_from_slice(&1u16.to_be_bytes());
        buf.extend_from_slice(&0u16.to_be_bytes());
        buf.extend_from_slice(&0u16.to_be_bytes());

        let qname_start = buf.len();
        encode_qname(ptr_name, &mut buf);
        buf.extend_from_slice(&DNS_TYPE_PTR.to_be_bytes());
        buf.extend_from_slice(&DNS_CLASS_IN.to_be_bytes());

        let ptr = 0xC000u16 | (qname_start as u16);
        buf.extend_from_slice(&ptr.to_be_bytes());
        buf.extend_from_slice(&DNS_TYPE_PTR.to_be_bytes());
        buf.extend_from_slice(&DNS_CLASS_IN.to_be_bytes());
        buf.extend_from_slice(&ttl.to_be_bytes());

        let mut rdata = Vec::new();
        encode_qname(target, &mut rdata);
        buf.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        buf.extend_from_slice(&rdata);

        buf
    }

    /// Builds a Text (TXT) response message.
    pub fn build_txt_response(id: u16, hostname: &str, texts: &[&str], ttl: u32) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&id.to_be_bytes());
        buf.extend_from_slice(&0x8180u16.to_be_bytes());
        buf.extend_from_slice(&1u16.to_be_bytes());
        buf.extend_from_slice(&1u16.to_be_bytes());
        buf.extend_from_slice(&0u16.to_be_bytes());
        buf.extend_from_slice(&0u16.to_be_bytes());

        let qname_start = buf.len();
        encode_qname(hostname, &mut buf);
        buf.extend_from_slice(&DNS_TYPE_TXT.to_be_bytes());
        buf.extend_from_slice(&DNS_CLASS_IN.to_be_bytes());

        let ptr = 0xC000u16 | (qname_start as u16);
        buf.extend_from_slice(&ptr.to_be_bytes());
        buf.extend_from_slice(&DNS_TYPE_TXT.to_be_bytes());
        buf.extend_from_slice(&DNS_CLASS_IN.to_be_bytes());
        buf.extend_from_slice(&ttl.to_be_bytes());

        let mut rdata = Vec::new();
        for txt in texts {
            let bytes = txt.as_bytes();
            let len = bytes.len().min(255) as u8;
            rdata.push(len);
            rdata.extend_from_slice(&bytes[..len as usize]);
        }
        buf.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        buf.extend_from_slice(&rdata);

        buf
    }

    /// Builds a Mail Exchange (MX) response message.
    pub fn build_mx_response(
        id: u16,
        hostname: &str,
        preference: u16,
        exchange: &str,
        ttl: u32,
    ) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&id.to_be_bytes());
        buf.extend_from_slice(&0x8180u16.to_be_bytes());
        buf.extend_from_slice(&1u16.to_be_bytes());
        buf.extend_from_slice(&1u16.to_be_bytes());
        buf.extend_from_slice(&0u16.to_be_bytes());
        buf.extend_from_slice(&0u16.to_be_bytes());

        let qname_start = buf.len();
        encode_qname(hostname, &mut buf);
        buf.extend_from_slice(&DNS_TYPE_MX.to_be_bytes());
        buf.extend_from_slice(&DNS_CLASS_IN.to_be_bytes());

        let ptr = 0xC000u16 | (qname_start as u16);
        buf.extend_from_slice(&ptr.to_be_bytes());
        buf.extend_from_slice(&DNS_TYPE_MX.to_be_bytes());
        buf.extend_from_slice(&DNS_CLASS_IN.to_be_bytes());
        buf.extend_from_slice(&ttl.to_be_bytes());

        let mut rdata = Vec::new();
        rdata.extend_from_slice(&preference.to_be_bytes());
        encode_qname(exchange, &mut rdata);
        buf.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        buf.extend_from_slice(&rdata);

        buf
    }

    /// Builds a Service (SRV - RFC 2782) response message.
    pub fn build_srv_response(
        id: u16,
        hostname: &str,
        priority: u16,
        weight: u16,
        port: u16,
        target: &str,
        ttl: u32,
    ) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&id.to_be_bytes());
        buf.extend_from_slice(&0x8180u16.to_be_bytes());
        buf.extend_from_slice(&1u16.to_be_bytes());
        buf.extend_from_slice(&1u16.to_be_bytes());
        buf.extend_from_slice(&0u16.to_be_bytes());
        buf.extend_from_slice(&0u16.to_be_bytes());

        let qname_start = buf.len();
        encode_qname(hostname, &mut buf);
        buf.extend_from_slice(&DNS_TYPE_SRV.to_be_bytes());
        buf.extend_from_slice(&DNS_CLASS_IN.to_be_bytes());

        let ptr = 0xC000u16 | (qname_start as u16);
        buf.extend_from_slice(&ptr.to_be_bytes());
        buf.extend_from_slice(&DNS_TYPE_SRV.to_be_bytes());
        buf.extend_from_slice(&DNS_CLASS_IN.to_be_bytes());
        buf.extend_from_slice(&ttl.to_be_bytes());

        let mut rdata = Vec::new();
        rdata.extend_from_slice(&priority.to_be_bytes());
        rdata.extend_from_slice(&weight.to_be_bytes());
        rdata.extend_from_slice(&port.to_be_bytes());
        encode_qname(target, &mut rdata);
        buf.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        buf.extend_from_slice(&rdata);

        buf
    }

    /// Builds an authoritative NXDOMAIN (Non-Existent Domain) response.
    pub fn build_nxdomain_response(id: u16, hostname: &str, qtype: u16) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&id.to_be_bytes());
        // Flags: QR=1, AA=1, RA=1, RCODE=3 (NXDOMAIN) -> 0x8183
        buf.extend_from_slice(&0x8183u16.to_be_bytes());
        buf.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT = 1
        buf.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT = 0
        buf.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT = 0
        buf.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT = 0

        encode_qname(hostname, &mut buf);
        buf.extend_from_slice(&qtype.to_be_bytes());
        buf.extend_from_slice(&DNS_CLASS_IN.to_be_bytes());

        buf
    }

    /// Parses a complete DNS wire-format payload.
    pub fn parse(data: &[u8]) -> Result<Self, DnsError> {
        if data.len() < 12 {
            return Err(DnsError::PacketTooShort(data.len()));
        }

        let id = u16::from_be_bytes([data[0], data[1]]);
        let flags = u16::from_be_bytes([data[2], data[3]]);
        let is_response = (flags & 0x8000) != 0;
        let authoritative = (flags & 0x0400) != 0;
        let truncated = (flags & 0x0200) != 0;
        let recursion_desired = (flags & 0x0100) != 0;
        let recursion_available = (flags & 0x0080) != 0;
        let rcode = (flags & 0x000F) as u8;

        let qdcount = u16::from_be_bytes([data[4], data[5]]);
        let ancount = u16::from_be_bytes([data[6], data[7]]);
        let nscount = u16::from_be_bytes([data[8], data[9]]);
        let arcount = u16::from_be_bytes([data[10], data[11]]);

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
            let (record, next_off) = parse_resource_record(data, offset)?;
            offset = next_off;
            answers.push(record);
        }

        let mut authorities = Vec::new();
        for _ in 0..nscount {
            let (record, next_off) = parse_resource_record(data, offset)?;
            offset = next_off;
            authorities.push(record);
        }

        let mut additionals = Vec::new();
        for _ in 0..arcount {
            let (record, next_off) = parse_resource_record(data, offset)?;
            offset = next_off;
            additionals.push(record);
        }

        Ok(DnsMessage {
            id,
            is_response,
            recursion_desired,
            recursion_available,
            authoritative,
            truncated,
            rcode,
            questions,
            answers,
            authorities,
            additionals,
        })
    }
}

fn parse_resource_record(data: &[u8], offset: usize) -> Result<(DnsAnswer, usize), DnsError> {
    let (name, mut curr_off) = decode_qname(data, offset)?;
    if curr_off + 10 > data.len() {
        return Err(DnsError::PacketTooShort(data.len()));
    }

    let rtype = u16::from_be_bytes([data[curr_off], data[curr_off + 1]]);
    let rclass = u16::from_be_bytes([data[curr_off + 2], data[curr_off + 3]]);
    let ttl = u32::from_be_bytes([
        data[curr_off + 4],
        data[curr_off + 5],
        data[curr_off + 6],
        data[curr_off + 7],
    ]);
    let rdlength = u16::from_be_bytes([data[curr_off + 8], data[curr_off + 9]]) as usize;
    curr_off += 10;

    if curr_off + rdlength > data.len() {
        return Err(DnsError::PacketTooShort(data.len()));
    }

    let rdata_bytes = &data[curr_off..curr_off + rdlength];
    let mut legacy_ip = Ipv4Address::new(0, 0, 0, 0);

    let parsed_data = match rtype {
        DNS_TYPE_A if rdlength == 4 => {
            let mut ip_bytes = [0u8; 4];
            ip_bytes.copy_from_slice(rdata_bytes);
            let ip = Ipv4Address(ip_bytes);
            legacy_ip = ip;
            DnsRecordData::A(ip)
        }
        DNS_TYPE_AAAA if rdlength == 16 => {
            let mut ip_bytes = [0u8; 16];
            ip_bytes.copy_from_slice(rdata_bytes);
            DnsRecordData::Aaaa(Ipv6Address(ip_bytes))
        }
        DNS_TYPE_CNAME => {
            let (target, _) = decode_qname(data, curr_off)?;
            DnsRecordData::Cname(target)
        }
        DNS_TYPE_PTR => {
            let (target, _) = decode_qname(data, curr_off)?;
            DnsRecordData::Ptr(target)
        }
        DNS_TYPE_NS => {
            let (ns_name, _) = decode_qname(data, curr_off)?;
            DnsRecordData::Ns(ns_name)
        }
        DNS_TYPE_MX if rdlength >= 2 => {
            let preference = u16::from_be_bytes([rdata_bytes[0], rdata_bytes[1]]);
            let (exchange, _) = decode_qname(data, curr_off + 2)?;
            DnsRecordData::Mx {
                preference,
                exchange,
            }
        }
        DNS_TYPE_TXT => {
            let mut texts = Vec::new();
            let mut off = 0;
            while off < rdata_bytes.len() {
                let slen = rdata_bytes[off] as usize;
                off += 1;
                if off + slen <= rdata_bytes.len() {
                    let s = String::from_utf8_lossy(&rdata_bytes[off..off + slen]).to_string();
                    texts.push(s);
                    off += slen;
                } else {
                    break;
                }
            }
            DnsRecordData::Txt(texts)
        }
        DNS_TYPE_SRV if rdlength >= 6 => {
            let priority = u16::from_be_bytes([rdata_bytes[0], rdata_bytes[1]]);
            let weight = u16::from_be_bytes([rdata_bytes[2], rdata_bytes[3]]);
            let port = u16::from_be_bytes([rdata_bytes[4], rdata_bytes[5]]);
            let (target, _) = decode_qname(data, curr_off + 6)?;
            DnsRecordData::Srv {
                priority,
                weight,
                port,
                target,
            }
        }
        DNS_TYPE_SOA => {
            let (mname, off1) = decode_qname(data, curr_off)?;
            let (rname, off2) = decode_qname(data, off1)?;
            if off2 + 20 <= curr_off + rdlength {
                let serial = u32::from_be_bytes([
                    data[off2],
                    data[off2 + 1],
                    data[off2 + 2],
                    data[off2 + 3],
                ]);
                let refresh = u32::from_be_bytes([
                    data[off2 + 4],
                    data[off2 + 5],
                    data[off2 + 6],
                    data[off2 + 7],
                ]);
                let retry = u32::from_be_bytes([
                    data[off2 + 8],
                    data[off2 + 9],
                    data[off2 + 10],
                    data[off2 + 11],
                ]);
                let expire = u32::from_be_bytes([
                    data[off2 + 12],
                    data[off2 + 13],
                    data[off2 + 14],
                    data[off2 + 15],
                ]);
                let minimum = u32::from_be_bytes([
                    data[off2 + 16],
                    data[off2 + 17],
                    data[off2 + 18],
                    data[off2 + 19],
                ]);
                DnsRecordData::Soa {
                    mname,
                    rname,
                    serial,
                    refresh,
                    retry,
                    expire,
                    minimum,
                }
            } else {
                DnsRecordData::Raw(rdata_bytes.to_vec())
            }
        }
        DNS_TYPE_OPT => {
            let udp_payload_size = rclass;
            let ext_rcode = ((ttl >> 24) & 0xff) as u8;
            let version = ((ttl >> 16) & 0xff) as u8;
            let flags = (ttl & 0xffff) as u16;
            DnsRecordData::Opt {
                udp_payload_size,
                ext_rcode,
                version,
                flags,
                data: rdata_bytes.to_vec(),
            }
        }
        _ => DnsRecordData::Raw(rdata_bytes.to_vec()),
    };

    let answer = DnsAnswer {
        name,
        rtype,
        rclass,
        ttl,
        ip: legacy_ip,
        data: parsed_data,
    };

    Ok((answer, curr_off + rdlength))
}

pub fn encode_qname(hostname: &str, buf: &mut Vec<u8>) {
    for label in hostname.split('.') {
        if !label.is_empty() {
            buf.push(label.len() as u8);
            buf.extend_from_slice(label.as_bytes());
        }
    }
    buf.push(0x00);
}

pub fn decode_qname(data: &[u8], mut offset: usize) -> Result<(String, usize), DnsError> {
    let mut labels = Vec::new();
    let mut jumped = false;
    let mut return_offset = offset;
    let mut visited_offsets = std::collections::HashSet::new();
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

/// In-memory DNS cache supporting positive answers, negative caching (RFC 2308),
/// TTL expiration, and multi-record round-robin.
#[derive(Debug, Clone)]
pub struct DnsCache {
    entries: HashMap<(String, u16), CachedEntry>,
}

#[derive(Debug, Clone)]
struct CachedEntry {
    records: Vec<DnsAnswer>,
    nxdomain: bool,
    inserted_at_secs: u64,
    ttl_secs: u32,
}

impl DnsCache {
    pub fn new() -> Self {
        DnsCache {
            entries: HashMap::new(),
        }
    }

    /// Stores positive DNS response records for a given name and query type.
    pub fn insert(&mut self, name: &str, qtype: u16, records: Vec<DnsAnswer>, now_secs: u64) {
        if records.is_empty() {
            return;
        }
        let min_ttl = records.iter().map(|r| r.ttl).min().unwrap_or(60);
        let key = (name.to_lowercase(), qtype);
        self.entries.insert(
            key,
            CachedEntry {
                records,
                nxdomain: false,
                inserted_at_secs: now_secs,
                ttl_secs: min_ttl,
            },
        );
    }

    /// Stores a negative caching entry (NXDOMAIN) according to RFC 2308.
    pub fn insert_negative(&mut self, name: &str, qtype: u16, ttl_secs: u32, now_secs: u64) {
        let key = (name.to_lowercase(), qtype);
        self.entries.insert(
            key,
            CachedEntry {
                records: Vec::new(),
                nxdomain: true,
                inserted_at_secs: now_secs,
                ttl_secs: ttl_secs.max(1),
            },
        );
    }

    /// Looks up active records in cache, returning None if expired or not found.
    pub fn lookup(
        &self,
        name: &str,
        qtype: u16,
        now_secs: u64,
    ) -> Option<Result<Vec<DnsAnswer>, ()>> {
        let key = (name.to_lowercase(), qtype);
        if let Some(entry) = self.entries.get(&key) {
            let elapsed = now_secs.saturating_sub(entry.inserted_at_secs);
            if elapsed < entry.ttl_secs as u64 {
                if entry.nxdomain {
                    return Some(Err(())); // Negative entry
                }
                let remaining_ttl = entry.ttl_secs.saturating_sub(elapsed as u32);
                let updated = entry
                    .records
                    .iter()
                    .map(|r| {
                        let mut copy = r.clone();
                        copy.ttl = remaining_ttl;
                        copy
                    })
                    .collect();
                return Some(Ok(updated));
            }
        }
        None
    }

    /// Looks up IPv4 (A) addresses for a hostname.
    pub fn lookup_a(&self, name: &str, now_secs: u64) -> Option<Vec<Ipv4Address>> {
        match self.lookup(name, DNS_TYPE_A, now_secs) {
            Some(Ok(answers)) => {
                let ips: Vec<Ipv4Address> = answers
                    .into_iter()
                    .filter_map(|ans| match ans.data {
                        DnsRecordData::A(ip) => Some(ip),
                        _ => None,
                    })
                    .collect();
                if ips.is_empty() { None } else { Some(ips) }
            }
            _ => None,
        }
    }

    /// Looks up IPv6 (AAAA) addresses for a hostname.
    pub fn lookup_aaaa(&self, name: &str, now_secs: u64) -> Option<Vec<Ipv6Address>> {
        match self.lookup(name, DNS_TYPE_AAAA, now_secs) {
            Some(Ok(answers)) => {
                let ips: Vec<Ipv6Address> = answers
                    .into_iter()
                    .filter_map(|ans| match ans.data {
                        DnsRecordData::Aaaa(ip) => Some(ip),
                        _ => None,
                    })
                    .collect();
                if ips.is_empty() { None } else { Some(ips) }
            }
            _ => None,
        }
    }

    /// Purges expired entries from the cache.
    pub fn purge_expired(&mut self, now_secs: u64) {
        self.entries.retain(|_, entry| {
            let elapsed = now_secs.saturating_sub(entry.inserted_at_secs);
            elapsed < entry.ttl_secs as u64
        });
    }

    /// Clears all cached DNS entries.
    pub fn clear(&mut self) {
        self.entries.clear();
    }
}

impl Default for DnsCache {
    fn default() -> Self {
        Self::new()
    }
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
        assert_eq!(resp.answers[0].data, DnsRecordData::A(resolved_ip));
        assert_eq!(resp.answers[0].ttl, 300);
    }

    #[test]
    fn test_dns_aaaa_and_ptr_records() {
        let hostname = "ipv6.toy-tcpip.org";
        let resolved_ip6 = Ipv6Address([
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01,
        ]);
        let id = 0x1234;

        // AAAA Query & Response
        let q_bytes = DnsMessage::build_aaaa_query(id, hostname);
        let q = DnsMessage::parse(&q_bytes).unwrap();
        assert_eq!(q.questions[0].qtype, DNS_TYPE_AAAA);

        let resp_bytes = DnsMessage::build_aaaa_response(id, hostname, resolved_ip6, 600);
        let resp = DnsMessage::parse(&resp_bytes).unwrap();
        assert_eq!(resp.answers[0].rtype, DNS_TYPE_AAAA);
        assert_eq!(resp.answers[0].data, DnsRecordData::Aaaa(resolved_ip6));

        // PTR Query & Response
        let ip4 = Ipv4Address::new(8, 8, 4, 4);
        let ptr_query = DnsMessage::build_ptr_query_v4(0x5678, ip4);
        let parsed_ptr_q = DnsMessage::parse(&ptr_query).unwrap();
        assert_eq!(parsed_ptr_q.questions[0].name, "4.4.8.8.in-addr.arpa");
        assert_eq!(parsed_ptr_q.questions[0].qtype, DNS_TYPE_PTR);

        let ptr_resp =
            DnsMessage::build_ptr_response(0x5678, "4.4.8.8.in-addr.arpa", "dns.google.com", 3600);
        let parsed_ptr_r = DnsMessage::parse(&ptr_resp).unwrap();
        assert_eq!(
            parsed_ptr_r.answers[0].data,
            DnsRecordData::Ptr("dns.google.com".to_string())
        );
    }

    #[test]
    fn test_dns_cname_mx_txt_srv() {
        let id = 0x4321;
        // CNAME
        let cname_resp = DnsMessage::build_cname_response(id, "alias.com", "target.com", 120);
        let parsed_cname = DnsMessage::parse(&cname_resp).unwrap();
        assert_eq!(
            parsed_cname.answers[0].data,
            DnsRecordData::Cname("target.com".to_string())
        );

        // MX
        let mx_resp = DnsMessage::build_mx_response(id, "domain.com", 10, "mail.domain.com", 300);
        let parsed_mx = DnsMessage::parse(&mx_resp).unwrap();
        assert_eq!(
            parsed_mx.answers[0].data,
            DnsRecordData::Mx {
                preference: 10,
                exchange: "mail.domain.com".to_string()
            }
        );

        // TXT
        let txt_resp = DnsMessage::build_txt_response(
            id,
            "domain.com",
            &["v=spf1 include:_spf.google.com ~all"],
            300,
        );
        let parsed_txt = DnsMessage::parse(&txt_resp).unwrap();
        assert_eq!(
            parsed_txt.answers[0].data,
            DnsRecordData::Txt(vec!["v=spf1 include:_spf.google.com ~all".to_string()])
        );

        // SRV
        let srv_resp = DnsMessage::build_srv_response(
            id,
            "_sip._tcp.example.com",
            10,
            60,
            5060,
            "sipserver.example.com",
            3600,
        );
        let parsed_srv = DnsMessage::parse(&srv_resp).unwrap();
        assert_eq!(
            parsed_srv.answers[0].data,
            DnsRecordData::Srv {
                priority: 10,
                weight: 60,
                port: 5060,
                target: "sipserver.example.com".to_string()
            }
        );
    }

    #[test]
    fn test_dns_cache_lifecycle() {
        let mut cache = DnsCache::new();
        let name = "cached.org";
        let ip = Ipv4Address::new(1, 1, 1, 1);
        let ans = DnsAnswer {
            name: name.to_string(),
            rtype: DNS_TYPE_A,
            rclass: DNS_CLASS_IN,
            ttl: 100,
            ip,
            data: DnsRecordData::A(ip),
        };

        cache.insert(name, DNS_TYPE_A, vec![ans], 1000);
        let found = cache.lookup_a(name, 1050).unwrap();
        assert_eq!(found, vec![ip]);

        // After TTL expires
        assert!(cache.lookup_a(name, 1105).is_none());

        // Negative caching
        cache.insert_negative("nonexistent.org", DNS_TYPE_A, 30, 1000);
        assert_eq!(
            cache.lookup("nonexistent.org", DNS_TYPE_A, 1010),
            Some(Err(()))
        );
        assert_eq!(cache.lookup("nonexistent.org", DNS_TYPE_A, 1040), None);
    }
}
