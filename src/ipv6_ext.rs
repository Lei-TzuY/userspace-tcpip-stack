//! IPv6 Extension Headers & Flow Label Architecture (RFC 8200, RFC 6437, RFC 2675, RFC 2711).
//!
//! Provides parsing, serialization, and chained dispatching for Hop-by-Hop Options,
//! Routing Headers (Type 0 & SRH), Fragment Headers, Destination Options, Authentication Headers,
//! and RFC 6437 20-bit Flow Label ECMP hashing.

use crate::ipv6::Ipv6Address;
use std::fmt;

// IPv6 Extension Next Header Numbers (RFC 8200 Section 4)
pub const IPV6_EXT_HOP_BY_HOP: u8 = 0;
pub const IPV6_EXT_ROUTING: u8 = 43;
pub const IPV6_EXT_FRAGMENT: u8 = 44;
pub const IPV6_EXT_ESP: u8 = 50;
pub const IPV6_EXT_AH: u8 = 51;
pub const IPV6_EXT_NO_NEXT_HEADER: u8 = 59;
pub const IPV6_EXT_DEST_OPTIONS: u8 = 60;
pub const IPV6_EXT_MOBILITY: u8 = 135;

/// Upper bound on the number of extension headers accepted in one chain.
///
/// RFC 8200 section 4.1 lays out a recommended order in which each extension header
/// appears at most once (Destination Options at most twice), so eight covers every
/// legitimate chain. The cap exists because the chain is otherwise limited only by the
/// payload: a 64 KiB packet of minimal 8-octet headers would otherwise force thousands
/// of heap-allocated header entries out of a single datagram.
pub const MAX_EXTENSION_HEADERS: usize = 16;

// IPv6 Option Types (RFC 8200 Section 4.2)
pub const IPV6_OPT_PAD1: u8 = 0x00;
pub const IPV6_OPT_PADN: u8 = 0x01;
pub const IPV6_OPT_ROUTER_ALERT: u8 = 0x05; // RFC 2711
pub const IPV6_OPT_JUMBO_PAYLOAD: u8 = 0xC2; // RFC 2675

/// Individual Option TLV for Hop-by-Hop and Destination Options.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Ipv6Option {
    Pad1,
    PadN(Vec<u8>),
    RouterAlert(u16),
    JumboPayload(u32),
    Generic { opt_type: u8, data: Vec<u8> },
}

impl Ipv6Option {
    pub fn opt_type(&self) -> u8 {
        match self {
            Ipv6Option::Pad1 => IPV6_OPT_PAD1,
            Ipv6Option::PadN(_) => IPV6_OPT_PADN,
            Ipv6Option::RouterAlert(_) => IPV6_OPT_ROUTER_ALERT,
            Ipv6Option::JumboPayload(_) => IPV6_OPT_JUMBO_PAYLOAD,
            Ipv6Option::Generic { opt_type, .. } => *opt_type,
        }
    }

    pub fn serialize(&self) -> Vec<u8> {
        match self {
            Ipv6Option::Pad1 => vec![IPV6_OPT_PAD1],
            Ipv6Option::PadN(pad) => {
                let mut buf = vec![IPV6_OPT_PADN, pad.len() as u8];
                buf.extend_from_slice(pad);
                buf
            }
            Ipv6Option::RouterAlert(val) => {
                let mut buf = vec![IPV6_OPT_ROUTER_ALERT, 2];
                buf.extend_from_slice(&val.to_be_bytes());
                buf
            }
            Ipv6Option::JumboPayload(len) => {
                let mut buf = vec![IPV6_OPT_JUMBO_PAYLOAD, 4];
                buf.extend_from_slice(&len.to_be_bytes());
                buf
            }
            Ipv6Option::Generic { opt_type, data } => {
                let mut buf = vec![*opt_type, data.len() as u8];
                buf.extend_from_slice(data);
                buf
            }
        }
    }

    pub fn parse_all(data: &[u8]) -> Result<Vec<Self>, Ipv6ExtError> {
        let mut opts = Vec::new();
        let mut cursor = 0;
        while cursor < data.len() {
            let opt_type = data[cursor];
            if opt_type == IPV6_OPT_PAD1 {
                opts.push(Ipv6Option::Pad1);
                cursor += 1;
                continue;
            }
            if cursor + 1 >= data.len() {
                return Err(Ipv6ExtError::TruncatedOption);
            }
            let opt_data_len = data[cursor + 1] as usize;
            let opt_end = cursor + 2 + opt_data_len;
            if opt_end > data.len() {
                return Err(Ipv6ExtError::TruncatedOption);
            }
            let opt_data = &data[cursor + 2..opt_end];
            let opt = match opt_type {
                IPV6_OPT_PADN => Ipv6Option::PadN(opt_data.to_vec()),
                IPV6_OPT_ROUTER_ALERT if opt_data.len() == 2 => {
                    let val = u16::from_be_bytes([opt_data[0], opt_data[1]]);
                    Ipv6Option::RouterAlert(val)
                }
                IPV6_OPT_JUMBO_PAYLOAD if opt_data.len() == 4 => {
                    let val =
                        u32::from_be_bytes([opt_data[0], opt_data[1], opt_data[2], opt_data[3]]);
                    Ipv6Option::JumboPayload(val)
                }
                _ => Ipv6Option::Generic {
                    opt_type,
                    data: opt_data.to_vec(),
                },
            };
            opts.push(opt);
            cursor = opt_end;
        }
        Ok(opts)
    }
}

/// Typed IPv6 Extension Header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Ipv6ExtensionHeader {
    HopByHop {
        options: Vec<Ipv6Option>,
    },
    Routing {
        routing_type: u8,
        segments_left: u8,
        data: Vec<u8>,
    },
    Fragment {
        fragment_offset: u16,
        more_fragments: bool,
        identification: u32,
    },
    DestinationOptions {
        options: Vec<Ipv6Option>,
    },
    AuthenticationHeader {
        spi: u32,
        sequence_number: u32,
        icv: Vec<u8>,
    },
    Unknown {
        next_header_type: u8,
        data: Vec<u8>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Ipv6ExtError {
    HeaderTooShort(usize),
    TruncatedOption,
    InvalidHeaderLength(usize),
    InvalidNextHeader(u8),
    ChainTooLong(usize),
    MisplacedHopByHop,
}

impl fmt::Display for Ipv6ExtError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Ipv6ExtError::HeaderTooShort(l) => {
                write!(f, "IPv6 extension header too short ({} bytes)", l)
            }
            Ipv6ExtError::TruncatedOption => write!(f, "Truncated IPv6 option in extension header"),
            Ipv6ExtError::InvalidHeaderLength(l) => {
                write!(f, "Invalid IPv6 extension header length ({} bytes)", l)
            }
            Ipv6ExtError::InvalidNextHeader(nh) => {
                write!(f, "Invalid next header value in extension chain: {}", nh)
            }
            Ipv6ExtError::ChainTooLong(count) => write!(
                f,
                "IPv6 extension header chain exceeds {} headers (saw at least {})",
                MAX_EXTENSION_HEADERS, count
            ),
            Ipv6ExtError::MisplacedHopByHop => write!(
                f,
                "Hop-by-Hop Options header must immediately follow the IPv6 header"
            ),
        }
    }
}

impl std::error::Error for Ipv6ExtError {}

impl Ipv6ExtensionHeader {
    /// Returns the Next Header ID identifying this extension header.
    pub fn extension_type(&self) -> u8 {
        match self {
            Ipv6ExtensionHeader::HopByHop { .. } => IPV6_EXT_HOP_BY_HOP,
            Ipv6ExtensionHeader::Routing { .. } => IPV6_EXT_ROUTING,
            Ipv6ExtensionHeader::Fragment { .. } => IPV6_EXT_FRAGMENT,
            Ipv6ExtensionHeader::DestinationOptions { .. } => IPV6_EXT_DEST_OPTIONS,
            Ipv6ExtensionHeader::AuthenticationHeader { .. } => IPV6_EXT_AH,
            Ipv6ExtensionHeader::Unknown {
                next_header_type, ..
            } => *next_header_type,
        }
    }

    /// Serializes this single extension header (without outer next_header).
    pub fn serialize_body(&self) -> (Vec<u8>, u8) {
        match self {
            Ipv6ExtensionHeader::HopByHop { options }
            | Ipv6ExtensionHeader::DestinationOptions { options } => {
                let mut opt_bytes = Vec::new();
                for opt in options {
                    opt_bytes.extend_from_slice(&opt.serialize());
                }
                // Must pad to multiple of 8 octets (including 2-byte header: next_header + hdr_ext_len)
                let total_body_len = 2 + opt_bytes.len();
                let pad_needed = (8 - (total_body_len % 8)) % 8;
                if pad_needed == 1 {
                    opt_bytes.push(IPV6_OPT_PAD1);
                } else if pad_needed > 1 {
                    let pad_data = vec![0u8; pad_needed - 2];
                    opt_bytes.push(IPV6_OPT_PADN);
                    opt_bytes.push(pad_data.len() as u8);
                    opt_bytes.extend_from_slice(&pad_data);
                }
                let total_octets = 2 + opt_bytes.len();
                let hdr_ext_len = (total_octets / 8).saturating_sub(1) as u8;
                (opt_bytes, hdr_ext_len)
            }
            Ipv6ExtensionHeader::Routing {
                routing_type,
                segments_left,
                data,
            } => {
                let mut body = Vec::with_capacity(2 + data.len());
                body.push(*routing_type);
                body.push(*segments_left);
                body.extend_from_slice(data);
                let total_octets = 2 + body.len();
                let pad_needed = (8 - (total_octets % 8)) % 8;
                body.extend(std::iter::repeat(0u8).take(pad_needed));
                let total_aligned = 2 + body.len();
                let hdr_ext_len = (total_aligned / 8).saturating_sub(1) as u8;
                (body, hdr_ext_len)
            }
            Ipv6ExtensionHeader::Fragment {
                fragment_offset,
                more_fragments,
                identification,
            } => {
                let mut body = vec![0u8; 6];
                let mut off_mf = (*fragment_offset & 0x1FFF) << 3;
                if *more_fragments {
                    off_mf |= 0x01;
                }
                body[0..2].copy_from_slice(&off_mf.to_be_bytes());
                body[2..6].copy_from_slice(&identification.to_be_bytes());
                (body, 0) // Fragment header is always 8 bytes fixed (hdr_ext_len not in fragment hdr format)
            }
            Ipv6ExtensionHeader::AuthenticationHeader {
                spi,
                sequence_number,
                icv,
            } => {
                let mut body = Vec::with_capacity(10 + icv.len());
                body.push(0); // Reserved
                body.push(0); // Reserved
                body.extend_from_slice(&spi.to_be_bytes());
                body.extend_from_slice(&sequence_number.to_be_bytes());
                body.extend_from_slice(icv);
                let total_words = (2 + body.len() + 3) / 4;
                let payload_len_words = total_words.saturating_sub(2) as u8;
                (body, payload_len_words)
            }
            Ipv6ExtensionHeader::Unknown { data, .. } => {
                let total_octets = 2 + data.len();
                let hdr_ext_len = (total_octets / 8).saturating_sub(1) as u8;
                (data.clone(), hdr_ext_len)
            }
        }
    }
}

/// Chain of IPv6 Extension Headers traversed between IPv6 Header and L4 payload.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Ipv6ExtensionChain {
    pub headers: Vec<Ipv6ExtensionHeader>,
    pub final_next_header: u8,
}

impl Ipv6ExtensionChain {
    pub fn new(final_next_header: u8) -> Self {
        Ipv6ExtensionChain {
            headers: Vec::new(),
            final_next_header,
        }
    }

    pub fn push(&mut self, header: Ipv6ExtensionHeader) {
        self.headers.push(header);
    }

    /// Parses an extension chain from raw payload given initial next_header from IPv6 fixed header.
    pub fn parse(initial_next_header: u8, data: &[u8]) -> Result<(Self, usize), Ipv6ExtError> {
        let mut headers = Vec::new();
        let mut curr_nh = initial_next_header;
        let mut offset = 0;

        while is_extension_header(curr_nh) {
            // RFC 8200 section 4.1: the Hop-by-Hop Options header, when present, must
            // immediately follow the IPv6 header. Every router on the path is obliged to
            // examine it, so one buried later in the chain is malformed rather than
            // merely unusual, and accepting it would let a sender hide hop-by-hop
            // options from forwarding nodes that stop at the first header.
            if curr_nh == IPV6_EXT_HOP_BY_HOP && !headers.is_empty() {
                return Err(Ipv6ExtError::MisplacedHopByHop);
            }

            // Bound the work one datagram can force. Each header costs a heap-allocated
            // entry, and nothing but the payload length limits how many an attacker can
            // chain together.
            if headers.len() >= MAX_EXTENSION_HEADERS {
                return Err(Ipv6ExtError::ChainTooLong(headers.len() + 1));
            }

            if curr_nh == IPV6_EXT_NO_NEXT_HEADER {
                return Ok((
                    Ipv6ExtensionChain {
                        headers,
                        final_next_header: IPV6_EXT_NO_NEXT_HEADER,
                    },
                    offset,
                ));
            }

            if offset >= data.len() {
                return Err(Ipv6ExtError::HeaderTooShort(data.len() - offset));
            }

            let next_nh = data[offset];

            if curr_nh == IPV6_EXT_FRAGMENT {
                if offset + 8 > data.len() {
                    return Err(Ipv6ExtError::HeaderTooShort(data.len() - offset));
                }
                let off_mf = u16::from_be_bytes([data[offset + 2], data[offset + 3]]);
                let fragment_offset = off_mf >> 3;
                let more_fragments = (off_mf & 0x01) != 0;
                let identification = u32::from_be_bytes([
                    data[offset + 4],
                    data[offset + 5],
                    data[offset + 6],
                    data[offset + 7],
                ]);
                headers.push(Ipv6ExtensionHeader::Fragment {
                    fragment_offset,
                    more_fragments,
                    identification,
                });
                offset += 8;
                curr_nh = next_nh;
                continue;
            }

            if offset + 2 > data.len() {
                return Err(Ipv6ExtError::HeaderTooShort(data.len() - offset));
            }
            let hdr_ext_len = data[offset + 1];
            let total_len = match curr_nh {
                IPV6_EXT_AH => (hdr_ext_len as usize + 2) * 4,
                _ => (hdr_ext_len as usize + 1) * 8,
            };

            if offset + total_len > data.len() {
                return Err(Ipv6ExtError::HeaderTooShort(data.len() - offset));
            }

            let ext_payload = &data[offset + 2..offset + total_len];
            match curr_nh {
                IPV6_EXT_HOP_BY_HOP => {
                    let options = Ipv6Option::parse_all(ext_payload)?;
                    headers.push(Ipv6ExtensionHeader::HopByHop { options });
                }
                IPV6_EXT_DEST_OPTIONS => {
                    let options = Ipv6Option::parse_all(ext_payload)?;
                    headers.push(Ipv6ExtensionHeader::DestinationOptions { options });
                }
                IPV6_EXT_ROUTING if ext_payload.len() >= 2 => {
                    let routing_type = ext_payload[0];
                    let segments_left = ext_payload[1];
                    let data = ext_payload[2..].to_vec();
                    headers.push(Ipv6ExtensionHeader::Routing {
                        routing_type,
                        segments_left,
                        data,
                    });
                }
                IPV6_EXT_AH if ext_payload.len() >= 10 => {
                    let spi = u32::from_be_bytes([
                        ext_payload[2],
                        ext_payload[3],
                        ext_payload[4],
                        ext_payload[5],
                    ]);
                    let sequence_number = u32::from_be_bytes([
                        ext_payload[6],
                        ext_payload[7],
                        ext_payload[8],
                        ext_payload[9],
                    ]);
                    let icv = ext_payload[10..].to_vec();
                    headers.push(Ipv6ExtensionHeader::AuthenticationHeader {
                        spi,
                        sequence_number,
                        icv,
                    });
                }
                _ => {
                    headers.push(Ipv6ExtensionHeader::Unknown {
                        next_header_type: curr_nh,
                        data: ext_payload.to_vec(),
                    });
                }
            }

            offset += total_len;
            curr_nh = next_nh;
        }

        Ok((
            Ipv6ExtensionChain {
                headers,
                final_next_header: curr_nh,
            },
            offset,
        ))
    }

    /// Serializes the entire extension chain and returns (bytes, first_next_header).
    pub fn serialize(&self) -> (Vec<u8>, u8) {
        if self.headers.is_empty() {
            return (Vec::new(), self.final_next_header);
        }

        let first_nh = self.headers[0].extension_type();
        let mut buf = Vec::new();

        for (i, header) in self.headers.iter().enumerate() {
            let next_nh = if i + 1 < self.headers.len() {
                self.headers[i + 1].extension_type()
            } else {
                self.final_next_header
            };

            match header {
                Ipv6ExtensionHeader::Fragment {
                    fragment_offset,
                    more_fragments,
                    identification,
                } => {
                    buf.push(next_nh);
                    buf.push(0); // Reserved
                    let mut off_mf = (*fragment_offset & 0x1FFF) << 3;
                    if *more_fragments {
                        off_mf |= 0x01;
                    }
                    buf.extend_from_slice(&off_mf.to_be_bytes());
                    buf.extend_from_slice(&identification.to_be_bytes());
                }
                _ => {
                    let (body, hdr_ext_len) = header.serialize_body();
                    buf.push(next_nh);
                    buf.push(hdr_ext_len);
                    buf.extend_from_slice(&body);
                }
            }
        }

        (buf, first_nh)
    }
}

/// Checks if a next_header value represents an IPv6 extension header.
pub fn is_extension_header(nh: u8) -> bool {
    matches!(
        nh,
        IPV6_EXT_HOP_BY_HOP
            | IPV6_EXT_ROUTING
            | IPV6_EXT_FRAGMENT
            | IPV6_EXT_AH
            | IPV6_EXT_DEST_OPTIONS
            | IPV6_EXT_MOBILITY
            | IPV6_EXT_NO_NEXT_HEADER
    )
}

/// Generates a 20-bit IPv6 Flow Label (RFC 6437) from a 5-tuple hash.
pub fn compute_flow_label(
    src_ip: Ipv6Address,
    dst_ip: Ipv6Address,
    proto: u8,
    src_port: u16,
    dst_port: u16,
    salt: u32,
) -> u32 {
    let mut hash = 0x811c9dc5u32 ^ salt;
    for b in src_ip.0 {
        hash = (hash ^ (b as u32)).wrapping_mul(0x01000193);
    }
    for b in dst_ip.0 {
        hash = (hash ^ (b as u32)).wrapping_mul(0x01000193);
    }
    hash = (hash ^ (proto as u32)).wrapping_mul(0x01000193);
    hash = (hash ^ ((src_port >> 8) as u32)).wrapping_mul(0x01000193);
    hash = (hash ^ ((src_port & 0xff) as u32)).wrapping_mul(0x01000193);
    hash = (hash ^ ((dst_port >> 8) as u32)).wrapping_mul(0x01000193);
    hash = (hash ^ ((dst_port & 0xff) as u32)).wrapping_mul(0x01000193);

    // 20-bit non-zero label (1..0xFFFFF)
    let label = (hash ^ (hash >> 12)) & 0x000F_FFFF;
    if label == 0 { 1 } else { label }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn test_ipv6_options_pad_and_router_alert() {
        let opts = vec![
            Ipv6Option::RouterAlert(0x0000), // MLD
            Ipv6Option::JumboPayload(70_000),
        ];
        let hbh = Ipv6ExtensionHeader::HopByHop { options: opts };
        let mut chain = Ipv6ExtensionChain::new(58); // ICMPv6
        chain.push(hbh);

        let (raw, first_nh) = chain.serialize();
        assert_eq!(first_nh, IPV6_EXT_HOP_BY_HOP);
        assert_eq!(raw.len() % 8, 0);

        let (parsed_chain, consumed) = Ipv6ExtensionChain::parse(first_nh, &raw).unwrap();
        assert_eq!(consumed, raw.len());
        assert_eq!(parsed_chain.final_next_header, 58);
        assert_eq!(parsed_chain.headers.len(), 1);

        if let Ipv6ExtensionHeader::HopByHop { options } = &parsed_chain.headers[0] {
            let mut non_pad = Vec::new();
            for o in options {
                match o {
                    Ipv6Option::Pad1 | Ipv6Option::PadN(_) => {}
                    _ => non_pad.push(o.clone()),
                }
            }
            assert_eq!(non_pad.len(), 2);
            assert_eq!(non_pad[0], Ipv6Option::RouterAlert(0x0000));
            assert_eq!(non_pad[1], Ipv6Option::JumboPayload(70_000));
        } else {
            panic!("Expected HopByHop header");
        }
    }

    #[test]
    fn test_ipv6_extension_chain_multi_hop() {
        let mut chain = Ipv6ExtensionChain::new(6); // TCP
        chain.push(Ipv6ExtensionHeader::HopByHop {
            options: vec![Ipv6Option::RouterAlert(1)],
        });
        chain.push(Ipv6ExtensionHeader::Fragment {
            fragment_offset: 100,
            more_fragments: true,
            identification: 0xCAFEBABE,
        });

        let (raw, first_nh) = chain.serialize();
        assert_eq!(first_nh, IPV6_EXT_HOP_BY_HOP);

        let (parsed_chain, consumed) = Ipv6ExtensionChain::parse(first_nh, &raw).unwrap();
        assert_eq!(consumed, raw.len());
        assert_eq!(parsed_chain.final_next_header, 6);
        assert_eq!(parsed_chain.headers.len(), 2);

        assert_eq!(
            parsed_chain.headers[1],
            Ipv6ExtensionHeader::Fragment {
                fragment_offset: 100,
                more_fragments: true,
                identification: 0xCAFEBABE
            }
        );
    }

    #[test]
    fn test_rfc6437_flow_label_deterministic_and_bounded() {
        let src = Ipv6Address::from_str("2001:db8::1").unwrap();
        let dst = Ipv6Address::from_str("2001:db8::2").unwrap();
        let fl1 = compute_flow_label(src, dst, 6, 8080, 443, 0x1234);
        let fl2 = compute_flow_label(src, dst, 6, 8080, 443, 0x1234);
        assert_eq!(fl1, fl2);
        assert!(fl1 > 0 && fl1 <= 0x000F_FFFF);
    }
}
