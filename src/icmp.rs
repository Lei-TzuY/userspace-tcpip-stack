//! Layer 3: Internet Control Message Protocol (ICMP - RFC 792).
//!
//! Handles ICMP Echo Request (Type 8) and Echo Reply (Type 0).

use crate::checksum::{compute_checksum, verify_checksum};
use std::fmt;

pub const ICMP_TYPE_ECHO_REPLY: u8 = 0;
pub const ICMP_TYPE_DEST_UNREACHABLE: u8 = 3;
pub const ICMP_TYPE_ECHO_REQUEST: u8 = 8;
pub const ICMP_TYPE_TIME_EXCEEDED: u8 = 11;

pub const ICMP_HEADER_LEN: usize = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IcmpType {
    EchoReply,
    EchoRequest,
    DestinationUnreachable,
    TimeExceeded,
    Other(u8),
}

impl IcmpType {
    pub fn from_u8(val: u8) -> Self {
        match val {
            ICMP_TYPE_ECHO_REPLY => IcmpType::EchoReply,
            ICMP_TYPE_ECHO_REQUEST => IcmpType::EchoRequest,
            ICMP_TYPE_DEST_UNREACHABLE => IcmpType::DestinationUnreachable,
            ICMP_TYPE_TIME_EXCEEDED => IcmpType::TimeExceeded,
            other => IcmpType::Other(other),
        }
    }

    pub fn to_u8(&self) -> u8 {
        match self {
            IcmpType::EchoReply => ICMP_TYPE_ECHO_REPLY,
            IcmpType::EchoRequest => ICMP_TYPE_ECHO_REQUEST,
            IcmpType::DestinationUnreachable => ICMP_TYPE_DEST_UNREACHABLE,
            IcmpType::TimeExceeded => ICMP_TYPE_TIME_EXCEEDED,
            IcmpType::Other(val) => *val,
        }
    }
}

impl fmt::Display for IcmpType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IcmpType::EchoReply => write!(f, "Echo Reply (0)"),
            IcmpType::EchoRequest => write!(f, "Echo Request (8)"),
            IcmpType::DestinationUnreachable => write!(f, "Destination Unreachable (3)"),
            IcmpType::TimeExceeded => write!(f, "Time Exceeded (11)"),
            IcmpType::Other(val) => write!(f, "ICMP Type ({})", val),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IcmpPacket<'a> {
    pub icmp_type: IcmpType,
    pub code: u8,
    pub checksum: u16,
    pub identifier: u16,
    pub sequence_number: u16,
    pub payload: &'a [u8],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IcmpError {
    PacketTooShort(usize),
    InvalidChecksum { computed: u16, found: u16 },
}

impl fmt::Display for IcmpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IcmpError::PacketTooShort(len) => {
                write!(f, "ICMP packet too short ({} bytes, min 8)", len)
            }
            IcmpError::InvalidChecksum { computed, found } => {
                write!(
                    f,
                    "ICMP checksum mismatch: computed 0x{:04x}, found 0x{:04x}",
                    computed, found
                )
            }
        }
    }
}

impl std::error::Error for IcmpError {}

fn ipv4_error_quote_len(orig_datagram: &[u8]) -> usize {
    if let Some(&version_ihl) = orig_datagram.first() {
        let version = version_ihl >> 4;
        let ihl_words = (version_ihl & 0x0f) as usize;
        let header_len = ihl_words.saturating_mul(4);
        if version == 4 && ihl_words >= 5 && header_len <= orig_datagram.len() {
            return orig_datagram.len().min(header_len.saturating_add(8));
        }
    }

    // Preserve the historical minimum-header behaviour for callers that pass
    // a truncated or non-IPv4 byte slice.
    orig_datagram.len().min(28)
}

impl<'a> IcmpPacket<'a> {
    pub fn parse(data: &'a [u8], check_checksum: bool) -> Result<Self, IcmpError> {
        if data.len() < ICMP_HEADER_LEN {
            return Err(IcmpError::PacketTooShort(data.len()));
        }

        if check_checksum && !verify_checksum(data) {
            let actual = compute_checksum(data);
            let found = u16::from_be_bytes([data[2], data[3]]);
            return Err(IcmpError::InvalidChecksum {
                computed: actual,
                found,
            });
        }

        let icmp_type = IcmpType::from_u8(data[0]);
        let code = data[1];
        let checksum = u16::from_be_bytes([data[2], data[3]]);
        let identifier = u16::from_be_bytes([data[4], data[5]]);
        let sequence_number = u16::from_be_bytes([data[6], data[7]]);
        let payload = &data[ICMP_HEADER_LEN..];

        Ok(IcmpPacket {
            icmp_type,
            code,
            checksum,
            identifier,
            sequence_number,
            payload,
        })
    }

    pub fn serialize(
        icmp_type: u8,
        code: u8,
        identifier: u16,
        sequence_number: u16,
        payload: &[u8],
    ) -> Vec<u8> {
        let mut buf = Vec::with_capacity(ICMP_HEADER_LEN + payload.len());
        buf.push(icmp_type);
        buf.push(code);
        buf.extend_from_slice(&[0x00, 0x00]); // Checksum placeholder
        buf.extend_from_slice(&identifier.to_be_bytes());
        buf.extend_from_slice(&sequence_number.to_be_bytes());
        buf.extend_from_slice(payload);

        let csum = compute_checksum(&buf);
        buf[2..4].copy_from_slice(&csum.to_be_bytes());
        buf
    }

    pub fn build_echo_reply(req: &IcmpPacket<'_>) -> Vec<u8> {
        Self::serialize(
            ICMP_TYPE_ECHO_REPLY,
            0,
            req.identifier,
            req.sequence_number,
            req.payload,
        )
    }

    pub fn build_echo_request(identifier: u16, sequence_number: u16, payload: &[u8]) -> Vec<u8> {
        Self::serialize(
            ICMP_TYPE_ECHO_REQUEST,
            0,
            identifier,
            sequence_number,
            payload,
        )
    }

    /// Builds an ICMP Time Exceeded (Type 11) message.
    pub fn build_time_exceeded(code: u8, orig_datagram: &[u8]) -> Vec<u8> {
        let copy_len = ipv4_error_quote_len(orig_datagram);
        let mut payload = Vec::with_capacity(4 + copy_len);
        payload.extend_from_slice(&[0, 0, 0, 0]); // Unused 4 bytes (RFC 792)
        // Include the complete original IPv4 header (including options) plus
        // the first 8 bytes of the original datagram payload.
        payload.extend_from_slice(&orig_datagram[..copy_len]);
        Self::serialize(ICMP_TYPE_TIME_EXCEEDED, code, 0, 0, &payload)
    }

    /// Builds an ICMP Destination Unreachable (Type 3) message (e.g. Fragmentation Needed Code 4)
    pub fn build_destination_unreachable(
        code: u8,
        next_hop_mtu: u16,
        orig_datagram: &[u8],
    ) -> Vec<u8> {
        let copy_len = ipv4_error_quote_len(orig_datagram);
        let mut payload = Vec::with_capacity(4 + copy_len);
        if code == 4 {
            // RFC 1191 Path MTU Discovery: 2 unused bytes + 2 bytes Next-Hop MTU
            payload.extend_from_slice(&[0, 0]);
            payload.extend_from_slice(&next_hop_mtu.to_be_bytes());
        } else {
            payload.extend_from_slice(&[0, 0, 0, 0]);
        }
        payload.extend_from_slice(&orig_datagram[..copy_len]);
        Self::serialize(ICMP_TYPE_DEST_UNREACHABLE, code, 0, 0, &payload)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_icmp_echo_reply_creation() {
        let ping_payload = b"abcdefghijklmnopqrstuvwabcdefghi";
        let req_raw = IcmpPacket::build_echo_request(0x1234, 1, ping_payload);
        assert_eq!(req_raw.len(), 8 + ping_payload.len());

        let req = IcmpPacket::parse(&req_raw, true).unwrap();
        assert_eq!(req.icmp_type, IcmpType::EchoRequest);
        assert_eq!(req.identifier, 0x1234);
        assert_eq!(req.sequence_number, 1);
        assert_eq!(req.payload, ping_payload);

        let reply_raw = IcmpPacket::build_echo_reply(&req);
        let reply = IcmpPacket::parse(&reply_raw, true).unwrap();
        assert_eq!(reply.icmp_type, IcmpType::EchoReply);
        assert_eq!(reply.identifier, 0x1234);
        assert_eq!(reply.sequence_number, 1);
        assert_eq!(reply.payload, ping_payload);
    }

    #[test]
    fn time_exceeded_quotes_ipv4_options_and_eight_payload_bytes() {
        let mut original = vec![0u8; 36];
        original[0] = 0x47; // IPv4, IHL=7 => 28-byte header.
        for (index, byte) in original.iter_mut().enumerate().skip(1) {
            *byte = index as u8;
        }

        let raw = IcmpPacket::build_time_exceeded(1, &original);
        let parsed = IcmpPacket::parse(&raw, true).unwrap();

        assert_eq!(parsed.icmp_type, IcmpType::TimeExceeded);
        assert_eq!(parsed.code, 1);
        assert_eq!(&parsed.payload[..4], &[0, 0, 0, 0]);
        assert_eq!(&parsed.payload[4..], original.as_slice());
    }

    #[test]
    fn destination_unreachable_quotes_ipv4_options_and_eight_payload_bytes() {
        let mut original = vec![0u8; 32];
        original[0] = 0x46; // IPv4, IHL=6 => 24-byte header.
        for (index, byte) in original.iter_mut().enumerate().skip(1) {
            *byte = (index as u8).wrapping_mul(3);
        }

        let raw = IcmpPacket::build_destination_unreachable(0, 0, &original);
        let parsed = IcmpPacket::parse(&raw, true).unwrap();

        assert_eq!(parsed.icmp_type, IcmpType::DestinationUnreachable);
        assert_eq!(&parsed.payload[..4], &[0, 0, 0, 0]);
        assert_eq!(&parsed.payload[4..], original.as_slice());
    }
}
