//! Layer 3: Internet Control Message Protocol (ICMP - RFC 792).
//!
//! Handles ICMP Echo, error-message parsing, and construction helpers.

use crate::checksum::{compute_checksum, verify_checksum};
use crate::ethernet::{ETHERTYPE_IPV4, EtherType, EthernetFrame, MacAddress};
use crate::ipv4::{IP_PROTO_ICMP, Ipv4Address, Ipv4Error, Ipv4Packet};
use crate::stack::NetStack;
use std::fmt;

pub const ICMP_TYPE_ECHO_REPLY: u8 = 0;
pub const ICMP_TYPE_DEST_UNREACHABLE: u8 = 3;
pub const ICMP_TYPE_ECHO_REQUEST: u8 = 8;
pub const ICMP_TYPE_TIME_EXCEEDED: u8 = 11;
pub const ICMP_TYPE_PARAMETER_PROBLEM: u8 = 12;

pub const ICMP_HEADER_LEN: usize = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IcmpType {
    EchoReply,
    EchoRequest,
    DestinationUnreachable,
    TimeExceeded,
    ParameterProblem,
    Other(u8),
}

impl IcmpType {
    pub fn from_u8(val: u8) -> Self {
        match val {
            ICMP_TYPE_ECHO_REPLY => IcmpType::EchoReply,
            ICMP_TYPE_ECHO_REQUEST => IcmpType::EchoRequest,
            ICMP_TYPE_DEST_UNREACHABLE => IcmpType::DestinationUnreachable,
            ICMP_TYPE_TIME_EXCEEDED => IcmpType::TimeExceeded,
            ICMP_TYPE_PARAMETER_PROBLEM => IcmpType::ParameterProblem,
            other => IcmpType::Other(other),
        }
    }

    pub fn to_u8(&self) -> u8 {
        match self {
            IcmpType::EchoReply => ICMP_TYPE_ECHO_REPLY,
            IcmpType::EchoRequest => ICMP_TYPE_ECHO_REQUEST,
            IcmpType::DestinationUnreachable => ICMP_TYPE_DEST_UNREACHABLE,
            IcmpType::TimeExceeded => ICMP_TYPE_TIME_EXCEEDED,
            IcmpType::ParameterProblem => ICMP_TYPE_PARAMETER_PROBLEM,
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
            IcmpType::ParameterProblem => write!(f, "Parameter Problem (12)"),
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

    /// Builds an ICMP Parameter Problem (Type 12, Code 0) message.
    ///
    /// The pointer identifies the octet in the invoking IPv4 header where the
    /// problem was detected. RFC 792 places it directly in byte 4 of the ICMP
    /// error header, followed by three reserved zero bytes, then the quoted
    /// original IPv4 header plus at least its first eight payload bytes.
    pub fn build_parameter_problem(pointer: u8, orig_datagram: &[u8]) -> Vec<u8> {
        let copy_len = ipv4_error_quote_len(orig_datagram);
        let mut buf = Vec::with_capacity(ICMP_HEADER_LEN + copy_len);
        buf.push(ICMP_TYPE_PARAMETER_PROBLEM);
        buf.push(0); // Code 0: pointer indicates the error.
        buf.extend_from_slice(&[0, 0]); // Checksum placeholder.
        buf.push(pointer);
        buf.extend_from_slice(&[0, 0, 0]);
        buf.extend_from_slice(&orig_datagram[..copy_len]);

        let csum = compute_checksum(&buf);
        buf[2..4].copy_from_slice(&csum.to_be_bytes());
        buf
    }
}

fn parameter_problem_pointer(error: &Ipv4Error) -> Option<u8> {
    match error {
        Ipv4Error::TotalLengthSmallerThanHeader { .. } => Some(2),
        Ipv4Error::ReservedFragmentFlagSet => Some(6),
        _ => None,
    }
}

fn safe_ipv4_error_source(address: Ipv4Address) -> bool {
    !address.is_unspecified()
        && !address.is_broadcast()
        && !address.is_multicast()
        && !address.is_loopback()
}

/// Builds a guarded ICMPv4 Parameter Problem reply for a malformed Ethernet/IPv4 frame.
///
/// Only parser failures with an unambiguous RFC 792 pointer are eligible. The invoking
/// IPv4 header must still have a valid checksum, target this host, come from a unicast
/// source, and be an initial non-ICMP fragment. Those gates preserve the stack's
/// fail-closed behaviour and RFC 1122/1812 error-suppression rules.
pub fn build_ipv4_parameter_problem_reply(
    local_mac: MacAddress,
    local_ip: Ipv4Address,
    raw_frame: &[u8],
) -> Option<Vec<u8>> {
    let ethernet = EthernetFrame::parse(raw_frame).ok()?;
    if ethernet.ethertype != EtherType::IPv4 || ethernet.dst_mac != local_mac {
        return None;
    }

    let datagram = ethernet.payload;
    let error = Ipv4Packet::parse(datagram, true).err()?;
    let pointer = parameter_problem_pointer(&error)?;

    if datagram.len() < 20 || datagram[0] >> 4 != 4 {
        return None;
    }
    let ihl = (datagram[0] & 0x0f) as usize;
    if ihl < 5 {
        return None;
    }
    let header_len = ihl.checked_mul(4)?;
    if header_len > datagram.len() || !verify_checksum(&datagram[..header_len]) {
        return None;
    }

    let source = Ipv4Address::from_bytes(datagram[12..16].try_into().ok()?);
    let destination = Ipv4Address::from_bytes(datagram[16..20].try_into().ok()?);
    if destination != local_ip || !safe_ipv4_error_source(source) {
        return None;
    }

    if datagram[9] == IP_PROTO_ICMP {
        return None;
    }
    let flags_fragment = u16::from_be_bytes([datagram[6], datagram[7]]);
    if flags_fragment & 0x1fff != 0 {
        return None;
    }

    let icmp = IcmpPacket::build_parameter_problem(pointer, datagram);
    let ip = Ipv4Packet::serialize(local_ip, source, IP_PROTO_ICMP, 0, 64, &icmp);
    Some(EthernetFrame::serialize(
        ethernet.src_mac,
        local_mac,
        ETHERTYPE_IPV4,
        &ip,
    ))
}

impl NetStack {
    /// Processes an Ethernet frame through the normal stack ingress while adding
    /// RFC 792 Parameter Problem generation for malformed IPv4 headers that the
    /// ordinary parser rejects before `process_frame` can reach its IPv4 branch.
    pub fn process_frame_with_ipv4_errors(&mut self, raw_frame: &[u8]) -> Vec<Vec<u8>> {
        if let Some(reply) =
            build_ipv4_parameter_problem_reply(self.config.mac, self.config.ip, raw_frame)
        {
            return vec![reply];
        }
        self.process_frame(raw_frame)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stack::NetStackConfig;

    const LOCAL_MAC: MacAddress = MacAddress([0x02, 0, 0, 0, 0, 1]);
    const REMOTE_MAC: MacAddress = MacAddress([0x02, 0, 0, 0, 0, 2]);
    const LOCAL_IP: Ipv4Address = Ipv4Address([192, 0, 2, 1]);
    const REMOTE_IP: Ipv4Address = Ipv4Address([192, 0, 2, 2]);

    fn stack() -> NetStack {
        NetStack::new(NetStackConfig {
            mac: LOCAL_MAC,
            ip: LOCAL_IP,
            ipv6: None,
            subnet_mask: 24,
            gateway: None,
        })
    }

    fn malformed_reserved_flag_frame(protocol: u8) -> Vec<u8> {
        let mut datagram =
            Ipv4Packet::serialize(REMOTE_IP, LOCAL_IP, protocol, 0x1234, 64, b"abcdefgh");
        datagram[6] |= 0x80;
        datagram[10] = 0;
        datagram[11] = 0;
        let checksum = compute_checksum(&datagram[..20]);
        datagram[10..12].copy_from_slice(&checksum.to_be_bytes());
        EthernetFrame::serialize(LOCAL_MAC, REMOTE_MAC, ETHERTYPE_IPV4, &datagram)
    }

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

    #[test]
    fn parameter_problem_encodes_pointer_in_error_header_and_quotes_ipv4_options() {
        let mut original = vec![0u8; 40];
        original[0] = 0x47; // IPv4, IHL=7 => 28-byte header + 8 quoted payload bytes.
        for (index, byte) in original.iter_mut().enumerate().skip(1) {
            *byte = (index as u8).wrapping_mul(5);
        }

        let raw = IcmpPacket::build_parameter_problem(9, &original);
        let parsed = IcmpPacket::parse(&raw, true).unwrap();

        assert_eq!(parsed.icmp_type, IcmpType::ParameterProblem);
        assert_eq!(parsed.code, 0);
        assert_eq!(&raw[4..8], &[9, 0, 0, 0]);
        assert_eq!(parsed.identifier, 0x0900);
        assert_eq!(parsed.sequence_number, 0);
        assert_eq!(parsed.payload, &original[..36]);
    }

    #[test]
    fn netstack_ingress_emits_parameter_problem_for_reserved_fragment_flag() {
        let mut stack = stack();
        let replies = stack.process_frame_with_ipv4_errors(&malformed_reserved_flag_frame(17));
        assert_eq!(replies.len(), 1);

        let ethernet = EthernetFrame::parse(&replies[0]).unwrap();
        assert_eq!(ethernet.dst_mac, REMOTE_MAC);
        assert_eq!(ethernet.src_mac, LOCAL_MAC);
        let ipv4 = Ipv4Packet::parse(ethernet.payload, true).unwrap();
        assert_eq!(ipv4.header.src_ip, LOCAL_IP);
        assert_eq!(ipv4.header.dst_ip, REMOTE_IP);
        let icmp = IcmpPacket::parse(ipv4.payload, true).unwrap();
        assert_eq!(icmp.icmp_type, IcmpType::ParameterProblem);
        assert_eq!(&ipv4.payload[4..8], &[6, 0, 0, 0]);
    }

    #[test]
    fn netstack_ingress_keeps_icmp_error_suppression() {
        let mut stack = stack();
        let replies =
            stack.process_frame_with_ipv4_errors(&malformed_reserved_flag_frame(IP_PROTO_ICMP));
        assert!(replies.is_empty());
    }

    #[test]
    fn netstack_ingress_falls_back_to_normal_echo_processing() {
        let mut stack = stack();
        let request = IcmpPacket::build_echo_request(7, 9, b"ping");
        let ipv4 = Ipv4Packet::serialize(REMOTE_IP, LOCAL_IP, IP_PROTO_ICMP, 1, 64, &request);
        let frame = EthernetFrame::serialize(LOCAL_MAC, REMOTE_MAC, ETHERTYPE_IPV4, &ipv4);

        let replies = stack.process_frame_with_ipv4_errors(&frame);
        assert_eq!(replies.len(), 1);
        let ethernet = EthernetFrame::parse(&replies[0]).unwrap();
        let ipv4 = Ipv4Packet::parse(ethernet.payload, true).unwrap();
        let icmp = IcmpPacket::parse(ipv4.payload, true).unwrap();
        assert_eq!(icmp.icmp_type, IcmpType::EchoReply);
        assert_eq!(icmp.identifier, 7);
        assert_eq!(icmp.sequence_number, 9);
    }
}
