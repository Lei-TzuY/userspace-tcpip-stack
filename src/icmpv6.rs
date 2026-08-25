//! Layer 3.5: ICMPv6 (RFC 4443) and Neighbor Discovery Protocol (NDP - RFC 4861).
//!
//! Provides Echo Request/Reply (Ping6), Neighbor Solicitation (NS) / Neighbor Advertisement (NA),
//! Router Solicitation (RS) / Router Advertisement (RA), and the in-memory Neighbor Cache (`NdpTable`).

use crate::ethernet::MacAddress;
use crate::ipv6::{Ipv6Address, NEXT_HEADER_ICMPV6, compute_ipv6_transport_checksum};
use std::collections::HashMap;
use std::fmt;

pub const ICMPV6_TYPE_DEST_UNREACHABLE: u8 = 1;
pub const ICMPV6_TYPE_PACKET_TOO_BIG: u8 = 2;
pub const ICMPV6_TYPE_TIME_EXCEEDED: u8 = 3;
pub const ICMPV6_TYPE_ECHO_REQUEST: u8 = 128;
pub const ICMPV6_TYPE_ECHO_REPLY: u8 = 129;
pub const ICMPV6_TYPE_ROUTER_SOLICIT: u8 = 133;
pub const ICMPV6_TYPE_ROUTER_ADVERT: u8 = 134;
pub const ICMPV6_TYPE_NEIGHBOR_SOLICIT: u8 = 135;
pub const ICMPV6_TYPE_NEIGHBOR_ADVERT: u8 = 136;

pub const NDP_OPT_SRC_LINK_LAYER_ADDR: u8 = 1;
pub const NDP_OPT_TARGET_LINK_LAYER_ADDR: u8 = 2;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Icmpv6Packet<'a> {
    pub msg_type: u8,
    pub code: u8,
    pub checksum: u16,
    pub payload: &'a [u8],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Icmpv6Error {
    PacketTooShort(usize),
    InvalidChecksum { found: u16 },
}

impl fmt::Display for Icmpv6Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Icmpv6Error::PacketTooShort(len) => {
                write!(f, "ICMPv6 packet too short ({} bytes, min 4)", len)
            }
            Icmpv6Error::InvalidChecksum { found } => {
                write!(
                    f,
                    "ICMPv6 checksum verification failed with 0x{:04x}",
                    found
                )
            }
        }
    }
}

impl std::error::Error for Icmpv6Error {}

impl<'a> Icmpv6Packet<'a> {
    pub fn parse(
        src_ip: Ipv6Address,
        dst_ip: Ipv6Address,
        data: &'a [u8],
        check_checksum: bool,
    ) -> Result<Self, Icmpv6Error> {
        if data.len() < 4 {
            return Err(Icmpv6Error::PacketTooShort(data.len()));
        }

        let msg_type = data[0];
        let code = data[1];
        let checksum = u16::from_be_bytes([data[2], data[3]]);

        if check_checksum {
            let computed =
                compute_ipv6_transport_checksum(src_ip, dst_ip, NEXT_HEADER_ICMPV6, data);
            if computed != 0 {
                return Err(Icmpv6Error::InvalidChecksum { found: checksum });
            }
        }

        let payload = &data[4..];

        Ok(Icmpv6Packet {
            msg_type,
            code,
            checksum,
            payload,
        })
    }

    /// Builds an ICMPv6 Echo Request (Ping6)
    pub fn build_echo_request(
        src_ip: Ipv6Address,
        dst_ip: Ipv6Address,
        id: u16,
        seq: u16,
        payload: &[u8],
    ) -> Vec<u8> {
        let mut buf = Vec::with_capacity(8 + payload.len());
        buf.push(ICMPV6_TYPE_ECHO_REQUEST);
        buf.push(0); // Code = 0
        buf.extend_from_slice(&[0x00, 0x00]); // Checksum placeholder
        buf.extend_from_slice(&id.to_be_bytes());
        buf.extend_from_slice(&seq.to_be_bytes());
        buf.extend_from_slice(payload);

        let csum = compute_ipv6_transport_checksum(src_ip, dst_ip, NEXT_HEADER_ICMPV6, &buf);
        buf[2..4].copy_from_slice(&csum.to_be_bytes());

        buf
    }

    /// Builds an ICMPv6 Echo Reply (Ping6)
    pub fn build_echo_reply(
        src_ip: Ipv6Address,
        dst_ip: Ipv6Address,
        id: u16,
        seq: u16,
        payload: &[u8],
    ) -> Vec<u8> {
        let mut buf = Vec::with_capacity(8 + payload.len());
        buf.push(ICMPV6_TYPE_ECHO_REPLY);
        buf.push(0); // Code = 0
        buf.extend_from_slice(&[0x00, 0x00]); // Checksum placeholder
        buf.extend_from_slice(&id.to_be_bytes());
        buf.extend_from_slice(&seq.to_be_bytes());
        buf.extend_from_slice(payload);

        let csum = compute_ipv6_transport_checksum(src_ip, dst_ip, NEXT_HEADER_ICMPV6, &buf);
        buf[2..4].copy_from_slice(&csum.to_be_bytes());

        buf
    }

    /// Builds ICMPv6 Destination Unreachable (RFC 4443, Type 1).
    ///
    /// `code` is kept explicit because RFC 4443 defines several independently useful
    /// unreachable reasons (no route, administratively prohibited, address unreachable,
    /// port unreachable, and others). The invoking packet is quoted up to the IPv6
    /// minimum-MTU limit required for ICMPv6 error messages.
    pub fn build_destination_unreachable(
        src_ip: Ipv6Address,
        dst_ip: Ipv6Address,
        code: u8,
        invoking_packet: &[u8],
    ) -> Vec<u8> {
        Self::build_error_message(
            src_ip,
            dst_ip,
            ICMPV6_TYPE_DEST_UNREACHABLE,
            code,
            0,
            invoking_packet,
        )
    }

    /// Builds ICMPv6 Packet Too Big (RFC 4443, Type 2 Code 0).
    ///
    /// The 32-bit `mtu` field tells the sender the maximum packet size accepted by the
    /// constraining link and is the signal IPv6 Path MTU Discovery relies on.
    pub fn build_packet_too_big(
        src_ip: Ipv6Address,
        dst_ip: Ipv6Address,
        mtu: u32,
        invoking_packet: &[u8],
    ) -> Vec<u8> {
        Self::build_error_message(
            src_ip,
            dst_ip,
            ICMPV6_TYPE_PACKET_TOO_BIG,
            0,
            mtu,
            invoking_packet,
        )
    }

    /// Builds ICMPv6 Time Exceeded (RFC 4443, Type 3 Code 0).
    /// The invoking packet is capped so the resulting IPv6 packet fits the
    /// minimum IPv6 MTU of 1280 bytes.
    pub fn build_time_exceeded(
        src_ip: Ipv6Address,
        dst_ip: Ipv6Address,
        invoking_packet: &[u8],
    ) -> Vec<u8> {
        Self::build_error_message(
            src_ip,
            dst_ip,
            ICMPV6_TYPE_TIME_EXCEEDED,
            0,
            0,
            invoking_packet,
        )
    }

    /// Common RFC 4443 error-message framing. Every current ICMPv6 error type has a
    /// four-byte type-specific field after the checksum, followed by as much of the
    /// invoking packet as can fit without making the resulting IPv6 packet exceed the
    /// minimum IPv6 MTU (1280 bytes).
    fn build_error_message(
        src_ip: Ipv6Address,
        dst_ip: Ipv6Address,
        msg_type: u8,
        code: u8,
        type_specific: u32,
        invoking_packet: &[u8],
    ) -> Vec<u8> {
        const MAX_INVOKING_BYTES: usize = 1232; // 1280 - IPv6(40) - ICMPv6(8)
        let quoted = invoking_packet.len().min(MAX_INVOKING_BYTES);
        let mut buf = Vec::with_capacity(8 + quoted);
        buf.push(msg_type);
        buf.push(code);
        buf.extend_from_slice(&[0, 0]);
        buf.extend_from_slice(&type_specific.to_be_bytes());
        buf.extend_from_slice(&invoking_packet[..quoted]);
        let csum = compute_ipv6_transport_checksum(src_ip, dst_ip, NEXT_HEADER_ICMPV6, &buf);
        buf[2..4].copy_from_slice(&csum.to_be_bytes());
        buf
    }

    /// Builds an NDP Neighbor Solicitation (NS - Type 135)
    pub fn build_neighbor_solicitation(
        src_ip: Ipv6Address,
        dst_ip: Ipv6Address,
        target_ip: Ipv6Address,
        sender_mac: MacAddress,
    ) -> Vec<u8> {
        let mut buf = Vec::with_capacity(28); // 4 hdr + 4 reserved + 16 target + 8 opt
        buf.push(ICMPV6_TYPE_NEIGHBOR_SOLICIT);
        buf.push(0); // Code = 0
        buf.extend_from_slice(&[0x00, 0x00]); // Checksum placeholder
        buf.extend_from_slice(&[0, 0, 0, 0]); // Reserved (4 bytes)
        buf.extend_from_slice(&target_ip.0);

        // Source Link-Layer Address Option (Type 1, Len 1 = 8 bytes)
        buf.push(NDP_OPT_SRC_LINK_LAYER_ADDR);
        buf.push(1); // Length in units of 8 octets
        buf.extend_from_slice(&sender_mac.0);

        let csum = compute_ipv6_transport_checksum(src_ip, dst_ip, NEXT_HEADER_ICMPV6, &buf);
        buf[2..4].copy_from_slice(&csum.to_be_bytes());

        buf
    }

    /// Builds an NDP Neighbor Advertisement (NA - Type 136)
    pub fn build_neighbor_advertisement(
        src_ip: Ipv6Address,
        dst_ip: Ipv6Address,
        target_ip: Ipv6Address,
        target_mac: MacAddress,
        is_router: bool,
        solicited: bool,
        override_flag: bool,
    ) -> Vec<u8> {
        let mut buf = Vec::with_capacity(28);
        buf.push(ICMPV6_TYPE_NEIGHBOR_ADVERT);
        buf.push(0); // Code = 0
        buf.extend_from_slice(&[0x00, 0x00]); // Checksum placeholder

        // Flags: R (Router = 0x80), S (Solicited = 0x40), O (Override = 0x20)
        let mut flags = 0u8;
        if is_router {
            flags |= 0x80;
        }
        if solicited {
            flags |= 0x40;
        }
        if override_flag {
            flags |= 0x20;
        }

        buf.push(flags);
        buf.extend_from_slice(&[0, 0, 0]); // Reserved (3 bytes)
        buf.extend_from_slice(&target_ip.0);

        // Target Link-Layer Address Option (Type 2, Len 1 = 8 bytes)
        buf.push(NDP_OPT_TARGET_LINK_LAYER_ADDR);
        buf.push(1);
        buf.extend_from_slice(&target_mac.0);

        let csum = compute_ipv6_transport_checksum(src_ip, dst_ip, NEXT_HEADER_ICMPV6, &buf);
        buf[2..4].copy_from_slice(&csum.to_be_bytes());

        buf
    }
}

/// Dynamic Neighbor Cache Table (IPv6 NDP equivalent of ARP Cache)
#[derive(Debug, Clone, Default)]
pub struct NdpTable {
    entries: HashMap<Ipv6Address, MacAddress>,
}

impl NdpTable {
    pub fn new() -> Self {
        NdpTable {
            entries: HashMap::new(),
        }
    }

    pub fn insert(&mut self, ip: Ipv6Address, mac: MacAddress) {
        self.entries.insert(ip, mac);
    }

    pub fn lookup(&self, ip: &Ipv6Address) -> Option<MacAddress> {
        self.entries.get(ip).copied()
    }

    pub fn entries(&self) -> &HashMap<Ipv6Address, MacAddress> {
        &self.entries
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn test_icmpv6_echo_request_and_reply() {
        let src = Ipv6Address::from_str("2001:db8::1").unwrap();
        let dst = Ipv6Address::from_str("2001:db8::2").unwrap();
        let payload = b"Ping6 test message";

        let raw_req = Icmpv6Packet::build_echo_request(src, dst, 0x1234, 1, payload);
        let parsed_req = Icmpv6Packet::parse(src, dst, &raw_req, true).unwrap();

        assert_eq!(parsed_req.msg_type, ICMPV6_TYPE_ECHO_REQUEST);
        assert_eq!(parsed_req.code, 0);

        let raw_reply = Icmpv6Packet::build_echo_reply(dst, src, 0x1234, 1, payload);
        let parsed_reply = Icmpv6Packet::parse(dst, src, &raw_reply, true).unwrap();

        assert_eq!(parsed_reply.msg_type, ICMPV6_TYPE_ECHO_REPLY);
        assert_eq!(parsed_reply.code, 0);
    }

    #[test]
    fn test_icmpv6_error_messages_checksum_fields_and_quote_limit() {
        let router = Ipv6Address::from_str("2001:db8::1").unwrap();
        let host = Ipv6Address::from_str("2001:db8::2").unwrap();
        let invoking = vec![0x5a; 1600];

        let unreachable =
            Icmpv6Packet::build_destination_unreachable(router, host, 0, &invoking);
        let parsed = Icmpv6Packet::parse(router, host, &unreachable, true).unwrap();
        assert_eq!(parsed.msg_type, ICMPV6_TYPE_DEST_UNREACHABLE);
        assert_eq!(parsed.code, 0);
        assert_eq!(&parsed.payload[..4], &[0, 0, 0, 0]);
        assert_eq!(unreachable.len(), 1240);
        assert_eq!(&parsed.payload[4..], &invoking[..1232]);

        let too_big = Icmpv6Packet::build_packet_too_big(router, host, 1280, &invoking);
        let parsed = Icmpv6Packet::parse(router, host, &too_big, true).unwrap();
        assert_eq!(parsed.msg_type, ICMPV6_TYPE_PACKET_TOO_BIG);
        assert_eq!(parsed.code, 0);
        assert_eq!(u32::from_be_bytes(parsed.payload[..4].try_into().unwrap()), 1280);
        assert_eq!(too_big.len(), 1240);
        assert_eq!(&parsed.payload[4..], &invoking[..1232]);

        let exceeded = Icmpv6Packet::build_time_exceeded(router, host, &invoking);
        let parsed = Icmpv6Packet::parse(router, host, &exceeded, true).unwrap();
        assert_eq!(parsed.msg_type, ICMPV6_TYPE_TIME_EXCEEDED);
        assert_eq!(parsed.code, 0);
        assert_eq!(&parsed.payload[..4], &[0, 0, 0, 0]);
        assert_eq!(exceeded.len(), 1240);
    }

    #[test]
    fn test_ndp_neighbor_solicitation_and_advertisement() {
        let client_ip = Ipv6Address::from_str("fe80::1").unwrap();
        let client_mac = MacAddress([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        let server_ip = Ipv6Address::from_str("fe80::2").unwrap();
        let server_mac = MacAddress([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);

        let ns =
            Icmpv6Packet::build_neighbor_solicitation(client_ip, server_ip, server_ip, client_mac);
        let parsed_ns = Icmpv6Packet::parse(client_ip, server_ip, &ns, true).unwrap();
        assert_eq!(parsed_ns.msg_type, ICMPV6_TYPE_NEIGHBOR_SOLICIT);

        let na = Icmpv6Packet::build_neighbor_advertisement(
            server_ip, client_ip, server_ip, server_mac, false, true, true,
        );
        let parsed_na = Icmpv6Packet::parse(server_ip, client_ip, &na, true).unwrap();
        assert_eq!(parsed_na.msg_type, ICMPV6_TYPE_NEIGHBOR_ADVERT);

        let mut ndp_table = NdpTable::new();
        ndp_table.insert(server_ip, server_mac);
        assert_eq!(ndp_table.lookup(&server_ip), Some(server_mac));
    }
}
