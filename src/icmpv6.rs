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
pub const NDP_OPT_PREFIX_INFORMATION: u8 = 3;

/// RFC 4861 Neighbor Unreachability Detection defaults. Reachable Time is
/// normally randomized around BaseReachableTime; this deterministic simulator
/// selects the 1.0 random factor so timer-driven behavior is reproducible.
pub const NDP_REACHABLE_TIME_MS: u64 = 30_000;
pub const NDP_DELAY_FIRST_PROBE_TIME_MS: u64 = 5_000;
pub const NDP_RETRANS_TIMER_MS: u64 = 1_000;
pub const NDP_MAX_UNICAST_SOLICIT: u8 = 3;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PrefixInformationOption {
    pub prefix_length: u8,
    pub on_link: bool,
    pub autonomous: bool,
    pub valid_lifetime: u32,
    pub preferred_lifetime: u32,
    pub prefix: Ipv6Address,
}

impl PrefixInformationOption {
    pub fn new(
        prefix: Ipv6Address,
        prefix_length: u8,
        on_link: bool,
        autonomous: bool,
        valid_lifetime: u32,
        preferred_lifetime: u32,
    ) -> Self {
        let prefix_length = prefix_length.min(128);
        PrefixInformationOption {
            prefix_length,
            on_link,
            autonomous,
            valid_lifetime,
            preferred_lifetime: preferred_lifetime.min(valid_lifetime),
            prefix: prefix.mask(prefix_length),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum RouterPreference {
    Low,
    Medium,
    High,
}

impl RouterPreference {
    fn from_ra_flags(flags: u8) -> Self {
        match (flags >> 3) & 0x03 {
            0x01 => Self::High,
            0x03 => Self::Low,
            // RFC 4191: the reserved 10 value MUST be treated as Medium.
            _ => Self::Medium,
        }
    }

    fn ra_flags(self) -> u8 {
        match self {
            Self::High => 0x08,
            Self::Medium => 0x00,
            Self::Low => 0x18,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouterAdvertisement {
    pub current_hop_limit: u8,
    pub managed: bool,
    pub other_config: bool,
    pub preference: RouterPreference,
    pub router_lifetime: u16,
    pub reachable_time: u32,
    pub retrans_timer: u32,
    pub prefixes: Vec<PrefixInformationOption>,
}

/// RFC 2464 IPv6 multicast-to-Ethernet mapping.
pub fn ipv6_multicast_mac(address: Ipv6Address) -> Option<MacAddress> {
    if !address.is_multicast() {
        return None;
    }
    Some(MacAddress([
        0x33,
        0x33,
        address.0[12],
        address.0[13],
        address.0[14],
        address.0[15],
    ]))
}

/// Derives a 64-bit modified EUI-64 interface identifier for SLAAC.
pub fn slaac_address(
    prefix: Ipv6Address,
    prefix_length: u8,
    mac: MacAddress,
) -> Option<Ipv6Address> {
    if prefix_length != 64 {
        return None;
    }
    let mut bytes = prefix.mask(64).0;
    bytes[8] = mac.0[0] ^ 0x02;
    bytes[9] = mac.0[1];
    bytes[10] = mac.0[2];
    bytes[11] = 0xff;
    bytes[12] = 0xfe;
    bytes[13] = mac.0[3];
    bytes[14] = mac.0[4];
    bytes[15] = mac.0[5];
    Some(Ipv6Address(bytes))
}

pub fn link_local_address(mac: MacAddress) -> Ipv6Address {
    slaac_address(Ipv6Address::new([0xfe80, 0, 0, 0, 0, 0, 0, 0]), 64, mac)
        .expect("/64 link-local SLAAC prefix")
}

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

fn ndp_options_well_formed(options: &[u8]) -> bool {
    let mut offset = 0usize;
    while offset < options.len() {
        if options.len() - offset < 2 {
            return false;
        }
        let units = options[offset + 1] as usize;
        if units == 0 {
            return false;
        }
        let Some(option_len) = units.checked_mul(8) else {
            return false;
        };
        let Some(end) = offset.checked_add(option_len) else {
            return false;
        };
        if end > options.len() {
            return false;
        }
        offset = end;
    }
    true
}

fn ndp_options_contain(options: &[u8], option_type: u8) -> bool {
    let mut offset = 0usize;
    while offset < options.len() {
        let units = options[offset + 1] as usize;
        let option_len = units * 8;
        if options[offset] == option_type {
            return true;
        }
        offset += option_len;
    }
    false
}

/// RFC 2464 section 6 fixes Source/Target Link-Layer Address options to one
/// 8-octet unit on Ethernet. Validate only the LLA option relevant to the
/// current NDP message; RFC 4861 requires options that do not belong to that
/// message type to be ignored rather than turning the whole packet invalid.
fn ndp_ethernet_lla_option_length_valid(options: &[u8], option_type: u8) -> bool {
    let mut offset = 0usize;
    while offset < options.len() {
        if options.len() - offset < 2 {
            return false;
        }
        let units = options[offset + 1] as usize;
        if units == 0 {
            return false;
        }
        let Some(option_len) = units.checked_mul(8) else {
            return false;
        };
        let Some(end) = offset.checked_add(option_len) else {
            return false;
        };
        if end > options.len() {
            return false;
        }
        if options[offset] == option_type && units != 1 {
            return false;
        }
        offset = end;
    }
    true
}

/// Extracts an Ethernet Source/Target Link-Layer Address option from an already
/// validated NDP option list. RFC 2464 fixes Ethernet LLA options at one 8-octet
/// unit; malformed or truncated lists deliberately yield no cache hint.
fn ndp_ethernet_link_layer_address(options: &[u8], option_type: u8) -> Option<MacAddress> {
    let mut offset = 0usize;
    while offset < options.len() {
        if options.len() - offset < 2 {
            return None;
        }
        let units = options[offset + 1] as usize;
        if units == 0 {
            return None;
        }
        let option_len = units.checked_mul(8)?;
        let end = offset.checked_add(option_len)?;
        if end > options.len() {
            return None;
        }
        if options[offset] == option_type {
            if option_len != 8 {
                return None;
            }
            return Some(MacAddress([
                options[offset + 2],
                options[offset + 3],
                options[offset + 4],
                options[offset + 5],
                options[offset + 6],
                options[offset + 7],
            ]));
        }
        offset = end;
    }
    None
}

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

    /// Validates an RFC 4861 Neighbor Solicitation and returns its Target Address.
    ///
    /// The checks here are deliberately performed before a caller learns the sender
    /// into its Neighbor Cache: off-link or malformed NDP must not become a cache hint.
    pub fn validated_neighbor_solicitation_target(
        &self,
        src_ip: Ipv6Address,
        dst_ip: Ipv6Address,
        hop_limit: u8,
    ) -> Option<Ipv6Address> {
        if self.msg_type != ICMPV6_TYPE_NEIGHBOR_SOLICIT
            || self.code != 0
            || hop_limit != 255
            || self.payload.len() < 20
        {
            return None;
        }

        let mut target = [0u8; 16];
        target.copy_from_slice(&self.payload[4..20]);
        let target = Ipv6Address(target);
        if target.is_multicast()
            || !ndp_options_well_formed(&self.payload[20..])
            || !ndp_ethernet_lla_option_length_valid(
                &self.payload[20..],
                NDP_OPT_SRC_LINK_LAYER_ADDR,
            )
        {
            return None;
        }

        // RFC 4861 section 7.1.1 / RFC 4862 DAD: an unspecified-source NS
        // must target the solicited-node multicast address and must omit SLLA.
        if src_ip.is_unspecified()
            && (dst_ip != target.solicited_node_multicast()
                || ndp_options_contain(&self.payload[20..], NDP_OPT_SRC_LINK_LAYER_ADDR))
        {
            return None;
        }

        Some(target)
    }

    /// Validates an RFC 4861 Neighbor Advertisement and returns its Target Address.
    pub fn validated_neighbor_advertisement_target(
        &self,
        dst_ip: Ipv6Address,
        hop_limit: u8,
    ) -> Option<Ipv6Address> {
        if self.msg_type != ICMPV6_TYPE_NEIGHBOR_ADVERT
            || self.code != 0
            || hop_limit != 255
            || self.payload.len() < 20
        {
            return None;
        }

        let mut target = [0u8; 16];
        target.copy_from_slice(&self.payload[4..20]);
        let target = Ipv6Address(target);
        if target.is_multicast()
            || !ndp_options_well_formed(&self.payload[20..])
            || !ndp_ethernet_lla_option_length_valid(
                &self.payload[20..],
                NDP_OPT_TARGET_LINK_LAYER_ADDR,
            )
        {
            return None;
        }

        let solicited = self.payload[0] & 0x40 != 0;
        if dst_ip.is_multicast() && solicited {
            return None;
        }

        Some(target)
    }

    /// Returns the Ethernet Target Link-Layer Address carried by a Neighbor
    /// Advertisement, if present. Callers should validate the advertisement
    /// before using this accessor.
    pub fn neighbor_advertisement_target_link_layer_address(&self) -> Option<MacAddress> {
        if self.msg_type != ICMPV6_TYPE_NEIGHBOR_ADVERT || self.payload.len() < 20 {
            return None;
        }
        ndp_ethernet_link_layer_address(&self.payload[20..], NDP_OPT_TARGET_LINK_LAYER_ADDR)
    }

    /// Returns the Ethernet Source Link-Layer Address option carried by an NS,
    /// RS, or RA. Absence is meaningful: RFC 4861 does not permit callers to
    /// synthesize a Neighbor Cache mapping from the enclosing Ethernet header.
    pub fn ndp_source_link_layer_address(&self) -> Option<MacAddress> {
        let options = match self.msg_type {
            ICMPV6_TYPE_NEIGHBOR_SOLICIT if self.payload.len() >= 20 => &self.payload[20..],
            ICMPV6_TYPE_ROUTER_SOLICIT if self.payload.len() >= 4 => &self.payload[4..],
            ICMPV6_TYPE_ROUTER_ADVERT if self.payload.len() >= 12 => &self.payload[12..],
            _ => return None,
        };
        ndp_ethernet_link_layer_address(options, NDP_OPT_SRC_LINK_LAYER_ADDR)
    }

    /// Validates an RFC 4861 Router Solicitation before a router uses
    /// the packet as a Neighbor Cache hint or generates a Router Advertisement.
    pub fn is_valid_router_solicitation(&self, src_ip: Ipv6Address, hop_limit: u8) -> bool {
        if self.msg_type != ICMPV6_TYPE_ROUTER_SOLICIT
            || self.code != 0
            || hop_limit != 255
            || self.payload.len() < 4
            || !ndp_options_well_formed(&self.payload[4..])
            || !ndp_ethernet_lla_option_length_valid(
                &self.payload[4..],
                NDP_OPT_SRC_LINK_LAYER_ADDR,
            )
        {
            return false;
        }

        // RFC 4861 section 6.1.1: initial RS packets sourced from :: MUST NOT
        // include the Source Link-Layer Address option.
        !(src_ip.is_unspecified()
            && ndp_options_contain(&self.payload[4..], NDP_OPT_SRC_LINK_LAYER_ADDR))
    }

    /// Validates an RFC 4861 Router Advertisement and returns the parsed body.
    /// Callers use this before Neighbor Cache learning so an off-link or malformed
    /// advertisement cannot leave cache state behind.
    pub fn validated_router_advertisement(
        &self,
        src_ip: Ipv6Address,
        hop_limit: u8,
    ) -> Option<RouterAdvertisement> {
        if self.msg_type != ICMPV6_TYPE_ROUTER_ADVERT
            || self.code != 0
            || hop_limit != 255
            || !src_ip.is_link_local()
            || self.payload.len() < 12
            || !ndp_options_well_formed(&self.payload[12..])
            || !ndp_ethernet_lla_option_length_valid(
                &self.payload[12..],
                NDP_OPT_SRC_LINK_LAYER_ADDR,
            )
        {
            return None;
        }
        RouterAdvertisement::parse(self)
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

    /// Builds an NDP Router Solicitation (RFC 4861, Type 133).
    /// A source link-layer option is omitted for an unspecified source address,
    /// as required during initial host configuration.
    pub fn build_router_solicitation(
        src_ip: Ipv6Address,
        dst_ip: Ipv6Address,
        source_mac: Option<MacAddress>,
    ) -> Vec<u8> {
        let include_slla = !src_ip.is_unspecified() && source_mac.is_some();
        let mut buf = Vec::with_capacity(if include_slla { 16 } else { 8 });
        buf.push(ICMPV6_TYPE_ROUTER_SOLICIT);
        buf.push(0);
        buf.extend_from_slice(&[0, 0]);
        buf.extend_from_slice(&[0, 0, 0, 0]);
        if include_slla {
            let mac = source_mac.unwrap();
            buf.push(NDP_OPT_SRC_LINK_LAYER_ADDR);
            buf.push(1);
            buf.extend_from_slice(&mac.0);
        }
        let csum = compute_ipv6_transport_checksum(src_ip, dst_ip, NEXT_HEADER_ICMPV6, &buf);
        buf[2..4].copy_from_slice(&csum.to_be_bytes());
        buf
    }

    /// Builds an NDP Router Advertisement (RFC 4861, Type 134) carrying one or
    /// more Prefix Information Options (RFC 4861 section 4.6.2).
    pub fn build_router_advertisement(
        src_ip: Ipv6Address,
        dst_ip: Ipv6Address,
        current_hop_limit: u8,
        router_lifetime: u16,
        prefixes: &[PrefixInformationOption],
        source_mac: Option<MacAddress>,
    ) -> Vec<u8> {
        Self::build_router_advertisement_with_preference(
            src_ip,
            dst_ip,
            current_hop_limit,
            router_lifetime,
            RouterPreference::Medium,
            prefixes,
            source_mac,
        )
    }

    /// RFC 4191-aware Router Advertisement builder. The legacy builder above
    /// remains source-compatible and advertises the default Medium preference.
    pub fn build_router_advertisement_with_preference(
        src_ip: Ipv6Address,
        dst_ip: Ipv6Address,
        current_hop_limit: u8,
        router_lifetime: u16,
        preference: RouterPreference,
        prefixes: &[PrefixInformationOption],
        source_mac: Option<MacAddress>,
    ) -> Vec<u8> {
        let mut buf =
            Vec::with_capacity(16 + prefixes.len() * 32 + usize::from(source_mac.is_some()) * 8);
        buf.push(ICMPV6_TYPE_ROUTER_ADVERT);
        buf.push(0);
        buf.extend_from_slice(&[0, 0]);
        buf.push(current_hop_limit);
        buf.push(preference.ra_flags()); // M=0, O=0, RFC 4191 Prf in bits 4..3
        buf.extend_from_slice(&router_lifetime.to_be_bytes());
        buf.extend_from_slice(&0u32.to_be_bytes()); // Reachable Time
        buf.extend_from_slice(&0u32.to_be_bytes()); // Retrans Timer

        if let Some(mac) = source_mac {
            buf.push(NDP_OPT_SRC_LINK_LAYER_ADDR);
            buf.push(1);
            buf.extend_from_slice(&mac.0);
        }

        for prefix in prefixes {
            buf.push(NDP_OPT_PREFIX_INFORMATION);
            buf.push(4); // 32 octets
            buf.push(prefix.prefix_length);
            let mut flags = 0u8;
            if prefix.on_link {
                flags |= 0x80;
            }
            if prefix.autonomous {
                flags |= 0x40;
            }
            buf.push(flags);
            buf.extend_from_slice(&prefix.valid_lifetime.to_be_bytes());
            buf.extend_from_slice(&prefix.preferred_lifetime.to_be_bytes());
            buf.extend_from_slice(&0u32.to_be_bytes());
            buf.extend_from_slice(&prefix.prefix.mask(prefix.prefix_length).0);
        }

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

    /// Builds the Neighbor Solicitation used by Duplicate Address Detection
    /// (RFC 4862 section 5.4.2). DAD uses the unspecified source address and MUST
    /// omit the Source Link-Layer Address option.
    pub fn build_dad_neighbor_solicitation(dst_ip: Ipv6Address, target_ip: Ipv6Address) -> Vec<u8> {
        let src_ip = Ipv6Address::UNSPECIFIED;
        let mut buf = Vec::with_capacity(24);
        buf.push(ICMPV6_TYPE_NEIGHBOR_SOLICIT);
        buf.push(0);
        buf.extend_from_slice(&[0, 0]);
        buf.extend_from_slice(&[0, 0, 0, 0]);
        buf.extend_from_slice(&target_ip.0);
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

impl RouterAdvertisement {
    /// Parses the body of an already checksum-validated ICMPv6 Router Advertisement.
    /// Unknown NDP options are skipped according to their encoded length.
    pub fn parse(icmp: &Icmpv6Packet<'_>) -> Option<Self> {
        if icmp.msg_type != ICMPV6_TYPE_ROUTER_ADVERT || icmp.code != 0 || icmp.payload.len() < 12 {
            return None;
        }
        let payload = icmp.payload;
        let current_hop_limit = payload[0];
        let flags = payload[1];
        let preference = RouterPreference::from_ra_flags(flags);
        let router_lifetime = u16::from_be_bytes([payload[2], payload[3]]);
        let reachable_time = u32::from_be_bytes(payload[4..8].try_into().ok()?);
        let retrans_timer = u32::from_be_bytes(payload[8..12].try_into().ok()?);
        let mut prefixes = Vec::new();
        let mut offset = 12usize;
        while offset < payload.len() {
            if offset + 2 > payload.len() {
                return None;
            }
            let option_type = payload[offset];
            let units = payload[offset + 1] as usize;
            if units == 0 {
                return None;
            }
            let option_len = units * 8;
            if offset + option_len > payload.len() {
                return None;
            }
            if option_type == NDP_OPT_PREFIX_INFORMATION {
                if option_len != 32 {
                    return None;
                }
                let option = &payload[offset..offset + option_len];
                let prefix_length = option[2];
                if prefix_length > 128 {
                    return None;
                }
                let option_flags = option[3];
                let valid_lifetime = u32::from_be_bytes(option[4..8].try_into().ok()?);
                let preferred_lifetime = u32::from_be_bytes(option[8..12].try_into().ok()?);
                if preferred_lifetime > valid_lifetime {
                    offset += option_len;
                    continue;
                }
                let mut prefix_bytes = [0u8; 16];
                prefix_bytes.copy_from_slice(&option[16..32]);
                prefixes.push(PrefixInformationOption::new(
                    Ipv6Address(prefix_bytes),
                    prefix_length,
                    option_flags & 0x80 != 0,
                    option_flags & 0x40 != 0,
                    valid_lifetime,
                    preferred_lifetime,
                ));
            }
            offset += option_len;
        }
        Some(RouterAdvertisement {
            current_hop_limit,
            managed: flags & 0x80 != 0,
            other_config: flags & 0x40 != 0,
            preference,
            router_lifetime,
            reachable_time,
            retrans_timer,
            prefixes,
        })
    }
}

/// RFC 4861 Neighbor Unreachability Detection state for a resolved neighbor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NeighborState {
    Reachable,
    Stale,
    Delay,
    Probe,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct NudMetadata {
    state: NeighborState,
    deadline_ms: Option<u64>,
    probes_sent: u8,
}

/// Dynamic Neighbor Cache Table (IPv6 NDP equivalent of ARP Cache).
///
/// The existing MAC map API remains source-compatible. Direct `insert`
/// calls are static/external mappings and therefore do not age; protocol
/// paths opt into timed NUD with `learn_stale` and `confirm_reachable`.
#[derive(Debug, Clone, Default)]
pub struct NdpTable {
    entries: HashMap<Ipv6Address, MacAddress>,
    nud: HashMap<Ipv6Address, NudMetadata>,
}

impl NdpTable {
    pub fn new() -> Self {
        NdpTable {
            entries: HashMap::new(),
            nud: HashMap::new(),
        }
    }

    pub fn insert(&mut self, ip: Ipv6Address, mac: MacAddress) {
        self.entries.insert(ip, mac);
        self.nud.remove(&ip);
    }

    /// Learns link-layer information without positive reachability evidence.
    /// An unchanged mapping preserves its current NUD state; a new or changed
    /// mapping becomes STALE.
    pub fn learn_stale(&mut self, ip: Ipv6Address, mac: MacAddress) {
        if self.entries.get(&ip).is_some_and(|current| *current == mac) {
            return;
        }
        self.mark_stale(ip, mac);
    }

    pub fn mark_stale(&mut self, ip: Ipv6Address, mac: MacAddress) {
        self.entries.insert(ip, mac);
        self.nud.insert(
            ip,
            NudMetadata {
                state: NeighborState::Stale,
                deadline_ms: None,
                probes_sent: 0,
            },
        );
    }

    /// Demotes a dynamically REACHABLE neighbor to STALE without changing
    /// its link-layer address. Static/external mappings are deliberately
    /// left untouched.
    pub fn demote_reachable_preserving_mac(&mut self, ip: Ipv6Address) -> bool {
        let Some(meta) = self.nud.get_mut(&ip) else {
            return false;
        };
        if meta.state != NeighborState::Reachable {
            return false;
        }
        meta.state = NeighborState::Stale;
        meta.deadline_ms = None;
        meta.probes_sent = 0;
        true
    }

    /// Records positive reachability confirmation, such as a solicited NA.
    pub fn confirm_reachable(&mut self, ip: Ipv6Address, mac: MacAddress, now_ms: u64) {
        self.entries.insert(ip, mac);
        self.nud.insert(
            ip,
            NudMetadata {
                state: NeighborState::Reachable,
                deadline_ms: Some(now_ms.saturating_add(NDP_REACHABLE_TIME_MS)),
                probes_sent: 0,
            },
        );
    }

    pub fn lookup(&self, ip: &Ipv6Address) -> Option<MacAddress> {
        self.entries.get(ip).copied()
    }

    /// Returns a mapping for transmission and performs first-use STALE -> DELAY.
    pub fn lookup_for_transmit(&mut self, ip: &Ipv6Address, now_ms: u64) -> Option<MacAddress> {
        let mac = self.entries.get(ip).copied()?;
        if let Some(meta) = self.nud.get_mut(ip) {
            if meta.state == NeighborState::Reachable
                && meta.deadline_ms.is_some_and(|deadline| now_ms >= deadline)
            {
                meta.state = NeighborState::Stale;
                meta.deadline_ms = None;
                meta.probes_sent = 0;
            }
            if meta.state == NeighborState::Stale {
                meta.state = NeighborState::Delay;
                meta.deadline_ms = Some(now_ms.saturating_add(NDP_DELAY_FIRST_PROBE_TIME_MS));
                meta.probes_sent = 0;
            }
        }
        Some(mac)
    }

    pub fn state(&self, ip: &Ipv6Address) -> Option<NeighborState> {
        self.entries.get(ip)?;
        Some(
            self.nud
                .get(ip)
                .map(|meta| meta.state)
                .unwrap_or(NeighborState::Reachable),
        )
    }

    /// Advances NUD timers and returns due unicast probes as (target, MAC).
    /// Coarse time jumps emit at most one probe per neighbor per timer pump.
    pub fn step_nud(&mut self, now_ms: u64) -> Vec<(Ipv6Address, MacAddress)> {
        let keys: Vec<Ipv6Address> = self.nud.keys().copied().collect();
        let mut probes = Vec::new();
        let mut remove = Vec::new();

        for ip in keys {
            let Some(meta) = self.nud.get_mut(&ip) else {
                continue;
            };
            let Some(mac) = self.entries.get(&ip).copied() else {
                remove.push(ip);
                continue;
            };

            if meta.state == NeighborState::Reachable
                && meta.deadline_ms.is_some_and(|deadline| now_ms >= deadline)
            {
                meta.state = NeighborState::Stale;
                meta.deadline_ms = None;
                meta.probes_sent = 0;
                continue;
            }

            let due = meta.deadline_ms.is_some_and(|deadline| now_ms >= deadline);
            match meta.state {
                NeighborState::Delay if due => {
                    meta.state = NeighborState::Probe;
                    meta.probes_sent = 1;
                    meta.deadline_ms = Some(now_ms.saturating_add(NDP_RETRANS_TIMER_MS));
                    probes.push((ip, mac));
                }
                NeighborState::Probe if due => {
                    if meta.probes_sent < NDP_MAX_UNICAST_SOLICIT {
                        meta.probes_sent = meta.probes_sent.saturating_add(1);
                        meta.deadline_ms = Some(now_ms.saturating_add(NDP_RETRANS_TIMER_MS));
                        probes.push((ip, mac));
                    } else {
                        remove.push(ip);
                    }
                }
                _ => {}
            }
        }

        for ip in remove {
            self.entries.remove(&ip);
            self.nud.remove(&ip);
        }
        probes
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

        let unreachable = Icmpv6Packet::build_destination_unreachable(router, host, 0, &invoking);
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
        assert_eq!(
            u32::from_be_bytes(parsed.payload[..4].try_into().unwrap()),
            1280
        );
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
