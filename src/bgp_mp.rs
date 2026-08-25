//! Multiprotocol reachability attributes (RFC 4760), including the RFC 2545
//! wire representation used by IPv6 Unicast.
//!
//! BGP-4 as written in RFC 4271 can only describe IPv4 unicast: the NEXT_HOP
//! attribute is four bytes and the NLRI field at the end of an UPDATE is a bare
//! list of IPv4 prefixes. RFC 4760 adds two optional non-transitive attributes
//! that carry any other family inside the same UPDATE message:
//!
//! ```text
//! MP_REACH_NLRI   (14)  AFI | SAFI | next-hop len | next-hop | reserved | NLRI
//! MP_UNREACH_NLRI (15)  AFI | SAFI | withdrawn NLRI
//! ```

use crate::bgp::{BGP_SUB_ATTRIBUTE_LENGTH_ERROR, BGP_SUB_INVALID_NETWORK_FIELD, BgpParseError};
use crate::bgp_caps::AfiSafi;
use crate::ipv4::Ipv4Address;
use crate::ipv6::Ipv6Address;
use std::fmt;

/// MP_REACH_NLRI path attribute type code (RFC 4760).
pub const BGP_ATTR_MP_REACH_NLRI: u8 = 14;
/// MP_UNREACH_NLRI path attribute type code (RFC 4760).
pub const BGP_ATTR_MP_UNREACH_NLRI: u8 = 15;
/// Extended Communities path attribute type code (RFC 4360).
pub const BGP_ATTR_EXT_COMMUNITIES: u8 = 16;
/// AS4_PATH path attribute type code (RFC 6793).
pub const BGP_ATTR_AS4_PATH: u8 = 17;

/// Largest NLRI payload accepted inside one MP attribute. A BGP message is capped
/// at 4096 bytes, so a longer claim is impossible on a real session.
pub const MAX_MP_NLRI_BYTES: usize = 4_096;

/// One IPv6-Unicast prefix as encoded in RFC 2545 / RFC 4760 NLRI.
///
/// Host bits are canonicalised to zero, so two encodings of the same prefix are
/// equal even if the final on-wire octet contains non-prefix bits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Ipv6UnicastPrefix {
    pub address: Ipv6Address,
    pub length: u8,
}

impl Ipv6UnicastPrefix {
    pub fn new(address: Ipv6Address, length: u8) -> Self {
        let length = length.min(128);
        Self {
            address: mask_ipv6(address, length),
            length,
        }
    }

    pub fn contains(&self, address: Ipv6Address) -> bool {
        mask_ipv6(address, self.length) == self.address
    }

    pub fn encoded_len(&self) -> usize {
        1 + self.length.div_ceil(8) as usize
    }

    pub fn encode(&self, out: &mut Vec<u8>) {
        let octets = self.length.div_ceil(8) as usize;
        out.push(self.length);
        out.extend_from_slice(&self.address.0[..octets]);
    }

    /// Decodes a complete IPv6-Unicast MP-BGP NLRI list.
    pub fn decode_list(data: &[u8]) -> Result<Vec<Self>, BgpParseError> {
        let mut out = Vec::new();
        let mut offset = 0usize;
        while offset < data.len() {
            let bits = data[offset];
            if bits > 128 {
                return Err(BgpParseError::update(
                    BGP_SUB_INVALID_NETWORK_FIELD,
                    format!("IPv6 prefix length {} exceeds 128 bits", bits),
                ));
            }
            let octets = bits.div_ceil(8) as usize;
            if offset + 1 + octets > data.len() {
                return Err(BgpParseError::update(
                    BGP_SUB_INVALID_NETWORK_FIELD,
                    "truncated IPv6 prefix in MP-BGP NLRI list",
                ));
            }
            let mut address = [0u8; 16];
            address[..octets].copy_from_slice(&data[offset + 1..offset + 1 + octets]);
            out.push(Self::new(Ipv6Address(address), bits));
            offset += 1 + octets;
        }
        Ok(out)
    }
}

impl fmt::Display for Ipv6UnicastPrefix {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.address, self.length)
    }
}

fn mask_ipv6(address: Ipv6Address, length: u8) -> Ipv6Address {
    let length = length.min(128);
    let mut bytes = address.0;
    let full_octets = (length / 8) as usize;
    let remaining = length % 8;
    if remaining != 0 && full_octets < 16 {
        bytes[full_octets] &= 0xff << (8 - remaining);
    }
    let clear_from = full_octets + usize::from(remaining != 0);
    for byte in &mut bytes[clear_from..] {
        *byte = 0;
    }
    Ipv6Address(bytes)
}

pub fn encode_ipv6_unicast_nlri(prefixes: &[Ipv6UnicastPrefix]) -> Vec<u8> {
    let mut out = Vec::with_capacity(prefixes.iter().map(Ipv6UnicastPrefix::encoded_len).sum());
    for prefix in prefixes {
        prefix.encode(&mut out);
    }
    out
}

/// A decoded MP_REACH_NLRI attribute.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MpReachNlri {
    pub afi: u16,
    pub safi: u8,
    /// Next hop exactly as it appeared on the wire. Its length is family-defined:
    /// 4 bytes for an IPv4 VTEP, 16/32 for IPv6, 12 for VPN-IPv4.
    pub next_hop: Vec<u8>,
    /// The family's own NLRI encoding, undecoded.
    pub nlri: Vec<u8>,
}

impl MpReachNlri {
    pub fn new(family: AfiSafi, next_hop: Vec<u8>, nlri: Vec<u8>) -> Self {
        Self {
            afi: family.afi,
            safi: family.safi,
            next_hop,
            nlri,
        }
    }

    /// An MP_REACH for a family whose next hop is a single IPv4 address, which is
    /// how EVPN over a VXLAN underlay identifies the advertising VTEP.
    pub fn with_ipv4_next_hop(family: AfiSafi, next_hop: Ipv4Address, nlri: Vec<u8>) -> Self {
        Self::new(family, next_hop.0.to_vec(), nlri)
    }

    /// RFC 2545 IPv6 next hop. A 16-byte value carries only the global address;
    /// a 32-byte value carries global followed by link-local.
    pub fn with_ipv6_next_hop(
        family: AfiSafi,
        global: Ipv6Address,
        link_local: Option<Ipv6Address>,
        nlri: Vec<u8>,
    ) -> Self {
        let mut next_hop = Vec::with_capacity(if link_local.is_some() { 32 } else { 16 });
        next_hop.extend_from_slice(&global.0);
        if let Some(link_local) = link_local {
            next_hop.extend_from_slice(&link_local.0);
        }
        Self::new(family, next_hop, nlri)
    }

    pub fn family(&self) -> AfiSafi {
        AfiSafi::new(self.afi, self.safi)
    }

    /// The next hop read as an IPv4 address, or `None` if it is not an IPv4 shape.
    pub fn ipv4_next_hop(&self) -> Option<Ipv4Address> {
        match self.next_hop.len() {
            4 => Some(Ipv4Address([
                self.next_hop[0],
                self.next_hop[1],
                self.next_hop[2],
                self.next_hop[3],
            ])),
            // RFC 4364 VPN next hop: 8-byte RD followed by address.
            12 => Some(Ipv4Address([
                self.next_hop[8],
                self.next_hop[9],
                self.next_hop[10],
                self.next_hop[11],
            ])),
            _ => None,
        }
    }

    /// RFC 2545 next hop decoded as `(global, optional link-local)`.
    /// Any other length is a family-level semantic error and returns `None`.
    pub fn ipv6_next_hops(&self) -> Option<(Ipv6Address, Option<Ipv6Address>)> {
        match self.next_hop.len() {
            16 => {
                let mut global = [0u8; 16];
                global.copy_from_slice(&self.next_hop);
                Some((Ipv6Address(global), None))
            }
            32 => {
                let mut global = [0u8; 16];
                let mut link_local = [0u8; 16];
                global.copy_from_slice(&self.next_hop[..16]);
                link_local.copy_from_slice(&self.next_hop[16..]);
                Some((Ipv6Address(global), Some(Ipv6Address(link_local))))
            }
            _ => None,
        }
    }

    pub fn encode_value(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(5 + self.next_hop.len() + self.nlri.len());
        out.extend_from_slice(&self.afi.to_be_bytes());
        out.push(self.safi);
        out.push(self.next_hop.len() as u8);
        out.extend_from_slice(&self.next_hop);
        out.push(0); // Reserved / SNPA count, always zero (RFC 4760 section 3)
        out.extend_from_slice(&self.nlri);
        out
    }

    pub fn parse_value(value: &[u8]) -> Result<Self, BgpParseError> {
        if value.len() < 5 {
            return Err(BgpParseError::update(
                BGP_SUB_ATTRIBUTE_LENGTH_ERROR,
                format!("MP_REACH_NLRI is {} bytes, minimum is 5", value.len()),
            ));
        }
        let afi = u16::from_be_bytes([value[0], value[1]]);
        let safi = value[2];
        let nh_len = value[3] as usize;
        let nh_start = 4usize;
        let nh_end = nh_start + nh_len;
        if nh_end >= value.len() {
            return Err(BgpParseError::update(
                BGP_SUB_ATTRIBUTE_LENGTH_ERROR,
                format!(
                    "MP_REACH_NLRI next hop of {} bytes runs past the {}-byte attribute",
                    nh_len,
                    value.len()
                ),
            ));
        }
        let nlri = &value[nh_end + 1..];
        if nlri.len() > MAX_MP_NLRI_BYTES {
            return Err(BgpParseError::update(
                BGP_SUB_INVALID_NETWORK_FIELD,
                "MP_REACH_NLRI payload exceeds the maximum BGP message size",
            ));
        }
        Ok(Self {
            afi,
            safi,
            next_hop: value[nh_start..nh_end].to_vec(),
            nlri: nlri.to_vec(),
        })
    }
}

/// A decoded MP_UNREACH_NLRI attribute.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MpUnreachNlri {
    pub afi: u16,
    pub safi: u8,
    pub nlri: Vec<u8>,
}

impl MpUnreachNlri {
    pub fn new(family: AfiSafi, nlri: Vec<u8>) -> Self {
        Self {
            afi: family.afi,
            safi: family.safi,
            nlri,
        }
    }

    pub fn family(&self) -> AfiSafi {
        AfiSafi::new(self.afi, self.safi)
    }

    pub fn encode_value(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(3 + self.nlri.len());
        out.extend_from_slice(&self.afi.to_be_bytes());
        out.push(self.safi);
        out.extend_from_slice(&self.nlri);
        out
    }

    pub fn parse_value(value: &[u8]) -> Result<Self, BgpParseError> {
        if value.len() < 3 {
            return Err(BgpParseError::update(
                BGP_SUB_ATTRIBUTE_LENGTH_ERROR,
                format!("MP_UNREACH_NLRI is {} bytes, minimum is 3", value.len()),
            ));
        }
        let nlri = &value[3..];
        if nlri.len() > MAX_MP_NLRI_BYTES {
            return Err(BgpParseError::update(
                BGP_SUB_INVALID_NETWORK_FIELD,
                "MP_UNREACH_NLRI payload exceeds the maximum BGP message size",
            ));
        }
        Ok(Self {
            afi: u16::from_be_bytes([value[0], value[1]]),
            safi: value[2],
            nlri: nlri.to_vec(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    fn evpn_nlri() -> Vec<u8> {
        vec![2, 4, 0xDE, 0xAD, 0xBE, 0xEF]
    }

    fn ip6(text: &str) -> Ipv6Address {
        Ipv6Address::from_str(text).unwrap()
    }

    #[test]
    fn test_mp_reach_round_trips_with_an_ipv4_next_hop() {
        let vtep = Ipv4Address::new(10, 0, 0, 1);
        let mp = MpReachNlri::with_ipv4_next_hop(AfiSafi::L2VPN_EVPN, vtep, evpn_nlri());
        let raw = mp.encode_value();
        assert_eq!(&raw[0..2], &25u16.to_be_bytes());
        assert_eq!(raw[2], 70);
        assert_eq!(raw[3], 4);
        assert_eq!(raw[8], 0);
        let parsed = MpReachNlri::parse_value(&raw).unwrap();
        assert_eq!(parsed, mp);
        assert_eq!(parsed.ipv4_next_hop(), Some(vtep));
    }

    #[test]
    fn test_ipv6_unicast_prefixes_round_trip_boundary_lengths() {
        let source = ip6("2001:db8:1234:5678:9abc:def0:1234:5678");
        for length in [0, 1, 7, 8, 63, 64, 65, 127, 128] {
            let prefix = Ipv6UnicastPrefix::new(source, length);
            let raw = encode_ipv6_unicast_nlri(&[prefix]);
            assert_eq!(raw.len(), prefix.encoded_len());
            assert_eq!(Ipv6UnicastPrefix::decode_list(&raw).unwrap(), vec![prefix]);
        }
    }

    #[test]
    fn test_ipv6_prefix_decoder_rejects_bad_length_and_truncation() {
        assert!(Ipv6UnicastPrefix::decode_list(&[129]).is_err());
        assert!(Ipv6UnicastPrefix::decode_list(&[64, 0x20, 0x01]).is_err());
    }

    #[test]
    fn test_ipv6_prefix_canonicalises_host_bits() {
        let p = Ipv6UnicastPrefix::new(ip6("2001:db8:abcd:ffff::1"), 49);
        assert_eq!(p.to_string(), "2001:db8:abcd:8000::/49");
        assert!(p.contains(ip6("2001:db8:abcd:9fff::beef")));
        assert!(!p.contains(ip6("2001:db8:abcd:7fff::1")));
    }

    #[test]
    fn test_ipv6_global_next_hop_round_trips_in_mp_reach() {
        let family = AfiSafi::new(2, 1);
        let global = ip6("2001:db8::1");
        let prefixes = vec![Ipv6UnicastPrefix::new(ip6("2001:db8:100::"), 48)];
        let mp = MpReachNlri::with_ipv6_next_hop(
            family,
            global,
            None,
            encode_ipv6_unicast_nlri(&prefixes),
        );
        let parsed = MpReachNlri::parse_value(&mp.encode_value()).unwrap();
        assert_eq!(parsed.family(), family);
        assert_eq!(parsed.ipv6_next_hops(), Some((global, None)));
        assert_eq!(Ipv6UnicastPrefix::decode_list(&parsed.nlri).unwrap(), prefixes);
    }

    #[test]
    fn test_ipv6_global_and_link_local_next_hops_round_trip() {
        let family = AfiSafi::new(2, 1);
        let global = ip6("2001:db8::1");
        let link_local = ip6("fe80::1");
        let mp = MpReachNlri::with_ipv6_next_hop(family, global, Some(link_local), Vec::new());
        assert_eq!(mp.next_hop.len(), 32);
        let parsed = MpReachNlri::parse_value(&mp.encode_value()).unwrap();
        assert_eq!(parsed.ipv6_next_hops(), Some((global, Some(link_local))));
    }

    #[test]
    fn test_non_rfc2545_next_hop_length_is_not_misdecoded_as_ipv6() {
        let mp = MpReachNlri::new(AfiSafi::new(2, 1), vec![0u8; 24], Vec::new());
        assert_eq!(mp.ipv6_next_hops(), None);
    }

    #[test]
    fn test_mp_unreach_round_trips() {
        let mp = MpUnreachNlri::new(AfiSafi::L2VPN_EVPN, evpn_nlri());
        let parsed = MpUnreachNlri::parse_value(&mp.encode_value()).unwrap();
        assert_eq!(parsed, mp);
    }

    #[test]
    fn test_a_vpn_next_hop_yields_the_address_after_the_route_distinguisher() {
        let mut nh = vec![0u8; 8];
        nh.extend_from_slice(&[10, 0, 0, 2]);
        let mp = MpReachNlri::new(AfiSafi::L2VPN_EVPN, nh, evpn_nlri());
        assert_eq!(mp.ipv4_next_hop(), Some(Ipv4Address::new(10, 0, 0, 2)));
    }

    #[test]
    fn test_a_next_hop_length_past_the_end_is_refused() {
        let raw = [0, 25, 70, 200, 1, 2, 3, 4, 0, 9];
        assert!(MpReachNlri::parse_value(&raw).is_err());
    }

    #[test]
    fn test_a_next_hop_that_leaves_no_reserved_octet_is_refused() {
        let raw = [0, 25, 70, 4, 10, 0, 0, 1];
        assert!(MpReachNlri::parse_value(&raw).is_err());
    }

    #[test]
    fn test_short_attributes_are_refused_rather_than_indexed() {
        for len in 0..5 {
            assert!(MpReachNlri::parse_value(&vec![0u8; len]).is_err());
        }
        for len in 0..3 {
            assert!(MpUnreachNlri::parse_value(&vec![0u8; len]).is_err());
        }
    }

    #[test]
    fn test_an_mp_attribute_with_no_nlri_is_structurally_valid() {
        let raw = [0, 25, 70, 0, 0];
        let parsed = MpReachNlri::parse_value(&raw).unwrap();
        assert!(parsed.next_hop.is_empty());
        assert!(parsed.nlri.is_empty());
        assert_eq!(parsed.ipv4_next_hop(), None);
        assert_eq!(parsed.ipv6_next_hops(), None);
    }
}
