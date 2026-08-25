//! Multiprotocol reachability attributes (RFC 4760).
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
//!
//! The NLRI payload is deliberately left as opaque bytes here. This module knows
//! how to find it and how to prove the length fields are honest; what the bytes
//! *mean* belongs to the family that owns them, which for `AFI 25 / SAFI 70` is
//! [`crate::evpn`]. That separation is what lets an EVPN route travel over the
//! ordinary BGP session on TCP port 179 instead of needing a transport of its own.

use crate::bgp::{BGP_SUB_ATTRIBUTE_LENGTH_ERROR, BGP_SUB_INVALID_NETWORK_FIELD, BgpParseError};
use crate::bgp_caps::AfiSafi;
use crate::ipv4::Ipv4Address;
use crate::ipv6::Ipv6Address;

/// MP_REACH_NLRI path attribute type code (RFC 4760).
pub const BGP_ATTR_MP_REACH_NLRI: u8 = 14;
/// MP_UNREACH_NLRI path attribute type code (RFC 4760).
pub const BGP_ATTR_MP_UNREACH_NLRI: u8 = 15;
/// Extended Communities path attribute type code (RFC 4360).
pub const BGP_ATTR_EXT_COMMUNITIES: u8 = 16;
/// AS4_PATH path attribute type code (RFC 6793).
pub const BGP_ATTR_AS4_PATH: u8 = 17;

/// Largest NLRI payload accepted inside one MP attribute. A BGP message is capped
/// at 4096 bytes, so a longer claim is impossible on a real session; the constant
/// makes the bound explicit rather than implied by the framer.
pub const MAX_MP_NLRI_BYTES: usize = 4_096;

/// A decoded MP_REACH_NLRI attribute.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MpReachNlri {
    pub afi: u16,
    pub safi: u8,
    /// Next hop exactly as it appeared on the wire. Its length is family-defined:
    /// 4 bytes for an IPv4 VTEP, 16 for IPv6, 12 for a VPN-IPv4 RD-prefixed one.
    pub next_hop: Vec<u8>,
    /// The family's own NLRI encoding, undecoded.
    pub nlri: Vec<u8>,
}

impl MpReachNlri {
    pub fn new(family: AfiSafi, next_hop: Vec<u8>, nlri: Vec<u8>) -> Self {
        MpReachNlri {
            afi: family.afi,
            safi: family.safi,
            next_hop,
            nlri,
        }
    }

    /// An MP_REACH for a family whose next hop is a single IPv4 address, which is
    /// how EVPN over a VXLAN underlay identifies the advertising VTEP.
    pub fn with_ipv4_next_hop(family: AfiSafi, next_hop: Ipv4Address, nlri: Vec<u8>) -> Self {
        MpReachNlri::new(family, next_hop.0.to_vec(), nlri)
    }

    /// RFC 2545 IPv6 next hop. A single global address uses 16 bytes.
    pub fn with_ipv6_next_hop(family: AfiSafi, next_hop: Ipv6Address, nlri: Vec<u8>) -> Self {
        MpReachNlri::new(family, next_hop.0.to_vec(), nlri)
    }

    /// RFC 2545 permits a 32-byte next hop containing global then link-local.
    pub fn with_ipv6_global_and_link_local(
        family: AfiSafi,
        global: Ipv6Address,
        link_local: Ipv6Address,
        nlri: Vec<u8>,
    ) -> Self {
        let mut next_hop = Vec::with_capacity(32);
        next_hop.extend_from_slice(&global.0);
        next_hop.extend_from_slice(&link_local.0);
        MpReachNlri::new(family, next_hop, nlri)
    }

    pub fn family(&self) -> AfiSafi {
        AfiSafi::new(self.afi, self.safi)
    }

    /// The next hop read as an IPv4 address, or `None` if it is not four bytes.
    pub fn ipv4_next_hop(&self) -> Option<Ipv4Address> {
        match self.next_hop.len() {
            4 => Some(Ipv4Address([
                self.next_hop[0],
                self.next_hop[1],
                self.next_hop[2],
                self.next_hop[3],
            ])),
            // A VPN next hop is an 8-byte zero RD followed by the address
            // (RFC 4364 section 4.3.2); the address is what identifies the VTEP.
            12 => Some(Ipv4Address([
                self.next_hop[8],
                self.next_hop[9],
                self.next_hop[10],
                self.next_hop[11],
            ])),
            _ => None,
        }
    }

    /// Returns the global IPv6 next hop from a 16- or 32-byte RFC 2545 field.
    pub fn ipv6_next_hop(&self) -> Option<Ipv6Address> {
        if !matches!(self.next_hop.len(), 16 | 32) {
            return None;
        }
        let mut bytes = [0u8; 16];
        bytes.copy_from_slice(&self.next_hop[..16]);
        Some(Ipv6Address(bytes))
    }

    /// Returns the optional link-local half of a 32-byte IPv6 next hop.
    pub fn ipv6_link_local_next_hop(&self) -> Option<Ipv6Address> {
        if self.next_hop.len() != 32 {
            return None;
        }
        let mut bytes = [0u8; 16];
        bytes.copy_from_slice(&self.next_hop[16..]);
        Some(Ipv6Address(bytes))
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

    /// Decodes the attribute value.
    ///
    /// Three separate length claims have to be checked before any of the payload
    /// is read: the fixed 5-byte prologue must fit, the next-hop length must not
    /// run past the end, and the reserved octet must still be there afterwards.
    /// A missing check on any one of them is an out-of-bounds read on input a
    /// neighbour fully controls.
    pub fn parse_value(value: &[u8]) -> Result<Self, BgpParseError> {
        // AFI(2) + SAFI(1) + next-hop length(1) + reserved(1)
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
        // The reserved octet sits immediately after the next hop, so the next hop
        // must end at least one byte before the end of the attribute.
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
        Ok(MpReachNlri {
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
        MpUnreachNlri {
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
        Ok(MpUnreachNlri {
            afi: u16::from_be_bytes([value[0], value[1]]),
            safi: value[2],
            nlri: nlri.to_vec(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn evpn_nlri() -> Vec<u8> {
        vec![2, 4, 0xDE, 0xAD, 0xBE, 0xEF]
    }

    #[test]
    fn test_mp_reach_round_trips_with_an_ipv4_next_hop() {
        let vtep = Ipv4Address::new(10, 0, 0, 1);
        let mp = MpReachNlri::with_ipv4_next_hop(AfiSafi::L2VPN_EVPN, vtep, evpn_nlri());
        let raw = mp.encode_value();

        // AFI 25, SAFI 70, 4-byte next hop, reserved 0.
        assert_eq!(&raw[0..2], &25u16.to_be_bytes());
        assert_eq!(raw[2], 70);
        assert_eq!(raw[3], 4);
        assert_eq!(raw[8], 0);

        let parsed = MpReachNlri::parse_value(&raw).unwrap();
        assert_eq!(parsed, mp);
        assert_eq!(parsed.family(), AfiSafi::L2VPN_EVPN);
        assert_eq!(parsed.ipv4_next_hop(), Some(vtep));
        assert_eq!(parsed.nlri, evpn_nlri());
    }

    #[test]
    fn test_mp_unreach_round_trips() {
        let mp = MpUnreachNlri::new(AfiSafi::L2VPN_EVPN, evpn_nlri());
        let parsed = MpUnreachNlri::parse_value(&mp.encode_value()).unwrap();
        assert_eq!(parsed, mp);
        assert_eq!(parsed.nlri, evpn_nlri());
    }

    #[test]
    fn test_ipv6_next_hop_accepts_global_and_global_plus_link_local() {
        let global = Ipv6Address::new([0x2001, 0xdb8, 0, 0, 0, 0, 0, 1]);
        let link_local = Ipv6Address::new([0xfe80, 0, 0, 0, 0, 0, 0, 1]);
        let single = MpReachNlri::with_ipv6_next_hop(
            AfiSafi::IPV6_UNICAST,
            global,
            vec![64, 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0],
        );
        assert_eq!(single.ipv6_next_hop(), Some(global));
        assert_eq!(single.ipv6_link_local_next_hop(), None);

        let dual = MpReachNlri::with_ipv6_global_and_link_local(
            AfiSafi::IPV6_UNICAST,
            global,
            link_local,
            Vec::new(),
        );
        assert_eq!(dual.ipv6_next_hop(), Some(global));
        assert_eq!(dual.ipv6_link_local_next_hop(), Some(link_local));
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
        // Claims a 200-byte next hop inside a 10-byte attribute.
        let raw = [0, 25, 70, 200, 1, 2, 3, 4, 0, 9];
        assert!(MpReachNlri::parse_value(&raw).is_err());
    }

    #[test]
    fn test_a_next_hop_that_leaves_no_reserved_octet_is_refused() {
        // 4-byte next hop in a 8-byte attribute: nothing left for the reserved byte.
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
        // A zero-length next hop and an empty NLRI list are both legal shapes;
        // rejecting them belongs to the family, not to the container.
        let raw = [0, 25, 70, 0, 0];
        let parsed = MpReachNlri::parse_value(&raw).unwrap();
        assert!(parsed.next_hop.is_empty());
        assert!(parsed.nlri.is_empty());
        assert_eq!(parsed.ipv4_next_hop(), None);
    }
}
