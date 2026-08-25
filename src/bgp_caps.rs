//! BGP capability advertisement (RFC 5492) and the address families it negotiates.
//!
//! A BGP OPEN carries a list of Optional Parameters. Exactly one parameter type
//! matters in practice - type 2, "Capabilities" - and it holds a sequence of
//! `(code, length, value)` capabilities. This module encodes and decodes that
//! structure, and turns the two OPENs of a session into the set of address
//! families both ends agreed to carry:
//!
//! ```text
//! local capabilities  \
//!                      >-- intersection --> negotiated AFI/SAFI set
//! peer capabilities   /
//! ```
//!
//! The intersection is what gates everything else. A speaker that never heard
//! `AFI 25 / SAFI 70` from its neighbour must not put EVPN NLRI on that session,
//! and this is the type that makes that check a single lookup.

use crate::bgp::{BGP_SUB_UNSUPPORTED_OPT_PARAM, BgpParseError};
use std::collections::BTreeSet;
use std::fmt;

/// Optional parameter type for a capability list (RFC 5492 section 4).
pub const BGP_OPT_PARAM_CAPABILITY: u8 = 2;

/// Multiprotocol Extensions (RFC 4760).
pub const BGP_CAP_MULTIPROTOCOL: u8 = 1;
/// Route Refresh (RFC 2918).
pub const BGP_CAP_ROUTE_REFRESH: u8 = 2;
/// Enhanced Route Refresh (RFC 7313).
pub const BGP_CAP_ENHANCED_ROUTE_REFRESH: u8 = 70;
/// Graceful Restart (RFC 4724).
pub const BGP_CAP_GRACEFUL_RESTART: u8 = 64;
/// Support for 4-octet AS numbers (RFC 6793).
pub const BGP_CAP_FOUR_OCTET_AS: u8 = 65;

/// Restart State bit in the Graceful Restart flags/time word.
pub const BGP_GR_RESTART_STATE: u16 = 0x8000;
/// Largest restart time representable by RFC 4724's 12-bit field.
pub const BGP_GR_MAX_RESTART_TIME: u16 = 0x0fff;
/// Forwarding State bit in one AFI/SAFI tuple.
pub const BGP_GR_FORWARDING_STATE: u8 = 0x80;

/// NOTIFICATION subcode for a capability the receiver requires but did not get
/// (RFC 5492 section 5).
pub const BGP_SUB_UNSUPPORTED_CAPABILITY: u8 = 7;

pub const BGP_AFI_IPV4: u16 = 1;
pub const BGP_AFI_IPV6: u16 = 2;
/// L2VPN, the family EVPN lives in.
pub const BGP_AFI_L2VPN: u16 = 25;

pub const BGP_SAFI_UNICAST: u8 = 1;
pub const BGP_SAFI_MULTICAST: u8 = 2;
/// EVPN (RFC 7432).
pub const BGP_SAFI_EVPN: u8 = 70;

/// Upper bound on capabilities decoded from one OPEN. The optional parameter
/// block is at most 255 bytes, so this cannot be reached by a well-formed
/// message; it exists so a pathological one cannot allocate without limit.
pub const MAX_CAPABILITIES: usize = 64;

/// One address family, as `(AFI, SAFI)`.
///
/// Ordered and hashable so a negotiated family set is a `BTreeSet` and iteration
/// over it is deterministic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AfiSafi {
    pub afi: u16,
    pub safi: u8,
}

impl AfiSafi {
    pub const IPV4_UNICAST: AfiSafi = AfiSafi {
        afi: BGP_AFI_IPV4,
        safi: BGP_SAFI_UNICAST,
    };
    pub const L2VPN_EVPN: AfiSafi = AfiSafi {
        afi: BGP_AFI_L2VPN,
        safi: BGP_SAFI_EVPN,
    };

    pub const fn new(afi: u16, safi: u8) -> Self {
        AfiSafi { afi, safi }
    }

    /// Human-readable family name, for diagnostics.
    pub fn name(&self) -> String {
        match (self.afi, self.safi) {
            (BGP_AFI_IPV4, BGP_SAFI_UNICAST) => "IPv4 Unicast".to_string(),
            (BGP_AFI_IPV4, BGP_SAFI_MULTICAST) => "IPv4 Multicast".to_string(),
            (BGP_AFI_IPV6, BGP_SAFI_UNICAST) => "IPv6 Unicast".to_string(),
            (BGP_AFI_L2VPN, BGP_SAFI_EVPN) => "L2VPN EVPN".to_string(),
            (afi, safi) => format!("AFI {} / SAFI {}", afi, safi),
        }
    }
}

impl fmt::Display for AfiSafi {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} (AFI {}/SAFI {})", self.name(), self.afi, self.safi)
    }
}

/// Per-address-family state carried inside RFC 4724 Graceful Restart.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BgpGracefulRestartFamily {
    pub family: AfiSafi,
    pub forwarding_state: bool,
}

impl BgpGracefulRestartFamily {
    pub const fn new(family: AfiSafi, forwarding_state: bool) -> Self {
        BgpGracefulRestartFamily {
            family,
            forwarding_state,
        }
    }
}

/// RFC 4724 Graceful Restart capability.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BgpGracefulRestartCapability {
    /// True when the sender is reconnecting after a control-plane restart.
    pub restarting: bool,
    /// Time a helper may retain stale routes, in seconds.
    pub restart_time: u16,
    /// Families for which graceful-restart state is advertised.
    pub families: Vec<BgpGracefulRestartFamily>,
}

impl BgpGracefulRestartCapability {
    pub fn new(
        restart_time: u16,
        restarting: bool,
        families: Vec<BgpGracefulRestartFamily>,
    ) -> Self {
        BgpGracefulRestartCapability {
            restarting,
            restart_time: restart_time.min(BGP_GR_MAX_RESTART_TIME),
            families,
        }
    }

    pub fn supports(&self, family: AfiSafi) -> bool {
        self.families.iter().any(|f| f.family == family)
    }

    fn encode_value(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(2 + self.families.len() * 4);
        let word = (self.restart_time & BGP_GR_MAX_RESTART_TIME)
            | if self.restarting {
                BGP_GR_RESTART_STATE
            } else {
                0
            };
        out.extend_from_slice(&word.to_be_bytes());
        for family in &self.families {
            out.extend_from_slice(&family.family.afi.to_be_bytes());
            out.push(family.family.safi);
            out.push(if family.forwarding_state {
                BGP_GR_FORWARDING_STATE
            } else {
                0
            });
        }
        out
    }

    fn decode_value(value: &[u8]) -> Result<Self, BgpParseError> {
        if value.len() < 2 || (value.len() - 2) % 4 != 0 {
            return Err(BgpParseError::open(
                BGP_SUB_UNSUPPORTED_OPT_PARAM,
                format!(
                    "Graceful Restart capability is {} bytes; expected 2 + 4*N",
                    value.len()
                ),
            ));
        }
        let word = u16::from_be_bytes([value[0], value[1]]);
        let mut families = Vec::new();
        for chunk in value[2..].chunks_exact(4) {
            let family = BgpGracefulRestartFamily::new(
                AfiSafi::new(u16::from_be_bytes([chunk[0], chunk[1]]), chunk[2]),
                chunk[3] & BGP_GR_FORWARDING_STATE != 0,
            );
            if !families.contains(&family) {
                families.push(family);
            }
        }
        Ok(BgpGracefulRestartCapability {
            restarting: word & BGP_GR_RESTART_STATE != 0,
            restart_time: word & BGP_GR_MAX_RESTART_TIME,
            families,
        })
    }
}

/// One decoded capability.
///
/// A capability this speaker does not implement is kept as [`BgpCapability::Unknown`]
/// rather than dropped. RFC 5492 requires unknown capabilities to be ignored, not
/// rejected, and keeping the bytes lets the diagnostics show what a peer offered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BgpCapability {
    MultiProtocol(AfiSafi),
    FourOctetAs(u32),
    RouteRefresh,
    EnhancedRouteRefresh,
    GracefulRestart(BgpGracefulRestartCapability),
    Unknown { code: u8, value: Vec<u8> },
}

impl BgpCapability {
    pub fn code(&self) -> u8 {
        match self {
            BgpCapability::MultiProtocol(_) => BGP_CAP_MULTIPROTOCOL,
            BgpCapability::FourOctetAs(_) => BGP_CAP_FOUR_OCTET_AS,
            BgpCapability::RouteRefresh => BGP_CAP_ROUTE_REFRESH,
            BgpCapability::EnhancedRouteRefresh => BGP_CAP_ENHANCED_ROUTE_REFRESH,
            BgpCapability::GracefulRestart(_) => BGP_CAP_GRACEFUL_RESTART,
            BgpCapability::Unknown { code, .. } => *code,
        }
    }

    /// The capability value, without the `(code, length)` header.
    pub fn value(&self) -> Vec<u8> {
        match self {
            BgpCapability::MultiProtocol(af) => {
                let mut v = Vec::with_capacity(4);
                v.extend_from_slice(&af.afi.to_be_bytes());
                v.push(0); // reserved
                v.push(af.safi);
                v
            }
            BgpCapability::FourOctetAs(asn) => asn.to_be_bytes().to_vec(),
            BgpCapability::RouteRefresh => Vec::new(),
            BgpCapability::EnhancedRouteRefresh => Vec::new(),
            BgpCapability::GracefulRestart(gr) => gr.encode_value(),
            BgpCapability::Unknown { value, .. } => value.clone(),
        }
    }

    /// Encodes `code`, `length`, and the value.
    pub fn encode(&self, out: &mut Vec<u8>) {
        let value = self.value();
        out.push(self.code());
        out.push(value.len() as u8);
        out.extend_from_slice(&value);
    }

    /// Decodes one capability from its code and already-bounds-checked value.
    ///
    /// A *known* code whose length is wrong is an error: silently treating a
    /// three-byte Four-Octet AS capability as unknown would let a peer claim
    /// AS4 support and then be believed about an ASN nobody actually read.
    pub fn decode(code: u8, value: &[u8]) -> Result<Self, BgpParseError> {
        match code {
            BGP_CAP_MULTIPROTOCOL => {
                if value.len() != 4 {
                    return Err(BgpParseError::open(
                        BGP_SUB_UNSUPPORTED_OPT_PARAM,
                        format!(
                            "Multiprotocol capability is {} bytes, must be 4",
                            value.len()
                        ),
                    ));
                }
                Ok(BgpCapability::MultiProtocol(AfiSafi::new(
                    u16::from_be_bytes([value[0], value[1]]),
                    value[3],
                )))
            }
            BGP_CAP_FOUR_OCTET_AS => {
                if value.len() != 4 {
                    return Err(BgpParseError::open(
                        BGP_SUB_UNSUPPORTED_OPT_PARAM,
                        format!(
                            "Four-Octet AS capability is {} bytes, must be 4",
                            value.len()
                        ),
                    ));
                }
                Ok(BgpCapability::FourOctetAs(u32::from_be_bytes([
                    value[0], value[1], value[2], value[3],
                ])))
            }
            BGP_CAP_ROUTE_REFRESH => {
                if !value.is_empty() {
                    return Err(BgpParseError::open(
                        BGP_SUB_UNSUPPORTED_OPT_PARAM,
                        "Route Refresh capability must carry no value",
                    ));
                }
                Ok(BgpCapability::RouteRefresh)
            }
            BGP_CAP_ENHANCED_ROUTE_REFRESH => {
                if !value.is_empty() {
                    return Err(BgpParseError::open(
                        BGP_SUB_UNSUPPORTED_OPT_PARAM,
                        "Enhanced Route Refresh capability must carry no value",
                    ));
                }
                Ok(BgpCapability::EnhancedRouteRefresh)
            }
            BGP_CAP_GRACEFUL_RESTART => Ok(BgpCapability::GracefulRestart(
                BgpGracefulRestartCapability::decode_value(value)?,
            )),
            other => Ok(BgpCapability::Unknown {
                code: other,
                value: value.to_vec(),
            }),
        }
    }
}

impl fmt::Display for BgpCapability {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BgpCapability::MultiProtocol(af) => write!(f, "Multiprotocol {}", af),
            BgpCapability::FourOctetAs(asn) => write!(f, "Four-Octet AS {}", asn),
            BgpCapability::RouteRefresh => write!(f, "Route Refresh"),
            BgpCapability::EnhancedRouteRefresh => write!(f, "Enhanced Route Refresh"),
            BgpCapability::GracefulRestart(gr) => write!(
                f,
                "Graceful Restart {}s{} ({} families)",
                gr.restart_time,
                if gr.restarting { " restarting" } else { "" },
                gr.families.len()
            ),
            BgpCapability::Unknown { code, value } => {
                write!(f, "unknown capability {} ({} bytes)", code, value.len())
            }
        }
    }
}

/// The capability list of one OPEN.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BgpCapabilitySet {
    pub capabilities: Vec<BgpCapability>,
}

impl BgpCapabilitySet {
    pub fn new() -> Self {
        BgpCapabilitySet::default()
    }

    pub fn is_empty(&self) -> bool {
        self.capabilities.is_empty()
    }

    pub fn push(&mut self, cap: BgpCapability) {
        if !self.capabilities.contains(&cap) {
            self.capabilities.push(cap);
        }
    }

    /// Adds a Multiprotocol capability for `family`.
    pub fn advertise(&mut self, family: AfiSafi) {
        self.push(BgpCapability::MultiProtocol(family));
    }

    /// Every family advertised through a Multiprotocol capability.
    ///
    /// An OPEN with no Multiprotocol capability at all is a legacy speaker, which
    /// RFC 4760 says implicitly supports IPv4 Unicast. That default is applied by
    /// [`negotiate`], not here, so this stays a faithful report of the wire.
    pub fn families(&self) -> BTreeSet<AfiSafi> {
        self.capabilities
            .iter()
            .filter_map(|c| match c {
                BgpCapability::MultiProtocol(af) => Some(*af),
                _ => None,
            })
            .collect()
    }

    pub fn supports(&self, family: AfiSafi) -> bool {
        self.capabilities
            .iter()
            .any(|c| matches!(c, BgpCapability::MultiProtocol(af) if *af == family))
    }

    /// The ASN from the Four-Octet AS capability, if the speaker sent one.
    pub fn four_octet_as(&self) -> Option<u32> {
        self.capabilities.iter().find_map(|c| match c {
            BgpCapability::FourOctetAs(asn) => Some(*asn),
            _ => None,
        })
    }

    pub fn supports_four_octet_as(&self) -> bool {
        self.four_octet_as().is_some()
    }

    /// True when the speaker advertised RFC 2918 Route Refresh.
    pub fn supports_route_refresh(&self) -> bool {
        self.capabilities
            .iter()
            .any(|c| matches!(c, BgpCapability::RouteRefresh))
    }

    /// True when the speaker advertised RFC 7313 Enhanced Route Refresh.
    pub fn supports_enhanced_route_refresh(&self) -> bool {
        self.capabilities
            .iter()
            .any(|c| matches!(c, BgpCapability::EnhancedRouteRefresh))
    }

    /// The RFC 4724 capability advertised by the speaker, if any.
    pub fn graceful_restart(&self) -> Option<&BgpGracefulRestartCapability> {
        self.capabilities.iter().find_map(|c| match c {
            BgpCapability::GracefulRestart(gr) => Some(gr),
            _ => None,
        })
    }

    pub fn supports_graceful_restart(&self) -> bool {
        self.graceful_restart().is_some()
    }

    /// Encodes the whole set as an OPEN optional parameter block.
    ///
    /// All capabilities go into a single parameter, which is what every modern
    /// implementation emits and what keeps the block inside the one-octet
    /// parameter length. An empty set encodes to nothing at all, so an OPEN from
    /// a speaker with nothing to say is byte-identical to a legacy one.
    pub fn encode_opt_params(&self) -> Vec<u8> {
        if self.capabilities.is_empty() {
            return Vec::new();
        }
        let mut caps = Vec::new();
        for c in &self.capabilities {
            c.encode(&mut caps);
        }
        let mut out = Vec::with_capacity(2 + caps.len());
        out.push(BGP_OPT_PARAM_CAPABILITY);
        out.push(caps.len() as u8);
        out.extend_from_slice(&caps);
        out
    }

    /// Decodes an OPEN optional parameter block.
    ///
    /// Every length is checked against what actually remains before it is used.
    /// A parameter of a type other than "Capabilities" is skipped rather than
    /// rejected - RFC 4271 defined the container generically, and refusing an
    /// unknown one would break a session over something we do not need to read.
    pub fn parse_opt_params(data: &[u8]) -> Result<Self, BgpParseError> {
        let mut set = BgpCapabilitySet::new();
        let mut i = 0usize;
        while i < data.len() {
            if i + 2 > data.len() {
                return Err(BgpParseError::open(
                    BGP_SUB_UNSUPPORTED_OPT_PARAM,
                    "truncated optional parameter header",
                ));
            }
            let param_type = data[i];
            let param_len = data[i + 1] as usize;
            let body_start = i + 2;
            let body_end = body_start
                .checked_add(param_len)
                .filter(|end| *end <= data.len())
                .ok_or_else(|| {
                    BgpParseError::open(
                        BGP_SUB_UNSUPPORTED_OPT_PARAM,
                        format!(
                            "optional parameter claims {} bytes but only {} remain",
                            param_len,
                            data.len().saturating_sub(body_start)
                        ),
                    )
                })?;

            if param_type == BGP_OPT_PARAM_CAPABILITY {
                set.parse_capability_block(&data[body_start..body_end])?;
            }

            i = body_end;
        }
        Ok(set)
    }

    fn parse_capability_block(&mut self, data: &[u8]) -> Result<(), BgpParseError> {
        let mut i = 0usize;
        while i < data.len() {
            if i + 2 > data.len() {
                return Err(BgpParseError::open(
                    BGP_SUB_UNSUPPORTED_OPT_PARAM,
                    "truncated capability header",
                ));
            }
            let code = data[i];
            let len = data[i + 1] as usize;
            let val_start = i + 2;
            let val_end = val_start
                .checked_add(len)
                .filter(|end| *end <= data.len())
                .ok_or_else(|| {
                    BgpParseError::open(
                        BGP_SUB_UNSUPPORTED_OPT_PARAM,
                        format!(
                            "capability {} claims {} bytes but only {} remain",
                            code,
                            len,
                            data.len().saturating_sub(val_start)
                        ),
                    )
                })?;

            if self.capabilities.len() >= MAX_CAPABILITIES {
                return Err(BgpParseError::open(
                    BGP_SUB_UNSUPPORTED_OPT_PARAM,
                    format!("OPEN carries more than {} capabilities", MAX_CAPABILITIES),
                ));
            }
            self.push(BgpCapability::decode(code, &data[val_start..val_end])?);
            i = val_end;
        }
        Ok(())
    }
}

impl fmt::Display for BgpCapabilitySet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.capabilities.is_empty() {
            return f.write_str("none");
        }
        let text: Vec<String> = self.capabilities.iter().map(|c| c.to_string()).collect();
        f.write_str(&text.join(", "))
    }
}

/// What two OPENs agreed on.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NegotiatedCapabilities {
    /// Families both ends advertised.
    pub families: BTreeSet<AfiSafi>,
    /// True when both ends sent the Four-Octet AS capability, which is what
    /// decides whether AS_PATH on this session carries 2- or 4-octet ASNs.
    pub four_octet_as: bool,
    /// True when both ends advertised RFC 2918 Route Refresh.
    pub route_refresh: bool,
    /// True when both ends also advertised RFC 7313 Enhanced Route Refresh.
    pub enhanced_route_refresh: bool,
    /// Everything the peer offered, kept verbatim for diagnostics.
    pub peer: BgpCapabilitySet,
}

impl NegotiatedCapabilities {
    pub fn supports(&self, family: AfiSafi) -> bool {
        self.families.contains(&family)
    }

    pub fn supports_evpn(&self) -> bool {
        self.supports(AfiSafi::L2VPN_EVPN)
    }

    pub fn supports_route_refresh(&self) -> bool {
        self.route_refresh
    }

    pub fn supports_enhanced_route_refresh(&self) -> bool {
        self.enhanced_route_refresh
    }
}

/// Intersects what this speaker offered with what the peer offered.
///
/// A speaker that sends no Multiprotocol capability is a legacy BGP-4 speaker and
/// implicitly means IPv4 Unicast (RFC 4760 section 8). Applying that default to
/// both sides is what keeps a plain RFC 4271 session working: it negotiates
/// exactly IPv4 Unicast and nothing else, so nothing about this module can put
/// an EVPN route on a legacy session.
pub fn negotiate(local: &BgpCapabilitySet, peer: &BgpCapabilitySet) -> NegotiatedCapabilities {
    fn families_with_default(set: &BgpCapabilitySet) -> BTreeSet<AfiSafi> {
        let f = set.families();
        if f.is_empty() {
            BTreeSet::from([AfiSafi::IPV4_UNICAST])
        } else {
            f
        }
    }

    let local_families = families_with_default(local);
    let peer_families = families_with_default(peer);

    let route_refresh = local.supports_route_refresh() && peer.supports_route_refresh();
    NegotiatedCapabilities {
        families: local_families
            .intersection(&peer_families)
            .copied()
            .collect(),
        four_octet_as: local.supports_four_octet_as() && peer.supports_four_octet_as(),
        route_refresh,
        enhanced_route_refresh: route_refresh
            && local.supports_enhanced_route_refresh()
            && peer.supports_enhanced_route_refresh(),
        peer: peer.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn full_set() -> BgpCapabilitySet {
        let mut set = BgpCapabilitySet::new();
        set.advertise(AfiSafi::IPV4_UNICAST);
        set.advertise(AfiSafi::L2VPN_EVPN);
        set.push(BgpCapability::FourOctetAs(4_200_000_001));
        set.push(BgpCapability::RouteRefresh);
        set.push(BgpCapability::EnhancedRouteRefresh);
        set.push(BgpCapability::GracefulRestart(
            BgpGracefulRestartCapability::new(
                120,
                false,
                vec![
                    BgpGracefulRestartFamily::new(AfiSafi::IPV4_UNICAST, true),
                    BgpGracefulRestartFamily::new(AfiSafi::L2VPN_EVPN, false),
                ],
            ),
        ));
        set
    }

    #[test]
    fn test_capability_block_round_trips() {
        let set = full_set();
        let encoded = set.encode_opt_params();
        assert_eq!(encoded[0], BGP_OPT_PARAM_CAPABILITY);
        assert_eq!(encoded[1] as usize, encoded.len() - 2);

        let decoded = BgpCapabilitySet::parse_opt_params(&encoded).unwrap();
        assert_eq!(decoded, set);
        assert_eq!(decoded.four_octet_as(), Some(4_200_000_001));
        assert!(decoded.supports(AfiSafi::L2VPN_EVPN));
    }

    #[test]
    fn test_an_empty_set_encodes_to_a_legacy_open() {
        assert!(BgpCapabilitySet::new().encode_opt_params().is_empty());
        assert!(
            BgpCapabilitySet::parse_opt_params(&[])
                .unwrap()
                .capabilities
                .is_empty()
        );
    }

    #[test]
    fn test_a_legacy_speaker_negotiates_ipv4_unicast_only() {
        let n = negotiate(&full_set(), &BgpCapabilitySet::new());
        assert_eq!(n.families, BTreeSet::from([AfiSafi::IPV4_UNICAST]));
        assert!(!n.supports_evpn());
        assert!(!n.four_octet_as);
        assert!(!n.route_refresh);
        assert!(!n.enhanced_route_refresh);
    }

    #[test]
    fn test_evpn_is_negotiated_only_when_both_ends_offer_it() {
        let mut ipv4_only = BgpCapabilitySet::new();
        ipv4_only.advertise(AfiSafi::IPV4_UNICAST);

        assert!(!negotiate(&full_set(), &ipv4_only).supports_evpn());
        assert!(negotiate(&full_set(), &full_set()).supports_evpn());
        assert!(negotiate(&full_set(), &full_set()).four_octet_as);
    }

    #[test]
    fn test_route_refresh_is_negotiated_only_when_both_ends_offer_it() {
        let full = full_set();
        let mut without_refresh = full_set();
        without_refresh
            .capabilities
            .retain(|c| !matches!(c, BgpCapability::RouteRefresh));

        assert!(negotiate(&full, &full).supports_route_refresh());
        assert!(!negotiate(&full, &without_refresh).supports_route_refresh());
        assert!(!negotiate(&without_refresh, &full).supports_route_refresh());
    }

    #[test]
    fn test_graceful_restart_round_trips_restart_and_forwarding_state() {
        let gr = BgpGracefulRestartCapability::new(
            300,
            true,
            vec![
                BgpGracefulRestartFamily::new(AfiSafi::IPV4_UNICAST, true),
                BgpGracefulRestartFamily::new(AfiSafi::L2VPN_EVPN, false),
            ],
        );
        let mut set = BgpCapabilitySet::new();
        set.push(BgpCapability::GracefulRestart(gr.clone()));
        let decoded = BgpCapabilitySet::parse_opt_params(&set.encode_opt_params()).unwrap();
        assert_eq!(decoded.graceful_restart(), Some(&gr));
        assert!(decoded.supports_graceful_restart());
        assert!(
            decoded
                .graceful_restart()
                .unwrap()
                .supports(AfiSafi::IPV4_UNICAST)
        );
    }

    #[test]
    fn test_malformed_graceful_restart_lengths_are_rejected() {
        assert!(BgpCapability::decode(BGP_CAP_GRACEFUL_RESTART, &[]).is_err());
        assert!(BgpCapability::decode(BGP_CAP_GRACEFUL_RESTART, &[0, 10, 0]).is_err());
    }

    #[test]
    fn test_an_unknown_capability_is_kept_but_ignored() {
        let mut set = BgpCapabilitySet::new();
        set.advertise(AfiSafi::IPV4_UNICAST);
        set.push(BgpCapability::Unknown {
            code: 200,
            value: vec![1, 2, 3],
        });
        let decoded = BgpCapabilitySet::parse_opt_params(&set.encode_opt_params()).unwrap();
        assert_eq!(decoded.capabilities.len(), 2);
        assert_eq!(decoded.families(), BTreeSet::from([AfiSafi::IPV4_UNICAST]));
    }

    #[test]
    fn test_a_wrong_length_known_capability_is_refused() {
        // Four-Octet AS with a three-byte value: a peer must not be believed
        // about an ASN it did not fully send.
        let raw = [
            BGP_OPT_PARAM_CAPABILITY,
            5,
            BGP_CAP_FOUR_OCTET_AS,
            3,
            0,
            1,
            2,
        ];
        assert!(BgpCapabilitySet::parse_opt_params(&raw).is_err());
    }

    #[test]
    fn test_a_capability_length_past_the_end_is_refused() {
        let raw = [BGP_OPT_PARAM_CAPABILITY, 2, BGP_CAP_MULTIPROTOCOL, 40];
        assert!(BgpCapabilitySet::parse_opt_params(&raw).is_err());
    }

    #[test]
    fn test_a_parameter_length_past_the_end_is_refused() {
        assert!(BgpCapabilitySet::parse_opt_params(&[BGP_OPT_PARAM_CAPABILITY, 90]).is_err());
    }

    #[test]
    fn test_an_unknown_optional_parameter_is_skipped() {
        let mut raw = vec![9u8, 2, 0xAA, 0xBB];
        raw.extend_from_slice(&full_set().encode_opt_params());
        let decoded = BgpCapabilitySet::parse_opt_params(&raw).unwrap();
        assert!(decoded.supports(AfiSafi::L2VPN_EVPN));
    }
}

#[cfg(test)]
mod enhanced_route_refresh_tests {
    use super::*;

    #[test]
    fn test_enhanced_route_refresh_requires_both_sides_and_base_refresh() {
        let mut local = BgpCapabilitySet::new();
        local.advertise(AfiSafi::IPV4_UNICAST);
        local.push(BgpCapability::RouteRefresh);
        local.push(BgpCapability::EnhancedRouteRefresh);

        let mut peer = local.clone();
        let n = negotiate(&local, &peer);
        assert!(n.supports_route_refresh());
        assert!(n.supports_enhanced_route_refresh());

        peer.capabilities
            .retain(|c| !matches!(c, BgpCapability::EnhancedRouteRefresh));
        let n = negotiate(&local, &peer);
        assert!(n.supports_route_refresh());
        assert!(!n.supports_enhanced_route_refresh());

        peer.push(BgpCapability::EnhancedRouteRefresh);
        peer.capabilities
            .retain(|c| !matches!(c, BgpCapability::RouteRefresh));
        let n = negotiate(&local, &peer);
        assert!(!n.supports_route_refresh());
        assert!(!n.supports_enhanced_route_refresh());
    }
}
