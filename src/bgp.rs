//! Border Gateway Protocol Version 4 (BGP-4 - RFC 4271).
//!
//! Inter-domain path-vector routing protocol over TCP port 179.
//! Features 19-byte BGP framing, OPEN, UPDATE (AS_PATH / NEXT_HOP), and KEEPALIVE messages.

use crate::bgp_caps::{AfiSafi, BgpCapabilitySet};
use crate::bgp_mp::{
    BGP_ATTR_AS4_PATH, BGP_ATTR_EXT_COMMUNITIES, BGP_ATTR_MP_REACH_NLRI, BGP_ATTR_MP_UNREACH_NLRI,
    MpReachNlri, MpUnreachNlri,
};
use crate::ipv4::Ipv4Address;
use std::collections::HashMap;
use std::fmt;

pub const BGP_PORT: u16 = 179;
pub const BGP_HEADER_LEN: usize = 19;
pub const BGP_MARKER: [u8; 16] = [0xFF; 16];

// BGP Message Types
pub const BGP_MSG_OPEN: u8 = 1;
pub const BGP_MSG_UPDATE: u8 = 2;
pub const BGP_MSG_NOTIFICATION: u8 = 3;
pub const BGP_MSG_KEEPALIVE: u8 = 4;
/// ROUTE-REFRESH (RFC 2918).
pub const BGP_MSG_ROUTE_REFRESH: u8 = 5;

// BGP Path Attribute Types
pub const BGP_ATTR_ORIGIN: u8 = 1;
pub const BGP_ATTR_AS_PATH: u8 = 2;
pub const BGP_ATTR_NEXT_HOP: u8 = 3;
pub const BGP_ATTR_MED: u8 = 4;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BgpMessage {
    Open {
        version: u8,
        my_as: u16,
        hold_time: u16,
        bgp_id: Ipv4Address,
    },
    Update {
        as_path: Vec<u16>,
        next_hop: Ipv4Address,
        nlri_prefix: Ipv4Address,
        nlri_mask: u8,
    },
    Keepalive,
    Notification {
        error_code: u8,
        error_subcode: u8,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BgpError {
    PacketTooShort(usize),
    InvalidMarker,
    InvalidType(u8),
    InvalidLength(u16),
}

impl fmt::Display for BgpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BgpError::PacketTooShort(l) => write!(f, "BGP packet too short ({} bytes, min 19)", l),
            BgpError::InvalidMarker => write!(f, "Invalid BGP 16-byte marker (expected all 0xFF)"),
            BgpError::InvalidType(t) => write!(f, "Invalid BGP message type: {}", t),
            BgpError::InvalidLength(l) => write!(f, "Invalid BGP message length: {}", l),
        }
    }
}

impl std::error::Error for BgpError {}

impl BgpMessage {
    pub fn parse(data: &[u8]) -> Result<Self, BgpError> {
        if data.len() < BGP_HEADER_LEN {
            return Err(BgpError::PacketTooShort(data.len()));
        }

        if data[0..16] != BGP_MARKER {
            return Err(BgpError::InvalidMarker);
        }

        let length = u16::from_be_bytes([data[16], data[17]]);
        let msg_type = data[18];

        if (data.len() as u16) < length {
            return Err(BgpError::PacketTooShort(data.len()));
        }

        let body = &data[BGP_HEADER_LEN..length as usize];

        match msg_type {
            BGP_MSG_OPEN => {
                if body.len() < 10 {
                    return Err(BgpError::PacketTooShort(body.len()));
                }
                let version = body[0];
                let my_as = u16::from_be_bytes([body[1], body[2]]);
                let hold_time = u16::from_be_bytes([body[3], body[4]]);
                let bgp_id = Ipv4Address([body[5], body[6], body[7], body[8]]);
                Ok(BgpMessage::Open {
                    version,
                    my_as,
                    hold_time,
                    bgp_id,
                })
            }
            BGP_MSG_KEEPALIVE => Ok(BgpMessage::Keepalive),
            BGP_MSG_NOTIFICATION => {
                let error_code = body.first().copied().unwrap_or(0);
                let error_subcode = body.get(1).copied().unwrap_or(0);
                Ok(BgpMessage::Notification {
                    error_code,
                    error_subcode,
                })
            }
            BGP_MSG_UPDATE => {
                // Simplified parser for AS_PATH and NEXT_HOP + NLRI
                let mut as_path = Vec::new();
                let mut next_hop = Ipv4Address::new(0, 0, 0, 0);
                let mut nlri_prefix = Ipv4Address::new(0, 0, 0, 0);
                let mut nlri_mask = 24u8;

                if body.len() >= 4 {
                    let withdrawn_len = u16::from_be_bytes([body[0], body[1]]) as usize;
                    let attr_offset = 2 + withdrawn_len;
                    if body.len() >= attr_offset + 2 {
                        let total_attr_len =
                            u16::from_be_bytes([body[attr_offset], body[attr_offset + 1]]) as usize;
                        let mut curr = attr_offset + 2;
                        let attr_end = curr + total_attr_len;

                        while curr + 3 <= attr_end && curr + 3 <= body.len() {
                            let _flags = body[curr];
                            let type_code = body[curr + 1];
                            let attr_len = body[curr + 2] as usize;
                            let val_start = curr + 3;
                            let val_end = val_start + attr_len;

                            if val_end <= body.len() {
                                match type_code {
                                    BGP_ATTR_AS_PATH => {
                                        if attr_len >= 2 {
                                            // Segment Type (1B), Path Length (1B), AS numbers (2B each)
                                            let seg_len = body[val_start + 1] as usize;
                                            for i in 0..seg_len {
                                                let offset = val_start + 2 + i * 2;
                                                if offset + 2 <= val_end {
                                                    as_path.push(u16::from_be_bytes([
                                                        body[offset],
                                                        body[offset + 1],
                                                    ]));
                                                }
                                            }
                                        }
                                    }
                                    BGP_ATTR_NEXT_HOP if attr_len == 4 => {
                                        next_hop = Ipv4Address([
                                            body[val_start],
                                            body[val_start + 1],
                                            body[val_start + 2],
                                            body[val_start + 3],
                                        ]);
                                    }
                                    _ => {}
                                }
                            }
                            curr = val_end;
                        }

                        // NLRI at end of update
                        if attr_end < body.len() {
                            nlri_mask = body[attr_end];
                            if attr_end + 4 < body.len() {
                                nlri_prefix = Ipv4Address([
                                    body[attr_end + 1],
                                    body[attr_end + 2],
                                    body[attr_end + 3],
                                    body[attr_end + 4],
                                ]);
                            }
                        }
                    }
                }

                Ok(BgpMessage::Update {
                    as_path,
                    next_hop,
                    nlri_prefix,
                    nlri_mask,
                })
            }
            _ => Err(BgpError::InvalidType(msg_type)),
        }
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut body = Vec::new();
        let msg_type = match self {
            BgpMessage::Open {
                version,
                my_as,
                hold_time,
                bgp_id,
            } => {
                body.push(*version);
                body.extend_from_slice(&my_as.to_be_bytes());
                body.extend_from_slice(&hold_time.to_be_bytes());
                body.extend_from_slice(&bgp_id.0);
                body.push(0); // Opt Param Len = 0
                BGP_MSG_OPEN
            }
            BgpMessage::Keepalive => BGP_MSG_KEEPALIVE,
            BgpMessage::Notification {
                error_code,
                error_subcode,
            } => {
                body.push(*error_code);
                body.push(*error_subcode);
                BGP_MSG_NOTIFICATION
            }
            BgpMessage::Update {
                as_path,
                next_hop,
                nlri_prefix,
                nlri_mask,
            } => {
                body.extend_from_slice(&0u16.to_be_bytes()); // Withdrawn Routes Len = 0

                let mut attrs = Vec::new();
                // 1. ORIGIN = IGP (0)
                attrs.extend_from_slice(&[0x40, BGP_ATTR_ORIGIN, 1, 0]);

                // 2. AS_PATH
                let mut as_seg = Vec::new();
                as_seg.push(2); // AS_SEQUENCE (2)
                as_seg.push(as_path.len() as u8);
                for asn in as_path {
                    as_seg.extend_from_slice(&asn.to_be_bytes());
                }
                attrs.push(0x40);
                attrs.push(BGP_ATTR_AS_PATH);
                attrs.push(as_seg.len() as u8);
                attrs.extend(as_seg);

                // 3. NEXT_HOP
                attrs.extend_from_slice(&[0x40, BGP_ATTR_NEXT_HOP, 4]);
                attrs.extend_from_slice(&next_hop.0);

                body.extend_from_slice(&(attrs.len() as u16).to_be_bytes());
                body.extend(attrs);

                // NLRI
                body.push(*nlri_mask);
                body.extend_from_slice(&nlri_prefix.0);

                BGP_MSG_UPDATE
            }
        };

        let total_len = (BGP_HEADER_LEN + body.len()) as u16;
        let mut buf = Vec::with_capacity(total_len as usize);

        buf.extend_from_slice(&BGP_MARKER);
        buf.extend_from_slice(&total_len.to_be_bytes());
        buf.push(msg_type);
        buf.extend(body);

        buf
    }

    pub fn build_open(asn: u16, hold_time: u16, router_id: Ipv4Address) -> Self {
        BgpMessage::Open {
            version: 4,
            my_as: asn,
            hold_time,
            bgp_id: router_id,
        }
    }

    pub fn build_update(
        prefix: Ipv4Address,
        mask: u8,
        next_hop: Ipv4Address,
        as_path: Vec<u16>,
    ) -> Self {
        BgpMessage::Update {
            as_path,
            next_hop,
            nlri_prefix: prefix,
            nlri_mask: mask,
        }
    }
}

/// BGP Routing Information Base (RIB)
pub struct BgpRib {
    routes: HashMap<(Ipv4Address, u8), (Ipv4Address, Vec<u16>)>,
}

impl Default for BgpRib {
    fn default() -> Self {
        Self::new()
    }
}

impl BgpRib {
    pub fn new() -> Self {
        let mut rib = BgpRib {
            routes: HashMap::new(),
        };
        rib.insert(
            Ipv4Address::new(8, 8, 8, 0),
            24,
            Ipv4Address::new(198, 51, 100, 1),
            vec![65001, 15169],
        );
        rib.insert(
            Ipv4Address::new(1, 1, 1, 0),
            24,
            Ipv4Address::new(203, 0, 113, 1),
            vec![65001, 13335],
        );
        rib
    }

    pub fn insert(
        &mut self,
        prefix: Ipv4Address,
        mask: u8,
        next_hop: Ipv4Address,
        as_path: Vec<u16>,
    ) {
        self.routes.insert((prefix, mask), (next_hop, as_path));
    }

    pub fn all_routes(&self) -> &HashMap<(Ipv4Address, u8), (Ipv4Address, Vec<u16>)> {
        &self.routes
    }
}

// ============================================================================
// Strict RFC 4271 wire layer.
//
// `BgpMessage` above is the original convenience codec: it models one NLRI per
// UPDATE and is tolerant of odd encodings. The control plane needs something
// stricter and richer, so the types below add full path-attribute handling,
// withdrawn routes, multi-prefix NLRI, and validation that maps every failure to
// the NOTIFICATION code the RFC prescribes. Both share the framing constants and
// the 16-byte marker.
// ============================================================================

pub const BGP_VERSION: u8 = 4;
/// Largest legal BGP message, RFC 4271 section 4.1. Nothing larger is ever buffered.
pub const BGP_MAX_MESSAGE_LEN: usize = 4096;
/// Smallest non-zero hold time a peer may propose, RFC 4271 section 4.2.
pub const BGP_MIN_HOLD_TIME: u16 = 3;
/// Default LOCAL_PREF applied to paths that arrive without the attribute.
pub const BGP_DEFAULT_LOCAL_PREF: u32 = 100;

pub const BGP_ATTR_LOCAL_PREF: u8 = 5;
pub const BGP_ATTR_ATOMIC_AGGREGATE: u8 = 6;
pub const BGP_ATTR_AGGREGATOR: u8 = 7;
/// ORIGINATOR_ID (RFC 4456 section 8): the BGP identifier of the speaker inside
/// this AS that first advertised the route. Optional and non-transitive.
pub const BGP_ATTR_ORIGINATOR_ID: u8 = 9;
/// CLUSTER_LIST (RFC 4456 section 8): the cluster IDs of every route reflector
/// the route has passed through. Optional and non-transitive.
pub const BGP_ATTR_CLUSTER_LIST: u8 = 10;

/// Largest CLUSTER_LIST this speaker will accept, in cluster IDs.
///
/// RFC 4456 puts no ceiling on the list, but an unbounded one is an attack
/// surface: a peer could send a 4096-byte attribute of nothing but cluster IDs
/// on every UPDATE and make every reflection hop copy it. A real hierarchy is a
/// handful of levels deep, so anything past this is malformed rather than deep.
pub const MAX_CLUSTER_LIST_LEN: usize = 32;

pub const BGP_ATTR_FLAG_OPTIONAL: u8 = 0x80;
pub const BGP_ATTR_FLAG_TRANSITIVE: u8 = 0x40;
pub const BGP_ATTR_FLAG_PARTIAL: u8 = 0x20;
pub const BGP_ATTR_FLAG_EXT_LEN: u8 = 0x10;

/// Largest number of ASNs one AS_PATH segment can carry: the count is a single octet.
pub const AS_PATH_MAX_SEGMENT_ASNS: usize = 255;

pub const BGP_AS_SET: u8 = 1;
pub const BGP_AS_SEQUENCE: u8 = 2;

/// The reserved ASN a 4-octet speaker puts on the wire where a 2-octet field
/// cannot hold the real one (RFC 6793 section 4.1). It is a placeholder, never a
/// routable AS: the true value travels in the Four-Octet AS capability or AS4_PATH.
pub const AS_TRANS: u16 = 23_456;

// NOTIFICATION error codes (RFC 4271 section 4.5).
pub const BGP_ERR_MESSAGE_HEADER: u8 = 1;
pub const BGP_ERR_OPEN_MESSAGE: u8 = 2;
pub const BGP_ERR_UPDATE_MESSAGE: u8 = 3;
pub const BGP_ERR_HOLD_TIMER_EXPIRED: u8 = 4;
pub const BGP_ERR_FSM: u8 = 5;
pub const BGP_ERR_CEASE: u8 = 6;

// Message-header subcodes.
pub const BGP_SUB_CONNECTION_NOT_SYNCHRONIZED: u8 = 1;
pub const BGP_SUB_BAD_MESSAGE_LENGTH: u8 = 2;
pub const BGP_SUB_BAD_MESSAGE_TYPE: u8 = 3;

// OPEN subcodes.
pub const BGP_SUB_UNSUPPORTED_VERSION: u8 = 1;
pub const BGP_SUB_BAD_PEER_AS: u8 = 2;
pub const BGP_SUB_BAD_BGP_IDENTIFIER: u8 = 3;
pub const BGP_SUB_UNSUPPORTED_OPT_PARAM: u8 = 4;
pub const BGP_SUB_UNACCEPTABLE_HOLD_TIME: u8 = 6;

// UPDATE subcodes.
pub const BGP_SUB_MALFORMED_ATTRIBUTE_LIST: u8 = 1;
pub const BGP_SUB_UNRECOGNIZED_WELL_KNOWN_ATTR: u8 = 2;
pub const BGP_SUB_MISSING_WELL_KNOWN_ATTR: u8 = 3;
pub const BGP_SUB_ATTRIBUTE_FLAGS_ERROR: u8 = 4;
pub const BGP_SUB_ATTRIBUTE_LENGTH_ERROR: u8 = 5;
pub const BGP_SUB_INVALID_ORIGIN: u8 = 6;
/// Optional Attribute Error: an optional attribute the receiver could not
/// accept, such as MP_REACH_NLRI for a family the session never negotiated.
pub const BGP_SUB_OPTIONAL_ATTRIBUTE_ERROR: u8 = 9;
pub const BGP_SUB_INVALID_NEXT_HOP: u8 = 8;
pub const BGP_SUB_INVALID_NETWORK_FIELD: u8 = 10;
pub const BGP_SUB_MALFORMED_AS_PATH: u8 = 11;

/// A decoding failure, carrying the NOTIFICATION code/subcode the peer should be told.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BgpParseError {
    pub code: u8,
    pub subcode: u8,
    pub reason: String,
}

impl BgpParseError {
    pub fn new(code: u8, subcode: u8, reason: impl Into<String>) -> Self {
        BgpParseError {
            code,
            subcode,
            reason: reason.into(),
        }
    }

    pub fn header(subcode: u8, reason: impl Into<String>) -> Self {
        Self::new(BGP_ERR_MESSAGE_HEADER, subcode, reason)
    }

    pub fn open(subcode: u8, reason: impl Into<String>) -> Self {
        Self::new(BGP_ERR_OPEN_MESSAGE, subcode, reason)
    }

    pub fn update(subcode: u8, reason: impl Into<String>) -> Self {
        Self::new(BGP_ERR_UPDATE_MESSAGE, subcode, reason)
    }
}

impl fmt::Display for BgpParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} (code {}/{})", self.reason, self.code, self.subcode)
    }
}

impl std::error::Error for BgpParseError {}

/// An IPv4 destination prefix. Host bits below `length` are always cleared, so two
/// prefixes that describe the same destination compare and hash equal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Ipv4Prefix {
    pub address: Ipv4Address,
    pub length: u8,
}

impl Ipv4Prefix {
    pub fn new(address: Ipv4Address, length: u8) -> Self {
        let length = length.min(32);
        Ipv4Prefix {
            address: address.mask(length),
            length,
        }
    }

    pub fn contains(&self, ip: Ipv4Address) -> bool {
        ip.mask(self.length) == self.address
    }

    /// Bytes this prefix occupies in an NLRI list: one length octet plus the
    /// minimum number of address octets needed to carry `length` bits.
    pub fn encoded_len(&self) -> usize {
        1 + self.length.div_ceil(8) as usize
    }

    pub fn encode(&self, out: &mut Vec<u8>) {
        let octets = self.length.div_ceil(8) as usize;
        out.push(self.length);
        out.extend_from_slice(&self.address.0[..octets]);
    }

    /// Decodes a complete NLRI / withdrawn-routes list. Any truncation or a prefix
    /// length above 32 is rejected rather than silently clamped.
    pub fn decode_list(data: &[u8], subcode: u8) -> Result<Vec<Ipv4Prefix>, BgpParseError> {
        let mut out = Vec::new();
        let mut i = 0usize;
        while i < data.len() {
            let bits = data[i];
            if bits > 32 {
                return Err(BgpParseError::update(
                    subcode,
                    format!("prefix length {} exceeds 32 bits", bits),
                ));
            }
            let octets = bits.div_ceil(8) as usize;
            if i + 1 + octets > data.len() {
                return Err(BgpParseError::update(
                    subcode,
                    "truncated prefix in NLRI list",
                ));
            }
            let mut addr = [0u8; 4];
            addr[..octets].copy_from_slice(&data[i + 1..i + 1 + octets]);
            out.push(Ipv4Prefix::new(Ipv4Address(addr), bits));
            i += 1 + octets;
        }
        Ok(out)
    }
}

impl fmt::Display for Ipv4Prefix {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.address, self.length)
    }
}

/// ORIGIN attribute value (RFC 4271 section 5.1.1). Ordered by preference: IGP is best.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub enum BgpOrigin {
    #[default]
    Igp,
    Egp,
    Incomplete,
}

impl BgpOrigin {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(BgpOrigin::Igp),
            1 => Some(BgpOrigin::Egp),
            2 => Some(BgpOrigin::Incomplete),
            _ => None,
        }
    }

    pub fn to_u8(self) -> u8 {
        match self {
            BgpOrigin::Igp => 0,
            BgpOrigin::Egp => 1,
            BgpOrigin::Incomplete => 2,
        }
    }
}

impl fmt::Display for BgpOrigin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BgpOrigin::Igp => write!(f, "i"),
            BgpOrigin::Egp => write!(f, "e"),
            BgpOrigin::Incomplete => write!(f, "?"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AsPathSegmentKind {
    Set,
    Sequence,
}

/// One AS_PATH segment. A SET contributes 1 to the path length no matter how many
/// ASNs it holds, which is what RFC 4271 section 9.1.2.2 requires.
///
/// ASNs are held as `u32`. RFC 6793 made 4-octet ASNs the general case and
/// redefined the classic 2-octet encoding as the compatibility path, so the
/// in-memory form is the wide one and the *encoding* is what narrows.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AsPathSegment {
    pub kind: AsPathSegmentKind,
    pub asns: Vec<u32>,
}

/// The AS_PATH attribute as a list of segments, with the helpers the decision
/// process and loop detection need.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
pub struct AsPath {
    pub segments: Vec<AsPathSegment>,
}

impl AsPath {
    pub fn empty() -> Self {
        AsPath::default()
    }

    /// Builds a single AS_SEQUENCE path, leftmost ASN first.
    pub fn sequence(asns: Vec<u32>) -> Self {
        if asns.is_empty() {
            return AsPath::default();
        }
        AsPath {
            segments: vec![AsPathSegment {
                kind: AsPathSegmentKind::Sequence,
                asns,
            }],
        }
    }

    /// Path length used by the decision process: every AS in a SEQUENCE counts once,
    /// a whole SET counts once.
    pub fn length(&self) -> usize {
        self.segments
            .iter()
            .map(|s| match s.kind {
                AsPathSegmentKind::Sequence => s.asns.len(),
                AsPathSegmentKind::Set => 1,
            })
            .sum()
    }

    pub fn is_empty(&self) -> bool {
        self.segments.iter().all(|s| s.asns.is_empty())
    }

    pub fn contains(&self, asn: u32) -> bool {
        self.segments.iter().any(|s| s.asns.contains(&asn))
    }

    /// True when any ASN on the path needs more than two octets, which is what
    /// decides whether the classic encoding can carry it truthfully.
    pub fn needs_four_octets(&self) -> bool {
        self.segments
            .iter()
            .any(|s| s.asns.iter().any(|a| *a > u16::MAX as u32))
    }

    /// Leftmost ASN of the leftmost AS_SEQUENCE: the neighbouring AS that advertised
    /// the route. Used to decide whether two MEDs are comparable.
    pub fn first_as(&self) -> Option<u32> {
        self.segments
            .iter()
            .find(|s| s.kind == AsPathSegmentKind::Sequence)
            .and_then(|s| s.asns.first().copied())
    }

    /// Leftmost ASN, but only when the path genuinely *begins* with an AS_SEQUENCE.
    ///
    /// This is the stricter reading needed to police an eBGP UPDATE, which has to lead
    /// with the advertising peer's own ASN. [`AsPath::first_as`] deliberately skips a
    /// leading AS_SET to find something MED-comparable; that would be the wrong answer
    /// here, because a path that leads with an AS_SET has no leading AS at all.
    pub fn leading_as(&self) -> Option<u32> {
        match self.segments.first() {
            Some(seg) if seg.kind == AsPathSegmentKind::Sequence => seg.asns.first().copied(),
            _ => None,
        }
    }

    /// Prepends the local ASN, as an eBGP speaker must do before re-advertising.
    /// A leading SEQUENCE is extended; anything else gets a fresh SEQUENCE in front.
    pub fn prepend(&mut self, asn: u32) {
        match self.segments.first_mut() {
            Some(seg) if seg.kind == AsPathSegmentKind::Sequence && seg.asns.len() < 255 => {
                seg.asns.insert(0, asn);
            }
            _ => self.segments.insert(
                0,
                AsPathSegment {
                    kind: AsPathSegmentKind::Sequence,
                    asns: vec![asn],
                },
            ),
        }
    }

    /// Flattened ASN list, left to right. Convenient for assertions and display.
    pub fn flatten(&self) -> Vec<u32> {
        self.segments.iter().flat_map(|s| s.asns.clone()).collect()
    }

    /// Encodes the path with the classic two-octet ASN width (RFC 4271).
    ///
    /// An ASN that does not fit becomes [`AS_TRANS`], never a truncated value. The
    /// true path is preserved separately in AS4_PATH, which is exactly the split
    /// RFC 6793 defines; silently writing `asn as u16` would put a real, different,
    /// someone else's ASN on the wire.
    pub fn encode(&self) -> Vec<u8> {
        self.encode_width(false)
    }

    /// Encodes the path.
    ///
    /// `four_octet` selects the ASN width, which on a live session comes from
    /// whether both ends advertised the Four-Octet AS capability.
    ///
    /// A segment holding more than [`AS_PATH_MAX_SEGMENT_ASNS`] entries is emitted as
    /// several segments of the same kind. Writing the length as a single octet instead
    /// would truncate the count and put an AS_PATH on the wire that no decoder can
    /// read. An empty segment is dropped rather than encoded, because the wire format
    /// gives it no meaning and a decoder is required to reject it.
    pub fn encode_width(&self, four_octet: bool) -> Vec<u8> {
        let mut out = Vec::new();
        for seg in &self.segments {
            let kind = match seg.kind {
                AsPathSegmentKind::Set => BGP_AS_SET,
                AsPathSegmentKind::Sequence => BGP_AS_SEQUENCE,
            };
            for chunk in seg.asns.chunks(AS_PATH_MAX_SEGMENT_ASNS) {
                out.push(kind);
                out.push(chunk.len() as u8);
                for asn in chunk {
                    if four_octet {
                        out.extend_from_slice(&asn.to_be_bytes());
                    } else {
                        let narrow = u16::try_from(*asn).unwrap_or(AS_TRANS);
                        out.extend_from_slice(&narrow.to_be_bytes());
                    }
                }
            }
        }
        out
    }

    /// Decodes a two-octet AS_PATH (RFC 4271).
    pub fn decode(data: &[u8]) -> Result<Self, BgpParseError> {
        Self::decode_width(data, false)
    }

    /// Decodes an AS_PATH whose ASNs are two or four octets wide.
    pub fn decode_width(data: &[u8], four_octet: bool) -> Result<Self, BgpParseError> {
        let width = if four_octet { 4usize } else { 2usize };
        let mut segments = Vec::new();
        let mut i = 0usize;
        while i < data.len() {
            if i + 2 > data.len() {
                return Err(BgpParseError::update(
                    BGP_SUB_MALFORMED_AS_PATH,
                    "truncated AS_PATH segment header",
                ));
            }
            let kind = match data[i] {
                BGP_AS_SET => AsPathSegmentKind::Set,
                BGP_AS_SEQUENCE => AsPathSegmentKind::Sequence,
                other => {
                    return Err(BgpParseError::update(
                        BGP_SUB_MALFORMED_AS_PATH,
                        format!("unknown AS_PATH segment type {}", other),
                    ));
                }
            };
            let count = data[i + 1] as usize;
            if count == 0 {
                return Err(BgpParseError::update(
                    BGP_SUB_MALFORMED_AS_PATH,
                    "empty AS_PATH segment",
                ));
            }
            let end = i + 2 + count * width;
            if end > data.len() {
                return Err(BgpParseError::update(
                    BGP_SUB_MALFORMED_AS_PATH,
                    "truncated AS_PATH segment body",
                ));
            }
            let mut asns = Vec::with_capacity(count);
            for k in 0..count {
                let off = i + 2 + k * width;
                asns.push(if four_octet {
                    u32::from_be_bytes([data[off], data[off + 1], data[off + 2], data[off + 3]])
                } else {
                    u16::from_be_bytes([data[off], data[off + 1]]) as u32
                });
            }
            segments.push(AsPathSegment { kind, asns });
            i = end;
        }
        Ok(AsPath { segments })
    }

    /// Rebuilds the true path from a narrow AS_PATH and the AS4_PATH that
    /// accompanied it (RFC 6793 section 4.2.3).
    ///
    /// The rule is positional, not a merge: AS4_PATH is the *tail* of the real
    /// path, so it replaces that many trailing hops of the two-octet path and the
    /// leading hops - the ones added by AS4-unaware speakers - are kept as they
    /// are. If AS4_PATH is the longer of the two it is discarded, because it then
    /// claims hops the AS_PATH never had.
    pub fn merge_as4_path(&self, as4: &AsPath) -> AsPath {
        let narrow = self.flatten();
        let wide = as4.flatten();
        if wide.is_empty() || wide.len() > narrow.len() {
            return self.clone();
        }
        // Only a plain sequence can be spliced positionally; a path carrying an
        // AS_SET has no single well-defined hop order to graft onto.
        if self
            .segments
            .iter()
            .chain(as4.segments.iter())
            .any(|s| s.kind != AsPathSegmentKind::Sequence)
        {
            return self.clone();
        }
        let keep = narrow.len() - wide.len();
        let mut merged: Vec<u32> = narrow[..keep].to_vec();
        merged.extend_from_slice(&wide);
        AsPath::sequence(merged)
    }
}

impl fmt::Display for AsPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut first = true;
        for seg in &self.segments {
            let text = seg
                .asns
                .iter()
                .map(|a| a.to_string())
                .collect::<Vec<_>>()
                .join(" ");
            let text = match seg.kind {
                AsPathSegmentKind::Set => format!("{{{}}}", text),
                AsPathSegmentKind::Sequence => text,
            };
            if !first {
                write!(f, " ")?;
            }
            write!(f, "{}", text)?;
            first = false;
        }
        if first {
            write!(f, "-")?;
        }
        Ok(())
    }
}

/// The path attributes attached to the NLRI of one UPDATE.
///
/// The RFC 4271 attributes are held as concrete fields; the multiprotocol ones
/// (RFC 4760) and Extended Communities (RFC 4360) hang off the same struct so a
/// single UPDATE can carry an IPv4 route, an EVPN route, or a withdrawal of
/// either without a second message shape.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BgpPathAttributes {
    pub origin: BgpOrigin,
    pub as_path: AsPath,
    /// The IPv4 NEXT_HOP. Meaningful only for IPv4-unicast NLRI; a family carried
    /// in MP_REACH_NLRI has its next hop inside that attribute instead, and this
    /// field is left unspecified.
    pub next_hop: Ipv4Address,
    pub med: Option<u32>,
    pub local_pref: Option<u32>,
    pub atomic_aggregate: bool,
    /// Extended Communities, which is where an EVPN route carries its Route Targets.
    pub ext_communities: Vec<[u8; 8]>,
    pub mp_reach: Option<MpReachNlri>,
    pub mp_unreach: Option<MpUnreachNlri>,
    /// ORIGINATOR_ID (RFC 4456): the BGP identifier of the speaker that first
    /// advertised this route inside the local AS. Set by a route reflector the
    /// first time it reflects a route, and never rewritten afterwards.
    pub originator_id: Option<Ipv4Address>,
    /// CLUSTER_LIST (RFC 4456): the cluster IDs of the reflectors this route has
    /// already traversed, most recent first.
    pub cluster_list: Vec<Ipv4Address>,
    /// True when the AS_PATH on this UPDATE should be written with 4-octet ASNs,
    /// which is the case exactly when both speakers negotiated the capability.
    pub four_octet_as: bool,
}

impl BgpPathAttributes {
    pub fn new(origin: BgpOrigin, as_path: AsPath, next_hop: Ipv4Address) -> Self {
        BgpPathAttributes {
            origin,
            as_path,
            next_hop,
            med: None,
            local_pref: None,
            atomic_aggregate: false,
            ext_communities: Vec::new(),
            mp_reach: None,
            mp_unreach: None,
            originator_id: None,
            cluster_list: Vec::new(),
            four_octet_as: false,
        }
    }

    /// The attribute set of an UPDATE that only withdraws multiprotocol NLRI.
    ///
    /// RFC 4760 section 3 says such an UPDATE need carry no other path attribute,
    /// and [`BgpPathAttributes::encode_for`] emits nothing else for it.
    pub fn mp_withdraw(mp_unreach: MpUnreachNlri) -> Self {
        let mut attrs =
            BgpPathAttributes::new(BgpOrigin::Igp, AsPath::empty(), Ipv4Address::UNSPECIFIED);
        attrs.mp_unreach = Some(mp_unreach);
        attrs
    }

    /// True when this attribute set describes nothing but a multiprotocol
    /// withdrawal, and so must not carry ORIGIN, AS_PATH, or NEXT_HOP.
    fn is_mp_withdraw_only(&self, has_ipv4_nlri: bool) -> bool {
        self.mp_unreach.is_some() && self.mp_reach.is_none() && !has_ipv4_nlri
    }

    /// Encodes for an UPDATE that announces IPv4 NLRI.
    pub fn encode(&self) -> Vec<u8> {
        self.encode_for(true)
    }

    /// Encodes the attribute block.
    ///
    /// `has_ipv4_nlri` decides two things the attribute set cannot know on its
    /// own: whether the IPv4 NEXT_HOP belongs on the wire at all, and whether a
    /// lone MP_UNREACH means "this is a pure withdrawal". Emitting a NEXT_HOP
    /// beside an EVPN MP_REACH would be a second, contradictory next hop for a
    /// family that does not use it.
    pub fn encode_for(&self, has_ipv4_nlri: bool) -> Vec<u8> {
        let mut out = Vec::new();

        if self.is_mp_withdraw_only(has_ipv4_nlri) {
            if let Some(mp) = &self.mp_unreach {
                push_attribute(
                    &mut out,
                    BGP_ATTR_FLAG_OPTIONAL,
                    BGP_ATTR_MP_UNREACH_NLRI,
                    &mp.encode_value(),
                );
            }
            return out;
        }

        out.extend_from_slice(&[BGP_ATTR_FLAG_TRANSITIVE, BGP_ATTR_ORIGIN, 1]);
        out.push(self.origin.to_u8());

        let path = self.as_path.encode_width(self.four_octet_as);
        push_attribute(&mut out, BGP_ATTR_FLAG_TRANSITIVE, BGP_ATTR_AS_PATH, &path);

        // A session that did not negotiate 4-octet ASNs gets the classic AS_PATH
        // with AS_TRANS standing in, plus AS4_PATH carrying the truth. Sending
        // AS4_PATH only when it is actually needed keeps ordinary 16-bit sessions
        // byte-for-byte what they were.
        if !self.four_octet_as && self.as_path.needs_four_octets() {
            let wide = self.as_path.encode_width(true);
            push_attribute(
                &mut out,
                BGP_ATTR_FLAG_OPTIONAL | BGP_ATTR_FLAG_TRANSITIVE,
                BGP_ATTR_AS4_PATH,
                &wide,
            );
        }

        if has_ipv4_nlri {
            out.extend_from_slice(&[BGP_ATTR_FLAG_TRANSITIVE, BGP_ATTR_NEXT_HOP, 4]);
            out.extend_from_slice(&self.next_hop.0);
        }

        if let Some(med) = self.med {
            out.extend_from_slice(&[BGP_ATTR_FLAG_OPTIONAL, BGP_ATTR_MED, 4]);
            out.extend_from_slice(&med.to_be_bytes());
        }

        if let Some(lp) = self.local_pref {
            out.extend_from_slice(&[BGP_ATTR_FLAG_TRANSITIVE, BGP_ATTR_LOCAL_PREF, 4]);
            out.extend_from_slice(&lp.to_be_bytes());
        }

        if self.atomic_aggregate {
            out.extend_from_slice(&[BGP_ATTR_FLAG_TRANSITIVE, BGP_ATTR_ATOMIC_AGGREGATE, 0]);
        }

        // The two reflection attributes are optional *non-transitive*: they
        // describe reflection inside one autonomous system, and an eBGP speaker
        // that received them would have no cluster topology to interpret them
        // against. The flag byte carries OPTIONAL and not TRANSITIVE, which is
        // what tells a receiver to drop them rather than pass them on.
        if let Some(id) = self.originator_id {
            out.extend_from_slice(&[BGP_ATTR_FLAG_OPTIONAL, BGP_ATTR_ORIGINATOR_ID, 4]);
            out.extend_from_slice(&id.0);
        }

        if !self.cluster_list.is_empty() {
            let mut value = Vec::with_capacity(self.cluster_list.len() * 4);
            for id in &self.cluster_list {
                value.extend_from_slice(&id.0);
            }
            push_attribute(
                &mut out,
                BGP_ATTR_FLAG_OPTIONAL,
                BGP_ATTR_CLUSTER_LIST,
                &value,
            );
        }

        if !self.ext_communities.is_empty() {
            let mut value = Vec::with_capacity(self.ext_communities.len() * 8);
            for comm in &self.ext_communities {
                value.extend_from_slice(comm);
            }
            push_attribute(
                &mut out,
                BGP_ATTR_FLAG_OPTIONAL | BGP_ATTR_FLAG_TRANSITIVE,
                BGP_ATTR_EXT_COMMUNITIES,
                &value,
            );
        }

        if let Some(mp) = &self.mp_reach {
            push_attribute(
                &mut out,
                BGP_ATTR_FLAG_OPTIONAL,
                BGP_ATTR_MP_REACH_NLRI,
                &mp.encode_value(),
            );
        }

        if let Some(mp) = &self.mp_unreach {
            push_attribute(
                &mut out,
                BGP_ATTR_FLAG_OPTIONAL,
                BGP_ATTR_MP_UNREACH_NLRI,
                &mp.encode_value(),
            );
        }

        out
    }
}

/// Appends one path attribute, choosing the one- or two-octet length form.
///
/// A value of 256 bytes or more - an EVPN UPDATE carrying many routes, or a long
/// Extended Communities list - does not fit the single length octet, and writing
/// `len as u8` would silently truncate the attribute and desynchronise the
/// receiver's parser. The Extended Length flag exists for exactly this case.
fn push_attribute(out: &mut Vec<u8>, flags: u8, type_code: u8, value: &[u8]) {
    if value.len() > u8::MAX as usize {
        out.push(flags | BGP_ATTR_FLAG_EXT_LEN);
        out.push(type_code);
        out.extend_from_slice(&(value.len() as u16).to_be_bytes());
    } else {
        out.push(flags);
        out.push(type_code);
        out.push(value.len() as u8);
    }
    out.extend_from_slice(value);
}

/// A decoded UPDATE: routes being withdrawn, the attributes for the announced
/// routes, and the announced NLRI. An UPDATE with neither NLRI nor withdrawn
/// routes and no attributes is the End-of-RIB marker and decodes cleanly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BgpUpdateMessage {
    pub withdrawn: Vec<Ipv4Prefix>,
    pub attributes: Option<BgpPathAttributes>,
    pub nlri: Vec<Ipv4Prefix>,
}

impl BgpUpdateMessage {
    pub fn announce(attributes: BgpPathAttributes, nlri: Vec<Ipv4Prefix>) -> Self {
        BgpUpdateMessage {
            withdrawn: Vec::new(),
            attributes: Some(attributes),
            nlri,
        }
    }

    pub fn withdraw(withdrawn: Vec<Ipv4Prefix>) -> Self {
        BgpUpdateMessage {
            withdrawn,
            attributes: None,
            nlri: Vec::new(),
        }
    }

    /// An UPDATE that announces multiprotocol NLRI: no IPv4 NLRI, the family's
    /// routes and next hop inside MP_REACH_NLRI.
    pub fn mp_announce(attributes: BgpPathAttributes) -> Self {
        BgpUpdateMessage {
            withdrawn: Vec::new(),
            attributes: Some(attributes),
            nlri: Vec::new(),
        }
    }

    /// An UPDATE that withdraws multiprotocol NLRI and nothing else.
    pub fn mp_withdraw(mp_unreach: MpUnreachNlri) -> Self {
        BgpUpdateMessage {
            withdrawn: Vec::new(),
            attributes: Some(BgpPathAttributes::mp_withdraw(mp_unreach)),
            nlri: Vec::new(),
        }
    }

    /// The MP_REACH_NLRI attribute, if this UPDATE carries one.
    pub fn mp_reach(&self) -> Option<&MpReachNlri> {
        self.attributes.as_ref().and_then(|a| a.mp_reach.as_ref())
    }

    /// The MP_UNREACH_NLRI attribute, if this UPDATE carries one.
    pub fn mp_unreach(&self) -> Option<&MpUnreachNlri> {
        self.attributes.as_ref().and_then(|a| a.mp_unreach.as_ref())
    }

    pub fn end_of_rib() -> Self {
        BgpUpdateMessage {
            withdrawn: Vec::new(),
            attributes: None,
            nlri: Vec::new(),
        }
    }

    pub fn is_end_of_rib(&self) -> bool {
        self.withdrawn.is_empty() && self.nlri.is_empty() && self.attributes.is_none()
    }

    fn encode_body(&self) -> Vec<u8> {
        let mut withdrawn_bytes = Vec::new();
        for p in &self.withdrawn {
            p.encode(&mut withdrawn_bytes);
        }
        // Attributes belong on the wire whenever they describe something: IPv4
        // NLRI, or a multiprotocol announcement or withdrawal. An UPDATE that only
        // withdraws IPv4 prefixes still carries none, as RFC 4271 requires.
        let attr_bytes = match &self.attributes {
            Some(a) if !self.nlri.is_empty() || a.mp_reach.is_some() || a.mp_unreach.is_some() => {
                a.encode_for(!self.nlri.is_empty())
            }
            _ => Vec::new(),
        };

        let mut body = Vec::new();
        body.extend_from_slice(&(withdrawn_bytes.len() as u16).to_be_bytes());
        body.extend_from_slice(&withdrawn_bytes);
        body.extend_from_slice(&(attr_bytes.len() as u16).to_be_bytes());
        body.extend_from_slice(&attr_bytes);
        for p in &self.nlri {
            p.encode(&mut body);
        }
        body
    }

    /// Decodes an UPDATE body (everything after the 19-byte header), reading
    /// AS_PATH with the classic two-octet ASN width.
    pub fn parse_body(body: &[u8]) -> Result<Self, BgpParseError> {
        Self::parse_body_width(body, false)
    }

    /// Decodes an UPDATE body. `four_octet_as` must be what the session
    /// negotiated, because the AS_PATH encoding depends on it and nothing in the
    /// message itself records which width was used.
    pub fn parse_body_width(body: &[u8], four_octet_as: bool) -> Result<Self, BgpParseError> {
        if body.len() < 4 {
            return Err(BgpParseError::update(
                BGP_SUB_MALFORMED_ATTRIBUTE_LIST,
                "UPDATE body shorter than the two length fields",
            ));
        }
        let withdrawn_len = u16::from_be_bytes([body[0], body[1]]) as usize;
        if 2 + withdrawn_len + 2 > body.len() {
            return Err(BgpParseError::update(
                BGP_SUB_MALFORMED_ATTRIBUTE_LIST,
                "withdrawn routes length runs past the end of the UPDATE",
            ));
        }
        let withdrawn =
            Ipv4Prefix::decode_list(&body[2..2 + withdrawn_len], BGP_SUB_INVALID_NETWORK_FIELD)?;

        let attr_len_off = 2 + withdrawn_len;
        let attr_len = u16::from_be_bytes([body[attr_len_off], body[attr_len_off + 1]]) as usize;
        let attr_start = attr_len_off + 2;
        let attr_end = attr_start.saturating_add(attr_len);
        if attr_end > body.len() {
            return Err(BgpParseError::update(
                BGP_SUB_MALFORMED_ATTRIBUTE_LIST,
                "path attribute length runs past the end of the UPDATE",
            ));
        }

        let parsed = Self::parse_attributes(&body[attr_start..attr_end], four_octet_as)?;
        let nlri = Ipv4Prefix::decode_list(&body[attr_end..], BGP_SUB_INVALID_NETWORK_FIELD)?;

        // Which attributes are mandatory depends on what the UPDATE actually says.
        //
        //  * IPv4 NLRI needs ORIGIN, AS_PATH and NEXT_HOP (RFC 4271 section 5).
        //  * MP_REACH_NLRI needs ORIGIN and AS_PATH, but not NEXT_HOP: the family
        //    carries its own inside the attribute (RFC 4760 section 3).
        //  * A pure withdrawal, IPv4 or multiprotocol, needs none of them.
        let announces_mp = parsed.mp_reach.is_some();
        let describes_routes = !nlri.is_empty() || announces_mp || parsed.mp_unreach.is_some();

        let attributes = if describes_routes {
            Some(parsed.into_attributes(!nlri.is_empty(), announces_mp)?)
        } else {
            None
        };

        Ok(BgpUpdateMessage {
            withdrawn,
            attributes,
            nlri,
        })
    }

    /// Decodes the path attribute block, enforcing flags and lengths.
    ///
    /// Which attributes are *required* is not decided here: that depends on what
    /// the UPDATE announces, which the caller knows and this does not.
    fn parse_attributes(
        data: &[u8],
        four_octet_as: bool,
    ) -> Result<ParsedAttributes, BgpParseError> {
        let mut parsed = ParsedAttributes::default();
        if data.is_empty() {
            return Ok(parsed);
        }

        let ParsedAttributes {
            ref mut origin,
            ref mut as_path,
            ref mut as4_path,
            ref mut next_hop,
            ref mut med,
            ref mut local_pref,
            ref mut atomic_aggregate,
            ref mut ext_communities,
            ref mut mp_reach,
            ref mut mp_unreach,
            ref mut originator_id,
            ref mut cluster_list,
        } = parsed;
        let mut seen: Vec<u8> = Vec::new();

        let mut i = 0usize;
        while i < data.len() {
            if i + 2 > data.len() {
                return Err(BgpParseError::update(
                    BGP_SUB_MALFORMED_ATTRIBUTE_LIST,
                    "truncated path attribute header",
                ));
            }
            let flags = data[i];
            let type_code = data[i + 1];
            let extended = flags & BGP_ATTR_FLAG_EXT_LEN != 0;
            let (len, hdr) = if extended {
                if i + 4 > data.len() {
                    return Err(BgpParseError::update(
                        BGP_SUB_ATTRIBUTE_LENGTH_ERROR,
                        "truncated extended attribute length",
                    ));
                }
                (u16::from_be_bytes([data[i + 2], data[i + 3]]) as usize, 4)
            } else {
                if i + 3 > data.len() {
                    return Err(BgpParseError::update(
                        BGP_SUB_ATTRIBUTE_LENGTH_ERROR,
                        "truncated attribute length",
                    ));
                }
                (data[i + 2] as usize, 3)
            };
            let val_start = i + hdr;
            let val_end = val_start.saturating_add(len);
            if val_end > data.len() {
                return Err(BgpParseError::update(
                    BGP_SUB_ATTRIBUTE_LENGTH_ERROR,
                    format!(
                        "attribute {} claims {} bytes but only {} remain",
                        type_code,
                        len,
                        data.len() - val_start
                    ),
                ));
            }
            if seen.contains(&type_code) {
                return Err(BgpParseError::update(
                    BGP_SUB_MALFORMED_ATTRIBUTE_LIST,
                    format!("duplicate path attribute {}", type_code),
                ));
            }
            seen.push(type_code);

            let value = &data[val_start..val_end];
            let optional = flags & BGP_ATTR_FLAG_OPTIONAL != 0;

            match type_code {
                BGP_ATTR_ORIGIN => {
                    if optional {
                        return Err(BgpParseError::update(
                            BGP_SUB_ATTRIBUTE_FLAGS_ERROR,
                            "ORIGIN marked optional",
                        ));
                    }
                    if value.len() != 1 {
                        return Err(BgpParseError::update(
                            BGP_SUB_ATTRIBUTE_LENGTH_ERROR,
                            "ORIGIN must be exactly one byte",
                        ));
                    }
                    *origin = Some(BgpOrigin::from_u8(value[0]).ok_or_else(|| {
                        BgpParseError::update(
                            BGP_SUB_INVALID_ORIGIN,
                            format!("undefined ORIGIN value {}", value[0]),
                        )
                    })?);
                }
                BGP_ATTR_AS_PATH => {
                    if optional {
                        return Err(BgpParseError::update(
                            BGP_SUB_ATTRIBUTE_FLAGS_ERROR,
                            "AS_PATH marked optional",
                        ));
                    }
                    // The bytes alone do not say how wide the ASNs are: a two-ASN
                    // 4-octet segment and a four-ASN 2-octet one are the same
                    // length and both decode. Only the session knows, because it
                    // negotiated it, so the width is passed in rather than guessed.
                    *as_path = Some(AsPath::decode_width(value, four_octet_as)?);
                }
                BGP_ATTR_AS4_PATH => {
                    if !optional {
                        return Err(BgpParseError::update(
                            BGP_SUB_ATTRIBUTE_FLAGS_ERROR,
                            "AS4_PATH must be marked optional",
                        ));
                    }
                    *as4_path = Some(AsPath::decode_width(value, true)?);
                }
                BGP_ATTR_NEXT_HOP => {
                    if optional {
                        return Err(BgpParseError::update(
                            BGP_SUB_ATTRIBUTE_FLAGS_ERROR,
                            "NEXT_HOP marked optional",
                        ));
                    }
                    if value.len() != 4 {
                        return Err(BgpParseError::update(
                            BGP_SUB_ATTRIBUTE_LENGTH_ERROR,
                            "NEXT_HOP must be exactly four bytes",
                        ));
                    }
                    *next_hop = Some(Ipv4Address([value[0], value[1], value[2], value[3]]));
                }
                BGP_ATTR_MED => {
                    if value.len() != 4 {
                        return Err(BgpParseError::update(
                            BGP_SUB_ATTRIBUTE_LENGTH_ERROR,
                            "MULTI_EXIT_DISC must be exactly four bytes",
                        ));
                    }
                    *med = Some(u32::from_be_bytes([value[0], value[1], value[2], value[3]]));
                }
                BGP_ATTR_LOCAL_PREF => {
                    if value.len() != 4 {
                        return Err(BgpParseError::update(
                            BGP_SUB_ATTRIBUTE_LENGTH_ERROR,
                            "LOCAL_PREF must be exactly four bytes",
                        ));
                    }
                    *local_pref =
                        Some(u32::from_be_bytes([value[0], value[1], value[2], value[3]]));
                }
                BGP_ATTR_ATOMIC_AGGREGATE => {
                    if !value.is_empty() {
                        return Err(BgpParseError::update(
                            BGP_SUB_ATTRIBUTE_LENGTH_ERROR,
                            "ATOMIC_AGGREGATE must be empty",
                        ));
                    }
                    *atomic_aggregate = true;
                }
                BGP_ATTR_EXT_COMMUNITIES => {
                    // Every extended community is exactly eight bytes; a length
                    // that is not a multiple of eight means the list is truncated
                    // and the Route Targets in it cannot be trusted.
                    if value.is_empty() || !value.len().is_multiple_of(8) {
                        return Err(BgpParseError::update(
                            BGP_SUB_ATTRIBUTE_LENGTH_ERROR,
                            format!(
                                "EXTENDED_COMMUNITIES is {} bytes, must be a non-zero multiple of 8",
                                value.len()
                            ),
                        ));
                    }
                    for chunk in value.chunks_exact(8) {
                        let mut comm = [0u8; 8];
                        comm.copy_from_slice(chunk);
                        ext_communities.push(comm);
                    }
                }
                BGP_ATTR_ORIGINATOR_ID => {
                    // Optional and non-transitive. A speaker that marks it
                    // transitive would have it leak out of the AS it describes,
                    // so the flags are checked, not just tolerated.
                    if !optional || flags & BGP_ATTR_FLAG_TRANSITIVE != 0 {
                        return Err(BgpParseError::update(
                            BGP_SUB_ATTRIBUTE_FLAGS_ERROR,
                            "ORIGINATOR_ID must be optional and non-transitive",
                        ));
                    }
                    if value.len() != 4 {
                        return Err(BgpParseError::update(
                            BGP_SUB_ATTRIBUTE_LENGTH_ERROR,
                            format!(
                                "ORIGINATOR_ID is {} bytes, must be exactly four",
                                value.len()
                            ),
                        ));
                    }
                    *originator_id = Some(Ipv4Address([value[0], value[1], value[2], value[3]]));
                }
                BGP_ATTR_CLUSTER_LIST => {
                    if !optional || flags & BGP_ATTR_FLAG_TRANSITIVE != 0 {
                        return Err(BgpParseError::update(
                            BGP_SUB_ATTRIBUTE_FLAGS_ERROR,
                            "CLUSTER_LIST must be optional and non-transitive",
                        ));
                    }
                    // Every cluster ID is exactly four bytes. A length that is
                    // not a multiple of four means the list is truncated, and a
                    // truncated cluster list cannot be trusted for the one thing
                    // it exists to do: detect a reflection loop.
                    if value.is_empty() || !value.len().is_multiple_of(4) {
                        return Err(BgpParseError::update(
                            BGP_SUB_ATTRIBUTE_LENGTH_ERROR,
                            format!(
                                "CLUSTER_LIST is {} bytes, must be a non-zero multiple of 4",
                                value.len()
                            ),
                        ));
                    }
                    if value.len() / 4 > MAX_CLUSTER_LIST_LEN {
                        return Err(BgpParseError::update(
                            BGP_SUB_ATTRIBUTE_LENGTH_ERROR,
                            format!(
                                "CLUSTER_LIST carries {} cluster IDs, more than the {} accepted",
                                value.len() / 4,
                                MAX_CLUSTER_LIST_LEN
                            ),
                        ));
                    }
                    for chunk in value.chunks_exact(4) {
                        cluster_list.push(Ipv4Address([chunk[0], chunk[1], chunk[2], chunk[3]]));
                    }
                }
                BGP_ATTR_MP_REACH_NLRI => {
                    if !optional {
                        return Err(BgpParseError::update(
                            BGP_SUB_ATTRIBUTE_FLAGS_ERROR,
                            "MP_REACH_NLRI must be marked optional",
                        ));
                    }
                    *mp_reach = Some(MpReachNlri::parse_value(value)?);
                }
                BGP_ATTR_MP_UNREACH_NLRI => {
                    if !optional {
                        return Err(BgpParseError::update(
                            BGP_SUB_ATTRIBUTE_FLAGS_ERROR,
                            "MP_UNREACH_NLRI must be marked optional",
                        ));
                    }
                    *mp_unreach = Some(MpUnreachNlri::parse_value(value)?);
                }
                other => {
                    // Unknown optional attributes are ignored, exactly as RFC 4271
                    // section 5 requires. An unknown *well-known* attribute is an error.
                    if !optional {
                        return Err(BgpParseError::update(
                            BGP_SUB_UNRECOGNIZED_WELL_KNOWN_ATTR,
                            format!("unrecognized well-known attribute {}", other),
                        ));
                    }
                }
            }

            i = val_end;
        }

        Ok(parsed)
    }
}

/// The path attributes of one UPDATE, before it is known which of them the
/// message was required to carry.
#[derive(Debug, Clone, Default)]
struct ParsedAttributes {
    origin: Option<BgpOrigin>,
    as_path: Option<AsPath>,
    as4_path: Option<AsPath>,
    next_hop: Option<Ipv4Address>,
    med: Option<u32>,
    local_pref: Option<u32>,
    atomic_aggregate: bool,
    ext_communities: Vec<[u8; 8]>,
    mp_reach: Option<MpReachNlri>,
    mp_unreach: Option<MpUnreachNlri>,
    originator_id: Option<Ipv4Address>,
    cluster_list: Vec<Ipv4Address>,
}

impl ParsedAttributes {
    /// Enforces the mandatory attributes for what this UPDATE actually announces,
    /// then folds AS4_PATH into AS_PATH.
    fn into_attributes(
        self,
        has_ipv4_nlri: bool,
        announces_mp: bool,
    ) -> Result<BgpPathAttributes, BgpParseError> {
        let missing = |what: &str| {
            BgpParseError::update(
                BGP_SUB_MISSING_WELL_KNOWN_ATTR,
                format!("UPDATE has no {}", what),
            )
        };

        // A pure multiprotocol withdrawal is allowed to carry nothing at all
        // (RFC 4760 section 3), so the well-known attributes are only demanded
        // when the UPDATE announces something.
        let announces = has_ipv4_nlri || announces_mp;
        let origin = match self.origin {
            Some(o) => o,
            None if !announces => BgpOrigin::Igp,
            None => return Err(missing("ORIGIN")),
        };
        let as_path = match self.as_path {
            Some(p) => p,
            None if !announces => AsPath::empty(),
            None => return Err(missing("AS_PATH")),
        };
        // NEXT_HOP is mandatory only for IPv4 NLRI. A family carried in
        // MP_REACH_NLRI has its own next hop in that attribute.
        let next_hop = match self.next_hop {
            Some(nh) => nh,
            None if !has_ipv4_nlri => Ipv4Address::UNSPECIFIED,
            None => return Err(missing("NEXT_HOP")),
        };

        let as_path = match &self.as4_path {
            Some(as4) => as_path.merge_as4_path(as4),
            None => as_path,
        };

        Ok(BgpPathAttributes {
            origin,
            as_path,
            next_hop,
            med: self.med,
            local_pref: self.local_pref,
            atomic_aggregate: self.atomic_aggregate,
            ext_communities: self.ext_communities,
            mp_reach: self.mp_reach,
            mp_unreach: self.mp_unreach,
            originator_id: self.originator_id,
            cluster_list: self.cluster_list,
            four_octet_as: false,
        })
    }
}

/// A decoded OPEN message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BgpOpenMessage {
    pub version: u8,
    pub my_as: u16,
    pub hold_time: u16,
    pub bgp_id: Ipv4Address,
    pub opt_params: Vec<u8>,
}

impl BgpOpenMessage {
    /// An OPEN with no optional parameters: a plain RFC 4271 speaker.
    ///
    /// `my_as` is a `u32` like every other ASN in this crate. Without the
    /// Four-Octet AS capability there is nowhere to put a value above 65535, so
    /// one becomes [`AS_TRANS`] - which is what a legacy speaker would see on the
    /// wire anyway, and is never a silent truncation to a different real AS.
    pub fn new(my_as: u32, hold_time: u16, bgp_id: Ipv4Address) -> Self {
        BgpOpenMessage {
            version: BGP_VERSION,
            my_as: u16::try_from(my_as).unwrap_or(AS_TRANS),
            hold_time,
            bgp_id,
            opt_params: Vec::new(),
        }
    }

    /// Builds an OPEN for a speaker with a 32-bit ASN and a capability set.
    ///
    /// The two-octet `My Autonomous System` field cannot hold an ASN above 65535,
    /// so RFC 6793 puts [`AS_TRANS`] there and the real value in the Four-Octet AS
    /// capability. Truncating instead would name a different, real AS.
    pub fn with_capabilities(
        my_as: u32,
        hold_time: u16,
        bgp_id: Ipv4Address,
        capabilities: &BgpCapabilitySet,
    ) -> Self {
        BgpOpenMessage {
            version: BGP_VERSION,
            my_as: u16::try_from(my_as).unwrap_or(AS_TRANS),
            hold_time,
            bgp_id,
            opt_params: capabilities.encode_opt_params(),
        }
    }

    /// The capabilities this OPEN advertises.
    pub fn capabilities(&self) -> Result<BgpCapabilitySet, BgpParseError> {
        BgpCapabilitySet::parse_opt_params(&self.opt_params)
    }

    /// The ASN this OPEN really claims.
    ///
    /// The Four-Octet AS capability wins when present, because the two-octet field
    /// may only be carrying [`AS_TRANS`]. A capability that disagrees with a
    /// perfectly representable `my_as` is a contradiction, and the wider field is
    /// treated as authoritative so a 4-octet peer is never misread as AS 23456.
    pub fn effective_as(&self, capabilities: &BgpCapabilitySet) -> u32 {
        capabilities.four_octet_as().unwrap_or(self.my_as as u32)
    }

    fn encode_body(&self) -> Vec<u8> {
        let mut body = Vec::with_capacity(10 + self.opt_params.len());
        body.push(self.version);
        body.extend_from_slice(&self.my_as.to_be_bytes());
        body.extend_from_slice(&self.hold_time.to_be_bytes());
        body.extend_from_slice(&self.bgp_id.0);
        body.push(self.opt_params.len() as u8);
        body.extend_from_slice(&self.opt_params);
        body
    }

    pub fn parse_body(body: &[u8]) -> Result<Self, BgpParseError> {
        if body.len() < 10 {
            return Err(BgpParseError::header(
                BGP_SUB_BAD_MESSAGE_LENGTH,
                "OPEN body shorter than the 10-byte fixed part",
            ));
        }
        let opt_len = body[9] as usize;
        if 10 + opt_len > body.len() {
            return Err(BgpParseError::open(
                BGP_SUB_UNSUPPORTED_OPT_PARAM,
                "optional parameter length runs past the end of the OPEN",
            ));
        }
        Ok(BgpOpenMessage {
            version: body[0],
            my_as: u16::from_be_bytes([body[1], body[2]]),
            hold_time: u16::from_be_bytes([body[3], body[4]]),
            bgp_id: Ipv4Address([body[5], body[6], body[7], body[8]]),
            opt_params: body[10..10 + opt_len].to_vec(),
        })
    }
}

/// A decoded NOTIFICATION message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BgpNotificationMessage {
    pub error_code: u8,
    pub error_subcode: u8,
    pub data: Vec<u8>,
}

impl BgpNotificationMessage {
    pub fn new(error_code: u8, error_subcode: u8) -> Self {
        BgpNotificationMessage {
            error_code,
            error_subcode,
            data: Vec::new(),
        }
    }

    pub fn describe(&self) -> String {
        let code = match self.error_code {
            BGP_ERR_MESSAGE_HEADER => "Message Header Error",
            BGP_ERR_OPEN_MESSAGE => "OPEN Message Error",
            BGP_ERR_UPDATE_MESSAGE => "UPDATE Message Error",
            BGP_ERR_HOLD_TIMER_EXPIRED => "Hold Timer Expired",
            BGP_ERR_FSM => "Finite State Machine Error",
            BGP_ERR_CEASE => "Cease",
            _ => "Unknown Error",
        };
        format!("{} ({}/{})", code, self.error_code, self.error_subcode)
    }
}

/// RFC 2918 ROUTE-REFRESH request. The four-byte body names exactly one
/// address family whose routes the peer asks us to advertise again.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BgpRouteRefreshMessage {
    pub family: AfiSafi,
}

impl BgpRouteRefreshMessage {
    pub const fn new(family: AfiSafi) -> Self {
        BgpRouteRefreshMessage { family }
    }

    fn encode_body(&self) -> Vec<u8> {
        let mut body = Vec::with_capacity(4);
        body.extend_from_slice(&self.family.afi.to_be_bytes());
        body.push(0); // Reserved, sent as zero and ignored by receivers.
        body.push(self.family.safi);
        body
    }

    fn parse_body(body: &[u8]) -> Result<Self, BgpParseError> {
        if body.len() != 4 {
            return Err(BgpParseError::header(
                BGP_SUB_BAD_MESSAGE_LENGTH,
                format!(
                    "ROUTE-REFRESH body is {} bytes, must be exactly 4",
                    body.len()
                ),
            ));
        }
        Ok(BgpRouteRefreshMessage {
            family: AfiSafi::new(u16::from_be_bytes([body[0], body[1]]), body[3]),
        })
    }
}

/// A fully decoded BGP protocol data unit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BgpPdu {
    Open(BgpOpenMessage),
    Update(BgpUpdateMessage),
    Notification(BgpNotificationMessage),
    Keepalive,
    RouteRefresh(BgpRouteRefreshMessage),
}

impl BgpPdu {
    pub fn type_code(&self) -> u8 {
        match self {
            BgpPdu::Open(_) => BGP_MSG_OPEN,
            BgpPdu::Update(_) => BGP_MSG_UPDATE,
            BgpPdu::Notification(_) => BGP_MSG_NOTIFICATION,
            BgpPdu::Keepalive => BGP_MSG_KEEPALIVE,
            BgpPdu::RouteRefresh(_) => BGP_MSG_ROUTE_REFRESH,
        }
    }

    pub fn type_name(&self) -> &'static str {
        match self {
            BgpPdu::Open(_) => "OPEN",
            BgpPdu::Update(_) => "UPDATE",
            BgpPdu::Notification(_) => "NOTIFICATION",
            BgpPdu::Keepalive => "KEEPALIVE",
            BgpPdu::RouteRefresh(_) => "ROUTE-REFRESH",
        }
    }

    /// Serializes into a complete on-the-wire message including the 19-byte header.
    pub fn serialize(&self) -> Vec<u8> {
        let body = match self {
            BgpPdu::Open(o) => o.encode_body(),
            BgpPdu::Update(u) => u.encode_body(),
            BgpPdu::Notification(n) => {
                let mut b = vec![n.error_code, n.error_subcode];
                b.extend_from_slice(&n.data);
                b
            }
            BgpPdu::Keepalive => Vec::new(),
            BgpPdu::RouteRefresh(r) => r.encode_body(),
        };
        let total = BGP_HEADER_LEN + body.len();
        let mut out = Vec::with_capacity(total);
        out.extend_from_slice(&BGP_MARKER);
        out.extend_from_slice(&(total as u16).to_be_bytes());
        out.push(self.type_code());
        out.extend_from_slice(&body);
        out
    }

    /// Decodes one complete framed message. `frame` must be exactly one message as
    /// produced by `BgpFramer`; trailing bytes are rejected rather than ignored.
    pub fn parse(frame: &[u8]) -> Result<Self, BgpParseError> {
        Self::parse_width(frame, false)
    }

    /// Decodes one complete framed message, reading AS_PATH with the ASN width
    /// the session negotiated.
    pub fn parse_width(frame: &[u8], four_octet_as: bool) -> Result<Self, BgpParseError> {
        let (msg_type, body) = parse_bgp_header(frame)?;
        match msg_type {
            BGP_MSG_OPEN => Ok(BgpPdu::Open(BgpOpenMessage::parse_body(body)?)),
            BGP_MSG_UPDATE => Ok(BgpPdu::Update(BgpUpdateMessage::parse_body_width(
                body,
                four_octet_as,
            )?)),
            BGP_MSG_NOTIFICATION => {
                if body.len() < 2 {
                    return Err(BgpParseError::header(
                        BGP_SUB_BAD_MESSAGE_LENGTH,
                        "NOTIFICATION shorter than its two-byte error code",
                    ));
                }
                Ok(BgpPdu::Notification(BgpNotificationMessage {
                    error_code: body[0],
                    error_subcode: body[1],
                    data: body[2..].to_vec(),
                }))
            }
            BGP_MSG_KEEPALIVE => {
                if !body.is_empty() {
                    return Err(BgpParseError::header(
                        BGP_SUB_BAD_MESSAGE_LENGTH,
                        "KEEPALIVE must be exactly 19 bytes",
                    ));
                }
                Ok(BgpPdu::Keepalive)
            }
            BGP_MSG_ROUTE_REFRESH => Ok(BgpPdu::RouteRefresh(
                BgpRouteRefreshMessage::parse_body(body)?,
            )),
            other => Err(BgpParseError::header(
                BGP_SUB_BAD_MESSAGE_TYPE,
                format!("unsupported message type {}", other),
            )),
        }
    }
}

/// Validates the 19-byte header and returns `(message_type, body)`.
///
/// Every field is checked before any of it is trusted: the marker must be the
/// all-ones pattern, the length must be inside the type's legal range, and the
/// frame must be exactly as long as the length field claims.
pub fn parse_bgp_header(frame: &[u8]) -> Result<(u8, &[u8]), BgpParseError> {
    if frame.len() < BGP_HEADER_LEN {
        return Err(BgpParseError::header(
            BGP_SUB_BAD_MESSAGE_LENGTH,
            format!("frame of {} bytes is shorter than the header", frame.len()),
        ));
    }
    if frame[0..16] != BGP_MARKER {
        return Err(BgpParseError::header(
            BGP_SUB_CONNECTION_NOT_SYNCHRONIZED,
            "marker is not the all-ones synchronisation pattern",
        ));
    }
    let length = u16::from_be_bytes([frame[16], frame[17]]) as usize;
    let msg_type = frame[18];
    if !(BGP_HEADER_LEN..=BGP_MAX_MESSAGE_LEN).contains(&length) {
        return Err(BgpParseError::header(
            BGP_SUB_BAD_MESSAGE_LENGTH,
            format!("length field {} is outside 19..=4096", length),
        ));
    }
    let min_len = match msg_type {
        BGP_MSG_OPEN => BGP_HEADER_LEN + 10,
        BGP_MSG_UPDATE => BGP_HEADER_LEN + 4,
        BGP_MSG_NOTIFICATION => BGP_HEADER_LEN + 2,
        BGP_MSG_KEEPALIVE => BGP_HEADER_LEN,
        BGP_MSG_ROUTE_REFRESH => BGP_HEADER_LEN + 4,
        other => {
            return Err(BgpParseError::header(
                BGP_SUB_BAD_MESSAGE_TYPE,
                format!("unsupported message type {}", other),
            ));
        }
    };
    if length < min_len {
        return Err(BgpParseError::header(
            BGP_SUB_BAD_MESSAGE_LENGTH,
            format!("length {} too small for message type {}", length, msg_type),
        ));
    }
    if frame.len() != length {
        return Err(BgpParseError::header(
            BGP_SUB_BAD_MESSAGE_LENGTH,
            format!(
                "frame carries {} bytes but the length field says {}",
                frame.len(),
                length
            ),
        ));
    }
    Ok((msg_type, &frame[BGP_HEADER_LEN..length]))
}

/// Message-type byte of a framed BGP message, without decoding the body.
/// Used by capture assertions and diagnostics.
pub fn peek_bgp_message_type(frame: &[u8]) -> Option<u8> {
    if frame.len() >= BGP_HEADER_LEN && frame[0..16] == BGP_MARKER {
        Some(frame[18])
    } else {
        None
    }
}

/// Reassembles BGP messages out of a TCP byte stream.
///
/// TCP gives no message boundaries, so a read may deliver half a header, half a
/// message, or six messages at once. The framer buffers whatever arrives and hands
/// back one complete message at a time. The buffer is hard-capped: a peer cannot
/// make it grow without bound, because a header is validated as soon as 19 bytes
/// are present and no legal message exceeds 4096 bytes.
#[derive(Debug, Clone)]
pub struct BgpFramer {
    buf: Vec<u8>,
    capacity: usize,
    pub bytes_received: u64,
    pub messages_decoded: u64,
}

/// Framer buffer cap: enough for one maximum-size message plus a partial follow-on.
pub const BGP_FRAMER_CAPACITY: usize = 2 * BGP_MAX_MESSAGE_LEN;

impl Default for BgpFramer {
    fn default() -> Self {
        Self::new()
    }
}

impl BgpFramer {
    pub fn new() -> Self {
        Self::with_capacity(BGP_FRAMER_CAPACITY)
    }

    pub fn with_capacity(capacity: usize) -> Self {
        BgpFramer {
            buf: Vec::new(),
            capacity: capacity.max(BGP_MAX_MESSAGE_LEN),
            bytes_received: 0,
            messages_decoded: 0,
        }
    }

    /// Appends freshly read stream bytes. Rejects input that would push the
    /// reassembly buffer past its cap instead of growing without limit.
    pub fn push(&mut self, data: &[u8]) -> Result<(), BgpParseError> {
        if self.buf.len() + data.len() > self.capacity {
            return Err(BgpParseError::new(
                BGP_ERR_CEASE,
                0,
                format!(
                    "reassembly buffer would exceed {} bytes; peer is not framing BGP",
                    self.capacity
                ),
            ));
        }
        self.buf.extend_from_slice(data);
        self.bytes_received += data.len() as u64;
        Ok(())
    }

    /// Pops the next complete message, or `Ok(None)` when more bytes are needed.
    /// A structurally invalid header is a hard error: the stream is desynchronised
    /// and the session must be torn down rather than resynchronised by guessing.
    pub fn next_frame(&mut self) -> Result<Option<Vec<u8>>, BgpParseError> {
        if self.buf.len() < BGP_HEADER_LEN {
            return Ok(None);
        }
        if self.buf[0..16] != BGP_MARKER {
            return Err(BgpParseError::header(
                BGP_SUB_CONNECTION_NOT_SYNCHRONIZED,
                "marker is not the all-ones synchronisation pattern",
            ));
        }
        let length = u16::from_be_bytes([self.buf[16], self.buf[17]]) as usize;
        if !(BGP_HEADER_LEN..=BGP_MAX_MESSAGE_LEN).contains(&length) {
            return Err(BgpParseError::header(
                BGP_SUB_BAD_MESSAGE_LENGTH,
                format!("length field {} is outside 19..=4096", length),
            ));
        }
        if self.buf.len() < length {
            return Ok(None);
        }
        let frame: Vec<u8> = self.buf.drain(..length).collect();
        self.messages_decoded += 1;
        Ok(Some(frame))
    }

    /// Returns the next complete message *without* consuming it.
    ///
    /// Connection collision resolution (RFC 4271 section 6.8) needs the peer's
    /// BGP identifier out of an OPEN before it knows which of two connections to
    /// keep. If the connection that carried it wins, that OPEN still has to be
    /// processed by the ordinary FSM, so it must still be in the buffer.
    pub fn peek_frame(&self) -> Result<Option<&[u8]>, BgpParseError> {
        if self.buf.len() < BGP_HEADER_LEN {
            return Ok(None);
        }
        if self.buf[0..16] != BGP_MARKER {
            return Err(BgpParseError::header(
                BGP_SUB_CONNECTION_NOT_SYNCHRONIZED,
                "marker is not the all-ones synchronisation pattern",
            ));
        }
        let length = u16::from_be_bytes([self.buf[16], self.buf[17]]) as usize;
        if !(BGP_HEADER_LEN..=BGP_MAX_MESSAGE_LEN).contains(&length) {
            return Err(BgpParseError::header(
                BGP_SUB_BAD_MESSAGE_LENGTH,
                format!("length field {} is outside 19..=4096", length),
            ));
        }
        if self.buf.len() < length {
            return Ok(None);
        }
        Ok(Some(&self.buf[..length]))
    }

    /// Bytes currently held awaiting the rest of a message.
    pub fn buffered(&self) -> usize {
        self.buf.len()
    }

    pub fn reset(&mut self) {
        self.buf.clear();
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bgp_open_and_keepalive_roundtrip() {
        let open = BgpMessage::build_open(65001, 180, Ipv4Address::new(10, 0, 0, 1));
        let raw_open = open.serialize();

        let parsed = BgpMessage::parse(&raw_open).unwrap();
        if let BgpMessage::Open {
            my_as,
            hold_time,
            bgp_id,
            ..
        } = parsed
        {
            assert_eq!(my_as, 65001);
            assert_eq!(hold_time, 180);
            assert_eq!(bgp_id, Ipv4Address::new(10, 0, 0, 1));
        } else {
            panic!("Expected Open message");
        }

        let keepalive = BgpMessage::Keepalive;
        let raw_ka = keepalive.serialize();
        assert_eq!(raw_ka.len(), 19);
        assert_eq!(BgpMessage::parse(&raw_ka).unwrap(), BgpMessage::Keepalive);
    }

    #[test]
    fn test_route_refresh_round_trips_and_has_an_exact_four_byte_body() {
        let sent = BgpPdu::RouteRefresh(BgpRouteRefreshMessage::new(AfiSafi::L2VPN_EVPN));
        let mut raw = sent.serialize();
        assert_eq!(raw.len(), BGP_HEADER_LEN + 4);
        assert_eq!(raw[18], BGP_MSG_ROUTE_REFRESH);
        assert_eq!(BgpPdu::parse(&raw).unwrap(), sent);

        // The reserved octet is ignored on receipt as RFC 2918 requires.
        raw[21] = 0x7f;
        assert_eq!(BgpPdu::parse(&raw).unwrap(), sent);

        // A fifth body byte is not padding: the message has exactly one shape.
        raw.push(0);
        raw[16..18].copy_from_slice(&((BGP_HEADER_LEN + 5) as u16).to_be_bytes());
        assert!(BgpPdu::parse(&raw).is_err());
    }

    #[test]
    fn test_as_path_length_counts_a_set_as_one_hop() {
        let mut path = AsPath::sequence(vec![65001, 65002]);
        assert_eq!(path.length(), 2);

        path.segments.push(AsPathSegment {
            kind: AsPathSegmentKind::Set,
            asns: vec![65010, 65011, 65012],
        });
        // The whole SET contributes one hop, not three (RFC 4271 section 9.1.2.2).
        assert_eq!(path.length(), 3);
        assert!(path.contains(65011));
        assert_eq!(path.first_as(), Some(65001));
    }

    #[test]
    fn test_as_path_prepend_extends_a_leading_sequence() {
        let mut path = AsPath::sequence(vec![65002, 65003]);
        path.prepend(65001);
        assert_eq!(path.segments.len(), 1, "prepend should not add a segment");
        assert_eq!(path.flatten(), vec![65001, 65002, 65003]);
        assert_eq!(path.length(), 3);
        assert_eq!(path.first_as(), Some(65001));

        // Prepending in front of a SET has to create a new SEQUENCE instead.
        let mut path = AsPath {
            segments: vec![AsPathSegment {
                kind: AsPathSegmentKind::Set,
                asns: vec![65005, 65006],
            }],
        };
        path.prepend(65001);
        assert_eq!(path.segments.len(), 2);
        assert_eq!(path.segments[0].kind, AsPathSegmentKind::Sequence);
        assert_eq!(path.length(), 2);
        assert_eq!(path.first_as(), Some(65001));

        // An empty path is the locally originated case.
        let mut empty = AsPath::empty();
        assert!(empty.is_empty());
        assert_eq!(empty.first_as(), None);
        empty.prepend(65001);
        assert_eq!(empty.flatten(), vec![65001]);
    }

    #[test]
    fn test_as_path_round_trips_including_sets() {
        let path = AsPath {
            segments: vec![
                AsPathSegment {
                    kind: AsPathSegmentKind::Sequence,
                    asns: vec![65001, 65002],
                },
                AsPathSegment {
                    kind: AsPathSegmentKind::Set,
                    asns: vec![65010, 65011],
                },
            ],
        };
        let encoded = path.encode();
        assert_eq!(AsPath::decode(&encoded).unwrap(), path);
        assert_eq!(path.to_string(), "65001 65002 {65010 65011}");
    }

    #[test]
    fn test_bgp_update_nlri_and_as_path() {
        let update = BgpMessage::build_update(
            Ipv4Address::new(172, 16, 0, 0),
            16,
            Ipv4Address::new(192, 168, 1, 1),
            vec![65001, 65002, 65003],
        );
        let raw = update.serialize();
        let parsed = BgpMessage::parse(&raw).unwrap();

        if let BgpMessage::Update {
            as_path,
            next_hop,
            nlri_prefix,
            nlri_mask,
        } = parsed
        {
            assert_eq!(as_path, vec![65001, 65002, 65003]);
            assert_eq!(next_hop, Ipv4Address::new(192, 168, 1, 1));
            assert_eq!(nlri_prefix, Ipv4Address::new(172, 16, 0, 0));
            assert_eq!(nlri_mask, 16);
        } else {
            panic!("Expected Update message");
        }
    }

    #[test]
    fn test_a_segment_longer_than_255_asns_is_split_rather_than_truncated() {
        // The segment count is one octet. Writing 300 as a u8 would put 44 on the
        // wire and leave the remaining ASNs to be read as segment headers, producing
        // a stream no decoder can follow.
        let asns: Vec<u32> = (0..300u32).map(|i| 1_000u32 + i).collect();
        let encoded = AsPath::sequence(asns.clone()).encode();
        let decoded = AsPath::decode(&encoded).expect("a 300-ASN path must survive encoding");

        assert_eq!(decoded.segments.len(), 2);
        assert_eq!(decoded.segments[0].asns.len(), AS_PATH_MAX_SEGMENT_ASNS);
        assert_eq!(decoded.segments[1].asns.len(), 45);
        // Splitting an AS_SEQUENCE changes nothing that matters: same ASNs, same
        // order, and the decision process still counts the same number of hops.
        assert_eq!(decoded.flatten(), asns);
        assert_eq!(decoded.length(), 300);
    }

    #[test]
    fn test_an_empty_segment_is_dropped_instead_of_encoded() {
        let path = AsPath {
            segments: vec![AsPathSegment {
                kind: AsPathSegmentKind::Sequence,
                asns: Vec::new(),
            }],
        };
        // A zero-length segment is what a decoder is required to reject, so emitting
        // one would mean generating a message we would refuse ourselves.
        assert!(path.encode().is_empty());
        assert!(AsPath::decode(&path.encode()).unwrap().is_empty());
    }

    #[test]
    fn test_leading_as_is_stricter_than_first_as() {
        let seq = AsPath::sequence(vec![65002, 65003]);
        assert_eq!(seq.leading_as(), Some(65002));
        assert_eq!(seq.first_as(), Some(65002));

        // A path that opens with an AS_SET has no leading AS at all, even though
        // first_as happily skips ahead to the sequence behind it to compare MEDs.
        let set_first = AsPath {
            segments: vec![
                AsPathSegment {
                    kind: AsPathSegmentKind::Set,
                    asns: vec![65010, 65011],
                },
                AsPathSegment {
                    kind: AsPathSegmentKind::Sequence,
                    asns: vec![65002],
                },
            ],
        };
        assert_eq!(set_first.leading_as(), None);
        assert_eq!(set_first.first_as(), Some(65002));

        assert_eq!(AsPath::empty().leading_as(), None);
    }
}

#[cfg(test)]
mod reflection_tests {
    use super::*;

    fn attrs_with(
        originator: Option<Ipv4Address>,
        clusters: Vec<Ipv4Address>,
    ) -> BgpPathAttributes {
        let mut a = BgpPathAttributes::new(
            BgpOrigin::Igp,
            AsPath::empty(),
            Ipv4Address::new(10, 0, 0, 1),
        );
        a.local_pref = Some(100);
        a.originator_id = originator;
        a.cluster_list = clusters;
        a
    }

    /// Walks an encoded attribute block, yielding `(flags, type, value)` for each
    /// attribute.
    ///
    /// Scanning for a type byte with a sliding window would find one inside a
    /// value - a cluster list of 10.0.0.x addresses is full of bytes that happen
    /// to equal the CLUSTER_LIST type code - so the block is parsed rather than
    /// searched.
    fn walk_attributes(encoded: &[u8]) -> Vec<(u8, u8, Vec<u8>)> {
        let mut out = Vec::new();
        let mut i = 0usize;
        while i + 3 <= encoded.len() {
            let flags = encoded[i];
            let type_code = encoded[i + 1];
            let extended = flags & BGP_ATTR_FLAG_EXT_LEN != 0;
            let (len, hdr) = if extended {
                if i + 4 > encoded.len() {
                    break;
                }
                (
                    u16::from_be_bytes([encoded[i + 2], encoded[i + 3]]) as usize,
                    4,
                )
            } else {
                (encoded[i + 2] as usize, 3)
            };
            let end = i + hdr + len;
            if end > encoded.len() {
                break;
            }
            out.push((flags, type_code, encoded[i + hdr..end].to_vec()));
            i = end;
        }
        out
    }

    fn round_trip(a: &BgpPathAttributes) -> BgpPathAttributes {
        let nlri = vec![Ipv4Prefix::new(Ipv4Address::new(172, 16, 0, 0), 24)];
        let frame = BgpPdu::Update(BgpUpdateMessage::announce(a.clone(), nlri)).serialize();
        match BgpPdu::parse(&frame).expect("the UPDATE did not decode") {
            BgpPdu::Update(u) => u.attributes.expect("no attributes came back"),
            other => panic!("expected an UPDATE, got {}", other.type_name()),
        }
    }

    #[test]
    fn test_originator_id_and_cluster_list_survive_the_wire() {
        let clusters = vec![
            Ipv4Address::new(10, 0, 0, 254),
            Ipv4Address::new(10, 0, 0, 253),
        ];
        let sent = attrs_with(Some(Ipv4Address::new(1, 1, 1, 1)), clusters.clone());
        let back = round_trip(&sent);

        assert_eq!(back.originator_id, Some(Ipv4Address::new(1, 1, 1, 1)));
        assert_eq!(back.cluster_list, clusters, "the cluster order changed");
        // The rest of the attribute set is untouched by carrying them.
        assert_eq!(back.origin, sent.origin);
        assert_eq!(back.next_hop, sent.next_hop);
        assert_eq!(back.local_pref, sent.local_pref);
    }

    #[test]
    fn test_a_route_with_no_reflection_metadata_encodes_none() {
        let sent = attrs_with(None, Vec::new());
        let encoded = sent.encode();
        assert!(
            !walk_attributes(&encoded)
                .iter()
                .any(|(_, t, _)| *t == BGP_ATTR_ORIGINATOR_ID || *t == BGP_ATTR_CLUSTER_LIST),
            "reflection metadata was written for a route that has none"
        );
        let back = round_trip(&sent);
        assert_eq!(back.originator_id, None);
        assert!(back.cluster_list.is_empty());
    }

    #[test]
    fn test_both_attributes_are_optional_and_non_transitive_on_the_wire() {
        let sent = attrs_with(
            Some(Ipv4Address::new(1, 1, 1, 1)),
            vec![Ipv4Address::new(9, 9, 9, 9)],
        );
        let mut seen = 0;
        for (flags, type_code, _) in walk_attributes(&sent.encode()) {
            if type_code != BGP_ATTR_ORIGINATOR_ID && type_code != BGP_ATTR_CLUSTER_LIST {
                continue;
            }
            seen += 1;
            assert_ne!(
                flags & BGP_ATTR_FLAG_OPTIONAL,
                0,
                "attribute {} was not marked optional",
                type_code
            );
            assert_eq!(
                flags & BGP_ATTR_FLAG_TRANSITIVE,
                0,
                "attribute {} was marked transitive; it must not leave the AS",
                type_code
            );
        }
        assert_eq!(seen, 2, "one of the two attributes was not encoded at all");
    }

    #[test]
    fn test_a_long_cluster_list_uses_the_extended_length_form() {
        // 64 cluster IDs is 256 bytes, one past what a single length octet can
        // describe. Writing `len as u8` would truncate it to zero and leave the
        // receiver's parser reading cluster IDs as attribute headers.
        let clusters: Vec<Ipv4Address> = (0..64)
            .map(|i| Ipv4Address::new(10, 0, 0, i as u8))
            .collect();
        let sent = attrs_with(None, clusters.clone());
        let (flags, _, value) = walk_attributes(&sent.encode())
            .into_iter()
            .find(|(_, t, _)| *t == BGP_ATTR_CLUSTER_LIST)
            .expect("no CLUSTER_LIST was encoded");
        assert_ne!(
            flags & BGP_ATTR_FLAG_EXT_LEN,
            0,
            "a 256-byte CLUSTER_LIST was written with the one-octet length form"
        );
        assert_eq!(value.len(), clusters.len() * 4);
    }
}
