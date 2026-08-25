//! IPv6 Unicast MP-BGP NLRI and routing-information bases (RFC 4760 / RFC 2545).
//!
//! BGP transport in this stack remains IPv4/TCP, exactly as a real MP-BGP session
//! may do. IPv6 reachability is carried inside MP_REACH_NLRI / MP_UNREACH_NLRI and
//! therefore needs its own prefix type and RIBs, not a second transport protocol.

use crate::bgp::{
    AsPath, BGP_DEFAULT_LOCAL_PREF, BGP_SUB_INVALID_NETWORK_FIELD, BgpOrigin, BgpParseError,
};
use crate::bgp_rib::PathSource;
use crate::ipv4::Ipv4Address;
use crate::ipv6::Ipv6Address;
use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

/// One IPv6 unicast destination prefix. Host bits are always cleared.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Ipv6Prefix {
    pub address: Ipv6Address,
    pub length: u8,
}

impl Ipv6Prefix {
    pub fn new(address: Ipv6Address, length: u8) -> Self {
        let length = length.min(128);
        Ipv6Prefix {
            address: mask_address(address, length),
            length,
        }
    }

    pub fn contains(&self, address: Ipv6Address) -> bool {
        mask_address(address, self.length) == self.address
    }

    pub fn encoded_len(&self) -> usize {
        1 + self.length.div_ceil(8) as usize
    }

    pub fn encode(&self, out: &mut Vec<u8>) {
        let octets = self.length.div_ceil(8) as usize;
        out.push(self.length);
        out.extend_from_slice(&self.address.0[..octets]);
    }

    /// Decodes an RFC 4760 IPv6-Unicast NLRI list.
    pub fn decode_list(data: &[u8]) -> Result<Vec<Ipv6Prefix>, BgpParseError> {
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
            let mut bytes = [0u8; 16];
            bytes[..octets].copy_from_slice(&data[offset + 1..offset + 1 + octets]);
            out.push(Ipv6Prefix::new(Ipv6Address(bytes), bits));
            offset += 1 + octets;
        }
        Ok(out)
    }
}

impl fmt::Display for Ipv6Prefix {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.address, self.length)
    }
}

fn mask_address(address: Ipv6Address, length: u8) -> Ipv6Address {
    let length = length.min(128);
    let mut bytes = address.0;
    let whole = (length / 8) as usize;
    let rem = length % 8;
    if rem != 0 && whole < bytes.len() {
        bytes[whole] &= 0xff << (8 - rem);
    }
    let clear_from = whole + usize::from(rem != 0);
    for byte in &mut bytes[clear_from..] {
        *byte = 0;
    }
    Ipv6Address(bytes)
}

pub fn encode_ipv6_nlri_list(prefixes: &[Ipv6Prefix]) -> Vec<u8> {
    let mut out = Vec::with_capacity(prefixes.iter().map(Ipv6Prefix::encoded_len).sum());
    for prefix in prefixes {
        prefix.encode(&mut out);
    }
    out
}

/// One path to an IPv6-Unicast prefix.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ipv6Path {
    pub prefix: Ipv6Prefix,
    pub source: PathSource,
    /// The BGP neighbour is still identified by the IPv4 address of the TCP session.
    pub peer_addr: Ipv4Address,
    pub peer_as: u32,
    pub peer_router_id: Ipv4Address,
    pub origin: BgpOrigin,
    pub as_path: AsPath,
    pub next_hop: Ipv6Address,
    pub med: Option<u32>,
    pub local_pref: u32,
    pub atomic_aggregate: bool,
    pub originator_id: Option<Ipv4Address>,
    pub cluster_list: Vec<Ipv4Address>,
    pub from_client: bool,
    pub received_at_ms: u64,
}

impl Ipv6Path {
    pub fn local(prefix: Ipv6Prefix, next_hop: Ipv6Address, router_id: Ipv4Address) -> Self {
        Ipv6Path {
            prefix,
            source: PathSource::Local,
            peer_addr: Ipv4Address::UNSPECIFIED,
            peer_as: 0,
            peer_router_id: router_id,
            origin: BgpOrigin::Igp,
            as_path: AsPath::empty(),
            next_hop,
            med: None,
            local_pref: BGP_DEFAULT_LOCAL_PREF,
            atomic_aggregate: false,
            originator_id: None,
            cluster_list: Vec::new(),
            from_client: false,
            received_at_ms: 0,
        }
    }

    pub fn is_local(&self) -> bool {
        self.source == PathSource::Local
    }

    pub fn is_ebgp(&self) -> bool {
        self.source == PathSource::Ebgp
    }

    pub fn same_route_as(&self, other: &Ipv6Path) -> bool {
        self.prefix == other.prefix
            && self.source == other.source
            && self.peer_addr == other.peer_addr
            && self.peer_as == other.peer_as
            && self.peer_router_id == other.peer_router_id
            && self.origin == other.origin
            && self.as_path == other.as_path
            && self.next_hop == other.next_hop
            && self.med == other.med
            && self.local_pref == other.local_pref
            && self.atomic_aggregate == other.atomic_aggregate
            && self.originator_id == other.originator_id
            && self.cluster_list == other.cluster_list
            && self.from_client == other.from_client
    }
}

/// RFC 4271-style best-path ordering for IPv6 Unicast.
pub fn compare_ipv6_paths(a: &Ipv6Path, b: &Ipv6Path) -> Ordering {
    match (a.is_local(), b.is_local()) {
        (true, false) => return Ordering::Less,
        (false, true) => return Ordering::Greater,
        _ => {}
    }
    match b.local_pref.cmp(&a.local_pref) {
        Ordering::Equal => {}
        other => return other,
    }
    match a.as_path.length().cmp(&b.as_path.length()) {
        Ordering::Equal => {}
        other => return other,
    }
    match a.origin.cmp(&b.origin) {
        Ordering::Equal => {}
        other => return other,
    }
    let (first_a, first_b) = (a.as_path.first_as(), b.as_path.first_as());
    if first_a.is_some() && first_a == first_b {
        match a.med.unwrap_or(0).cmp(&b.med.unwrap_or(0)) {
            Ordering::Equal => {}
            other => return other,
        }
    }
    match (a.is_ebgp(), b.is_ebgp()) {
        (true, false) => return Ordering::Less,
        (false, true) => return Ordering::Greater,
        _ => {}
    }
    match a.cluster_list.len().cmp(&b.cluster_list.len()) {
        Ordering::Equal => {}
        other => return other,
    }
    a.peer_router_id
        .cmp(&b.peer_router_id)
        .then(a.peer_addr.cmp(&b.peer_addr))
}

pub fn select_best_ipv6<'a>(candidates: &[&'a Ipv6Path]) -> Option<&'a Ipv6Path> {
    candidates
        .iter()
        .copied()
        .reduce(|best, next| match compare_ipv6_paths(next, best) {
            Ordering::Less => next,
            _ => best,
        })
}

#[derive(Debug, Clone, Default)]
pub struct Ipv6AdjRibIn {
    tables: BTreeMap<Ipv4Address, BTreeMap<Ipv6Prefix, Ipv6Path>>,
}

impl Ipv6AdjRibIn {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, peer: Ipv4Address, path: Ipv6Path) -> Option<Ipv6Path> {
        self.tables
            .entry(peer)
            .or_default()
            .insert(path.prefix, path)
    }

    pub fn remove(&mut self, peer: Ipv4Address, prefix: Ipv6Prefix) -> Option<Ipv6Path> {
        let removed = self
            .tables
            .get_mut(&peer)
            .and_then(|table| table.remove(&prefix));
        if self.tables.get(&peer).is_some_and(BTreeMap::is_empty) {
            self.tables.remove(&peer);
        }
        removed
    }

    pub fn clear_peer(&mut self, peer: Ipv4Address) -> usize {
        self.tables
            .remove(&peer)
            .map(|table| table.len())
            .unwrap_or(0)
    }

    pub fn peer_table(&self, peer: Ipv4Address) -> Option<&BTreeMap<Ipv6Prefix, Ipv6Path>> {
        self.tables.get(&peer)
    }

    pub fn peer_table_mut(
        &mut self,
        peer: Ipv4Address,
    ) -> Option<&mut BTreeMap<Ipv6Prefix, Ipv6Path>> {
        self.tables.get_mut(&peer)
    }

    pub fn prefix_count(&self, peer: Ipv4Address) -> usize {
        self.tables.get(&peer).map(BTreeMap::len).unwrap_or(0)
    }

    pub fn path_count(&self) -> usize {
        self.tables.values().map(BTreeMap::len).sum()
    }

    pub fn prefixes(&self) -> BTreeSet<Ipv6Prefix> {
        self.tables
            .values()
            .flat_map(|table| table.keys().copied())
            .collect()
    }

    pub fn candidates(&self, prefix: Ipv6Prefix) -> Vec<&Ipv6Path> {
        self.tables
            .values()
            .filter_map(|table| table.get(&prefix))
            .collect()
    }

    pub fn iter_paths(&self) -> impl Iterator<Item = &Ipv6Path> {
        self.tables.values().flat_map(|table| table.values())
    }
}

#[derive(Debug, Clone, Default)]
pub struct Ipv6LocRib {
    best: BTreeMap<Ipv6Prefix, Ipv6Path>,
}

impl Ipv6LocRib {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn get(&self, prefix: &Ipv6Prefix) -> Option<&Ipv6Path> {
        self.best.get(prefix)
    }

    pub fn contains(&self, prefix: &Ipv6Prefix) -> bool {
        self.best.contains_key(prefix)
    }

    pub fn insert(&mut self, path: Ipv6Path) -> Option<Ipv6Path> {
        self.best.insert(path.prefix, path)
    }

    pub fn remove(&mut self, prefix: &Ipv6Prefix) -> Option<Ipv6Path> {
        self.best.remove(prefix)
    }

    pub fn len(&self) -> usize {
        self.best.len()
    }

    pub fn is_empty(&self) -> bool {
        self.best.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = (&Ipv6Prefix, &Ipv6Path)> {
        self.best.iter()
    }

    pub fn prefixes(&self) -> Vec<Ipv6Prefix> {
        self.best.keys().copied().collect()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ipv6AdvertisedRoute {
    pub origin: BgpOrigin,
    pub as_path: AsPath,
    pub next_hop: Ipv6Address,
    pub med: Option<u32>,
    pub local_pref: Option<u32>,
    pub originator_id: Option<Ipv4Address>,
    pub cluster_list: Vec<Ipv4Address>,
}

#[derive(Debug, Clone, Default)]
pub struct Ipv6AdjRibOut {
    tables: BTreeMap<Ipv4Address, BTreeMap<Ipv6Prefix, Ipv6AdvertisedRoute>>,
}

impl Ipv6AdjRibOut {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn get(&self, peer: Ipv4Address, prefix: &Ipv6Prefix) -> Option<&Ipv6AdvertisedRoute> {
        self.tables.get(&peer).and_then(|table| table.get(prefix))
    }

    pub fn insert(&mut self, peer: Ipv4Address, prefix: Ipv6Prefix, route: Ipv6AdvertisedRoute) {
        self.tables.entry(peer).or_default().insert(prefix, route);
    }

    pub fn remove(
        &mut self,
        peer: Ipv4Address,
        prefix: &Ipv6Prefix,
    ) -> Option<Ipv6AdvertisedRoute> {
        let removed = self
            .tables
            .get_mut(&peer)
            .and_then(|table| table.remove(prefix));
        if self.tables.get(&peer).is_some_and(BTreeMap::is_empty) {
            self.tables.remove(&peer);
        }
        removed
    }

    pub fn clear_peer(&mut self, peer: Ipv4Address) -> usize {
        self.tables
            .remove(&peer)
            .map(|table| table.len())
            .unwrap_or(0)
    }

    pub fn prefixes(&self, peer: Ipv4Address) -> Vec<Ipv6Prefix> {
        self.tables
            .get(&peer)
            .map(|table| table.keys().copied().collect())
            .unwrap_or_default()
    }

    pub fn prefix_count(&self, peer: Ipv4Address) -> usize {
        self.tables.get(&peer).map(BTreeMap::len).unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    fn ip(text: &str) -> Ipv6Address {
        Ipv6Address::from_str(text).unwrap()
    }

    #[test]
    fn ipv6_prefix_masks_and_round_trips_all_interesting_lengths() {
        for length in [0, 1, 7, 8, 63, 64, 65, 127, 128] {
            let prefix = Ipv6Prefix::new(ip("2001:db8:1234:5678:9abc:def0:1234:5678"), length);
            let raw = encode_ipv6_nlri_list(&[prefix]);
            assert_eq!(Ipv6Prefix::decode_list(&raw).unwrap(), vec![prefix]);
            assert_eq!(raw.len(), prefix.encoded_len());
        }
    }

    #[test]
    fn ipv6_prefix_decoder_rejects_bad_lengths_and_truncation() {
        assert!(Ipv6Prefix::decode_list(&[129]).is_err());
        assert!(Ipv6Prefix::decode_list(&[64, 0x20, 0x01]).is_err());
    }

    #[test]
    fn local_path_wins_over_learned_path() {
        let prefix = Ipv6Prefix::new(ip("2001:db8:1::"), 48);
        let local = Ipv6Path::local(prefix, ip("2001:db8::1"), Ipv4Address::new(1, 1, 1, 1));
        let mut learned = local.clone();
        learned.source = PathSource::Ebgp;
        learned.peer_addr = Ipv4Address::new(10, 0, 0, 2);
        learned.peer_as = 65002;
        learned.as_path = AsPath::sequence(vec![65002]);
        assert_eq!(select_best_ipv6(&[&learned, &local]), Some(&local));
    }
}
