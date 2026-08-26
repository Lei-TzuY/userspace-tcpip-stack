//! IPv6 routing table and Longest Prefix Match (LPM) lookup.
//!
//! Kept separate from the IPv4 table so existing callers remain source-compatible
//! while the dual-stack data plane grows independently.

use crate::ipv6::Ipv6Address;
use crate::router::RouteSource;
use std::fmt;

fn mask_address(address: Ipv6Address, prefix_len: u8) -> Ipv6Address {
    let prefix_len = prefix_len.min(128);
    let mut bytes = address.0;
    let whole = (prefix_len / 8) as usize;
    let rem = prefix_len % 8;
    if rem != 0 && whole < bytes.len() {
        bytes[whole] &= 0xff << (8 - rem);
    }
    let clear_from = whole + usize::from(rem != 0);
    for byte in &mut bytes[clear_from..] {
        *byte = 0;
    }
    Ipv6Address(bytes)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ipv6RouteEntry {
    pub destination: Ipv6Address,
    pub prefix_len: u8,
    pub gateway: Option<Ipv6Address>,
    pub interface: String,
    pub source: RouteSource,
}

impl Ipv6RouteEntry {
    pub fn new(
        destination: Ipv6Address,
        prefix_len: u8,
        gateway: Option<Ipv6Address>,
        interface: &str,
    ) -> Self {
        Self::with_source(
            destination,
            prefix_len,
            gateway,
            interface,
            RouteSource::Static,
        )
    }

    pub fn with_source(
        destination: Ipv6Address,
        prefix_len: u8,
        gateway: Option<Ipv6Address>,
        interface: &str,
        source: RouteSource,
    ) -> Self {
        let prefix_len = prefix_len.min(128);
        Ipv6RouteEntry {
            destination: mask_address(destination, prefix_len),
            prefix_len,
            gateway,
            interface: interface.to_string(),
            source,
        }
    }

    pub fn matches(&self, address: Ipv6Address) -> bool {
        mask_address(address, self.prefix_len) == self.destination
    }

    pub fn next_hop(&self, destination: Ipv6Address) -> Ipv6Address {
        self.gateway.unwrap_or(destination)
    }

    pub fn distance(&self) -> u8 {
        self.source.distance()
    }
}

impl fmt::Display for Ipv6RouteEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let gateway = self
            .gateway
            .map(|g| g.to_string())
            .unwrap_or_else(|| "on-link".to_string());
        write!(
            f,
            "{}/{} via {} dev {} [{}/{}]",
            self.destination,
            self.prefix_len,
            gateway,
            self.interface,
            self.source,
            self.distance()
        )
    }
}

#[derive(Debug, Default, Clone)]
pub struct Ipv6RoutingTable {
    routes: Vec<Ipv6RouteEntry>,
}

impl Ipv6RoutingTable {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_route(
        &mut self,
        destination: Ipv6Address,
        prefix_len: u8,
        gateway: Option<Ipv6Address>,
        interface: &str,
    ) {
        self.add_route_from(
            destination,
            prefix_len,
            gateway,
            interface,
            RouteSource::Static,
        );
    }

    pub fn add_route_from(
        &mut self,
        destination: Ipv6Address,
        prefix_len: u8,
        gateway: Option<Ipv6Address>,
        interface: &str,
        source: RouteSource,
    ) {
        let entry =
            Ipv6RouteEntry::with_source(destination, prefix_len, gateway, interface, source);
        let key = (entry.destination, entry.prefix_len);
        if let Some(existing) = self
            .routes
            .iter_mut()
            .find(|r| (r.destination, r.prefix_len) == key && r.source == source)
        {
            *existing = entry;
        } else {
            self.routes.push(entry);
        }
        self.sort();
    }

    /// Adds one route without replacing another route from the same source that
    /// targets the same prefix through a different next hop or interface.
    ///
    /// The legacy `add_route_from` API intentionally keeps its replacement
    /// semantics for source compatibility. This explicit multipath API is used by
    /// control planes that legitimately need several candidates for one prefix,
    /// such as an IPv6 Default Router List.
    pub fn add_multipath_route_from(
        &mut self,
        destination: Ipv6Address,
        prefix_len: u8,
        gateway: Option<Ipv6Address>,
        interface: &str,
        source: RouteSource,
    ) {
        let entry =
            Ipv6RouteEntry::with_source(destination, prefix_len, gateway, interface, source);
        let duplicate = self.routes.iter().any(|route| {
            route.destination == entry.destination
                && route.prefix_len == entry.prefix_len
                && route.gateway == entry.gateway
                && route.interface == entry.interface
                && route.source == entry.source
        });
        if !duplicate {
            self.routes.push(entry);
            self.sort();
        }
    }

    pub fn remove_route(
        &mut self,
        destination: Ipv6Address,
        prefix_len: u8,
        source: RouteSource,
    ) -> bool {
        let key = (mask_address(destination, prefix_len), prefix_len.min(128));
        let before = self.routes.len();
        self.routes
            .retain(|r| !((r.destination, r.prefix_len) == key && r.source == source));
        self.routes.len() != before
    }

    /// Removes only the matching next-hop candidate, preserving other routes to
    /// the same prefix and from the same source.
    pub fn remove_route_via(
        &mut self,
        destination: Ipv6Address,
        prefix_len: u8,
        gateway: Option<Ipv6Address>,
        interface: &str,
        source: RouteSource,
    ) -> bool {
        let key = (mask_address(destination, prefix_len), prefix_len.min(128));
        let before = self.routes.len();
        self.routes.retain(|route| {
            !((route.destination, route.prefix_len) == key
                && route.gateway == gateway
                && route.interface == interface
                && route.source == source)
        });
        self.routes.len() != before
    }

    pub fn remove_all_from(&mut self, source: RouteSource) -> usize {
        let before = self.routes.len();
        self.routes.retain(|r| r.source != source);
        before - self.routes.len()
    }

    pub fn lookup(&self, destination: Ipv6Address) -> Option<&Ipv6RouteEntry> {
        self.routes.iter().find(|route| route.matches(destination))
    }

    /// Returns every route tied for the best Longest Prefix Match and
    /// administrative distance. Ordering is deterministic and follows the route
    /// table's stable insertion order among equal-cost candidates.
    pub fn lookup_best_routes(&self, destination: Ipv6Address) -> Vec<&Ipv6RouteEntry> {
        let Some(best) = self.lookup(destination) else {
            return Vec::new();
        };
        self.routes
            .iter()
            .filter(|route| {
                route.matches(destination)
                    && route.prefix_len == best.prefix_len
                    && route.distance() == best.distance()
            })
            .collect()
    }

    pub fn find_exact(&self, destination: Ipv6Address, prefix_len: u8) -> Option<&Ipv6RouteEntry> {
        let key = (mask_address(destination, prefix_len), prefix_len.min(128));
        self.routes
            .iter()
            .find(|route| (route.destination, route.prefix_len) == key)
    }

    pub fn all_routes(&self) -> &[Ipv6RouteEntry] {
        &self.routes
    }

    pub fn routes_from(&self, source: RouteSource) -> Vec<&Ipv6RouteEntry> {
        self.routes.iter().filter(|r| r.source == source).collect()
    }

    pub fn len(&self) -> usize {
        self.routes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.routes.is_empty()
    }

    fn sort(&mut self) {
        self.routes.sort_by(|a, b| {
            b.prefix_len
                .cmp(&a.prefix_len)
                .then(a.distance().cmp(&b.distance()))
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    fn ip(s: &str) -> Ipv6Address {
        Ipv6Address::from_str(s).unwrap()
    }

    #[test]
    fn longest_prefix_match_handles_default_and_odd_bit_prefixes() {
        let mut table = Ipv6RoutingTable::new();
        table.add_route(ip("::"), 0, Some(ip("fe80::1")), "eth0");
        table.add_route(ip("2001:db8:10::"), 48, None, "eth1");
        table.add_route(ip("2001:db8:10:0:8000::"), 65, None, "eth2");

        assert_eq!(
            table
                .lookup(ip("2001:db8:10:0:8000::1"))
                .unwrap()
                .prefix_len,
            65
        );
        assert_eq!(
            table.lookup(ip("2001:db8:10:ffff::1")).unwrap().prefix_len,
            48
        );
        assert_eq!(
            table.lookup(ip("2001:4860:4860::8888")).unwrap().prefix_len,
            0
        );
    }

    #[test]
    fn connected_beats_bgp_and_source_scoped_replacement_is_deterministic() {
        let mut table = Ipv6RoutingTable::new();
        let prefix = ip("2001:db8:20::");
        table.add_route_from(prefix, 64, Some(ip("fe80::2")), "eth1", RouteSource::Bgp);
        table.add_route_from(prefix, 64, None, "eth0", RouteSource::Connected);
        assert_eq!(
            table.lookup(ip("2001:db8:20::7")).unwrap().source,
            RouteSource::Connected
        );

        table.add_route_from(prefix, 64, Some(ip("fe80::3")), "eth2", RouteSource::Bgp);
        assert_eq!(table.routes_from(RouteSource::Bgp).len(), 1);
        assert_eq!(
            table.routes_from(RouteSource::Bgp)[0].gateway,
            Some(ip("fe80::3"))
        );
        assert!(table.remove_route(prefix, 64, RouteSource::Bgp));
        assert_eq!(table.routes_from(RouteSource::Connected).len(), 1);
    }

    #[test]
    fn multipath_routes_coexist_and_can_be_removed_individually() {
        let mut table = Ipv6RoutingTable::new();
        let default = ip("::");
        let router_a = ip("fe80::1");
        let router_b = ip("fe80::2");

        table.add_multipath_route_from(default, 0, Some(router_a), "eth0", RouteSource::Static);
        table.add_multipath_route_from(default, 0, Some(router_b), "eth0", RouteSource::Static);
        // Re-adding the same candidate must be idempotent.
        table.add_multipath_route_from(default, 0, Some(router_b), "eth0", RouteSource::Static);

        let best = table.lookup_best_routes(ip("2001:db8::1234"));
        assert_eq!(best.len(), 2);
        assert_eq!(best[0].gateway, Some(router_a));
        assert_eq!(best[1].gateway, Some(router_b));

        assert!(table.remove_route_via(default, 0, Some(router_a), "eth0", RouteSource::Static,));
        assert_eq!(
            table.lookup(ip("2001:db8::1234")).unwrap().gateway,
            Some(router_b)
        );
        assert_eq!(table.lookup_best_routes(ip("2001:db8::1234")).len(), 1);
    }

    #[test]
    fn best_routes_excludes_less_specific_and_worse_distance_candidates() {
        let mut table = Ipv6RoutingTable::new();
        let prefix = ip("2001:db8:42::");
        table.add_multipath_route_from(prefix, 64, Some(ip("fe80::1")), "eth0", RouteSource::Bgp);
        table.add_multipath_route_from(prefix, 64, None, "eth1", RouteSource::Connected);
        table.add_multipath_route_from(ip("2001:db8::"), 32, None, "eth2", RouteSource::Connected);

        let best = table.lookup_best_routes(ip("2001:db8:42::99"));
        assert_eq!(best.len(), 1);
        assert_eq!(best[0].source, RouteSource::Connected);
        assert_eq!(best[0].prefix_len, 64);
    }
}
