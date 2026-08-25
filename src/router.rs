//! Network layer routing table and Longest Prefix Match (LPM) route lookup.

use crate::ipv4::Ipv4Address;
use std::fmt;

/// Where a route came from. Used for administrative-distance tie-breaking between
/// equal-length prefixes and for protocol-scoped withdrawal: a routing process may
/// remove exactly its own routes without disturbing connected or static entries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub enum RouteSource {
    /// Directly attached subnet of a local interface.
    Connected,
    /// On-link prefix learned from an IPv6 Router Advertisement PIO.
    Ra,
    /// Operator-configured route (the default for `add_route`).
    #[default]
    Static,
    /// Learned from BGP-4 best-path selection.
    Bgp,
    /// Learned from OSPFv2 SPF.
    Ospf,
    /// Learned from RIPv2 distance vector.
    Rip,
}

impl RouteSource {
    /// Administrative distance: lower wins when two routes share a prefix length.
    /// The values follow common vendor practice so connected and static routes always
    /// take precedence over dynamically learned ones.
    pub fn distance(&self) -> u8 {
        match self {
            RouteSource::Connected => 0,
            RouteSource::Ra => 0,
            RouteSource::Static => 1,
            RouteSource::Bgp => 20,
            RouteSource::Ospf => 110,
            RouteSource::Rip => 120,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            RouteSource::Connected => "connected",
            RouteSource::Ra => "ra",
            RouteSource::Static => "static",
            RouteSource::Bgp => "bgp",
            RouteSource::Ospf => "ospf",
            RouteSource::Rip => "rip",
        }
    }
}

impl fmt::Display for RouteSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteEntry {
    pub destination: Ipv4Address,
    pub prefix_len: u8,
    pub netmask: u32,
    pub gateway: Option<Ipv4Address>,
    pub interface: String,
    pub source: RouteSource,
}

impl RouteEntry {
    pub fn new(
        destination: Ipv4Address,
        prefix_len: u8,
        gateway: Option<Ipv4Address>,
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
        destination: Ipv4Address,
        prefix_len: u8,
        gateway: Option<Ipv4Address>,
        interface: &str,
        source: RouteSource,
    ) -> Self {
        let prefix_len = prefix_len.min(32);
        let netmask = if prefix_len == 0 {
            0u32
        } else {
            !((1u32 << (32 - prefix_len)) - 1)
        };

        RouteEntry {
            destination,
            prefix_len,
            netmask,
            gateway,
            interface: interface.to_string(),
            source,
        }
    }

    pub fn matches(&self, ip: Ipv4Address) -> bool {
        (ip.to_u32() & self.netmask) == (self.destination.to_u32() & self.netmask)
    }

    pub fn next_hop(&self, destination: Ipv4Address) -> Ipv4Address {
        self.gateway.unwrap_or(destination)
    }

    /// Administrative distance of this entry, derived from its source.
    pub fn distance(&self) -> u8 {
        self.source.distance()
    }
}

impl fmt::Display for RouteEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let gw_str = match self.gateway {
            Some(gw) => gw.to_string(),
            None => "on-link".to_string(),
        };
        write!(
            f,
            "{}/{} via {} dev {} [{}/{}]",
            self.destination,
            self.prefix_len,
            gw_str,
            self.interface,
            self.source,
            self.distance()
        )
    }
}

#[derive(Debug, Default, Clone)]
pub struct RoutingTable {
    routes: Vec<RouteEntry>,
}

impl RoutingTable {
    pub fn new() -> Self {
        RoutingTable { routes: Vec::new() }
    }

    /// Installs an operator-configured (static) route.
    pub fn add_route(
        &mut self,
        destination: Ipv4Address,
        prefix_len: u8,
        gateway: Option<Ipv4Address>,
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

    /// Installs a route attributed to `source`. An existing entry for the same prefix
    /// *from the same source* is replaced in place, so a routing process that re-announces
    /// a prefix updates its next hop instead of accumulating duplicates.
    pub fn add_route_from(
        &mut self,
        destination: Ipv4Address,
        prefix_len: u8,
        gateway: Option<Ipv4Address>,
        interface: &str,
        source: RouteSource,
    ) {
        let entry = RouteEntry::with_source(destination, prefix_len, gateway, interface, source);
        let key = (entry.destination.mask(entry.prefix_len), entry.prefix_len);
        if let Some(existing) = self
            .routes
            .iter_mut()
            .find(|r| (r.destination.mask(r.prefix_len), r.prefix_len) == key && r.source == source)
        {
            *existing = entry;
        } else {
            self.routes.push(entry);
        }
        self.sort();
    }

    /// Removes the entry for `destination/prefix_len` contributed by `source`.
    /// Returns true if a route was actually removed.
    pub fn remove_route(
        &mut self,
        destination: Ipv4Address,
        prefix_len: u8,
        source: RouteSource,
    ) -> bool {
        let key = (destination.mask(prefix_len), prefix_len);
        let before = self.routes.len();
        self.routes.retain(|r| {
            !((r.destination.mask(r.prefix_len), r.prefix_len) == key && r.source == source)
        });
        self.routes.len() != before
    }

    /// Removes every route contributed by `source`. Returns how many were removed.
    /// Used when a routing process is torn down and must not leave stale forwarding state.
    pub fn remove_all_from(&mut self, source: RouteSource) -> usize {
        let before = self.routes.len();
        self.routes.retain(|r| r.source != source);
        before - self.routes.len()
    }

    /// Best matching route for `dst_ip` by longest prefix, then lowest administrative
    /// distance among equal-length prefixes.
    pub fn lookup(&self, dst_ip: Ipv4Address) -> Option<&RouteEntry> {
        self.routes.iter().find(|r| r.matches(dst_ip))
    }

    /// Exact-prefix lookup, ignoring longest-prefix semantics.
    pub fn find_exact(&self, destination: Ipv4Address, prefix_len: u8) -> Option<&RouteEntry> {
        let key = (destination.mask(prefix_len), prefix_len);
        self.routes
            .iter()
            .find(|r| (r.destination.mask(r.prefix_len), r.prefix_len) == key)
    }

    pub fn all_routes(&self) -> &[RouteEntry] {
        &self.routes
    }

    /// Every route contributed by `source`, in table order.
    pub fn routes_from(&self, source: RouteSource) -> Vec<&RouteEntry> {
        self.routes.iter().filter(|r| r.source == source).collect()
    }

    pub fn len(&self) -> usize {
        self.routes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.routes.is_empty()
    }

    /// Longest prefix first, then lowest administrative distance. `sort_by` is stable, so
    /// routes that tie on both keys keep their insertion order and lookups stay deterministic.
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

    #[test]
    fn test_longest_prefix_match() {
        let mut rt = RoutingTable::new();
        // Default route 0.0.0.0/0 via 192.168.1.1
        rt.add_route(
            Ipv4Address::UNSPECIFIED,
            0,
            Some(Ipv4Address::new(192, 168, 1, 1)),
            "eth0",
        );
        // Subnet route 192.168.1.0/24 direct
        rt.add_route(Ipv4Address::new(192, 168, 1, 0), 24, None, "eth0");
        // Specific host route 192.168.1.50/32 direct
        rt.add_route(Ipv4Address::new(192, 168, 1, 50), 32, None, "eth0");

        // 192.168.1.50 matches /32
        let r1 = rt.lookup(Ipv4Address::new(192, 168, 1, 50)).unwrap();
        assert_eq!(r1.prefix_len, 32);

        // 192.168.1.20 matches /24
        let r2 = rt.lookup(Ipv4Address::new(192, 168, 1, 20)).unwrap();
        assert_eq!(r2.prefix_len, 24);

        // 8.8.8.8 matches /0 default gateway
        let r3 = rt.lookup(Ipv4Address::new(8, 8, 8, 8)).unwrap();
        assert_eq!(r3.prefix_len, 0);
        assert_eq!(r3.gateway, Some(Ipv4Address::new(192, 168, 1, 1)));
    }

    #[test]
    fn test_connected_route_beats_bgp_route_of_equal_length() {
        let mut rt = RoutingTable::new();
        let prefix = Ipv4Address::new(10, 9, 0, 0);
        // BGP first, so insertion order cannot be what decides the winner.
        rt.add_route_from(
            prefix,
            24,
            Some(Ipv4Address::new(10, 0, 0, 2)),
            "eth1",
            RouteSource::Bgp,
        );
        rt.add_route_from(prefix, 24, None, "eth0", RouteSource::Connected);

        let best = rt.lookup(Ipv4Address::new(10, 9, 0, 7)).unwrap();
        assert_eq!(best.source, RouteSource::Connected);
        assert_eq!(best.interface, "eth0");
    }

    #[test]
    fn test_source_scoped_replacement_and_removal() {
        let mut rt = RoutingTable::new();
        let prefix = Ipv4Address::new(172, 20, 0, 0);
        rt.add_route_from(prefix, 16, None, "eth0", RouteSource::Connected);
        rt.add_route_from(
            prefix,
            16,
            Some(Ipv4Address::new(10, 0, 0, 1)),
            "eth1",
            RouteSource::Bgp,
        );
        // Re-announcing the same BGP prefix replaces rather than duplicates.
        rt.add_route_from(
            prefix,
            16,
            Some(Ipv4Address::new(10, 0, 0, 9)),
            "eth2",
            RouteSource::Bgp,
        );
        assert_eq!(rt.routes_from(RouteSource::Bgp).len(), 1);
        assert_eq!(rt.routes_from(RouteSource::Bgp)[0].interface, "eth2");
        assert_eq!(rt.len(), 2);

        // Withdrawing the BGP route leaves the connected route untouched.
        assert!(rt.remove_route(prefix, 16, RouteSource::Bgp));
        assert!(!rt.remove_route(prefix, 16, RouteSource::Bgp));
        assert_eq!(rt.routes_from(RouteSource::Bgp).len(), 0);
        assert_eq!(rt.routes_from(RouteSource::Connected).len(), 1);
    }
}
